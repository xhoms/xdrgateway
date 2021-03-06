package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/xhoms/xdrgateway"
	"github.com/xhoms/xdrgateway/xdrclient"
)

var (
	build string
)

func main() {
	port := "8080"
	if envport, exists := os.LookupEnv("PORT"); exists {
		port = envport
	}
	offset := 0
	if envOffset, exists := os.LookupEnv("OFFSET"); exists {
		if intval, err := strconv.Atoi(envOffset); err == nil {
			offset = intval
		}
	}
	debug := false
	if _, exists := os.LookupEnv("DEBUG"); exists {
		debug = true
	}
	parser := xdrgateway.NewBasicParser(offset, debug)
	fmt.Println("PAN-OS to Cortex XDR alert ingestion Gateway")
	fmt.Println("--------------------------------------------")
	fmt.Println("version:", xdrgateway.Version, build)
	fmt.Println("  - Send PAN_OS alerts to /in using HTTP POST")
	fmt.Println("  - The endpoint /stats provides runtime statistics")
	fmt.Println("  - Use the following payload in the HTTP Log Forwarding feature")
	fmt.Println(string(parser.DumpPayloadLayout()))
	client := xdrclient.NewClientFromEnv()
	pipeOps := xdrgateway.NewPipeOpsFromEnv()
	api := xdrgateway.NewAPI(parser, client, os.Getenv("PSK"), debug, pipeOps)
	http.HandleFunc("/stats", api.HandlerStats)
	http.HandleFunc("/dump", api.HandlerHint)
	http.HandleFunc("/in", api.HandlerIngestion)
	log.Println("starting http service on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
