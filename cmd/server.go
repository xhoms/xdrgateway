package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/xhoms/xdrgateway"
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
	client := xdrgateway.NewXDRClientFromEnv()
	pipeOps := xdrgateway.NewOpsFromEnv()
	parser := xdrgateway.NewBasicParser(offset)
	api := xdrgateway.NewAPI(parser, client, os.Getenv("PSK"), debug, pipeOps)
	http.HandleFunc("/stats", api.Stats)
	http.HandleFunc("/dump", api.Dump)
	http.HandleFunc("/in", api.Ingestion)
	log.Println("starting http service on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
