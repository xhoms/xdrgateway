package xdrgateway

import (
	"fmt"
	"log"
	"net/http"
)

// ExampleHTTPPipe implements a HTTP server that can be used to ingest PAN-OS alerts into Cortex XDR
// leveraging the NGFW's HTTP Log Forwarding feature
func ExampleHTTPPipe() {
	port := "8080"
	client := NewXDRClientFromEnv()
	parser := NewBasicParser(0)
	api := NewAPI(parser, client, "", false, nil)
	http.HandleFunc("/in", api.Ingestion)
	log.Println("payload template to be used in the PAN-OS device")
	fmt.Println(string(parser.DumpPayloadLayout()))
	log.Println("starting http service on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
