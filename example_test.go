package xdrgateway

import (
	"fmt"
	"log"
	"net/http"

	"github.com/xhoms/xdrgateway/xdrclient"
)

// Example that creates a HTTP server that can be used to ingest PAN-OS alerts into Cortex XDR
// leveraging the NGFW's HTTP Log Forwarding feature
func ExampleAPI() {
	port := "8080"
	client := xdrclient.NewClientFromEnv()
	parser := NewBasicParser(0, false)
	api := NewAPI(parser, client, "", false, nil)
	http.HandleFunc("/in", api.HandlerIngestion)
	log.Println("payload template to be used in the PAN-OS device")
	fmt.Println(string(parser.DumpPayloadLayout()))
	log.Println("starting http service on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
