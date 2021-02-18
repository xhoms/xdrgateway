package xdrgateway

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// ExampleXDRClient_fromenv shows how to create an XDRCllient from environmentala variables to send an alert.
//
// Notice NewXDRClientFromEnv() will throw a fatal error if the mandatory variables are not found
func ExampleXDRClient_fromenv() {
	client := NewXDRClientFromEnv()
	alert := &Alert{
		LocalIP:          "15.14.13.12",
		LocalPort:        11,
		RemoteIP:         "10.9.8.7",
		RemotePort:       6,
		Timestamp:        time.Now().Unix() / int64(time.Millisecond),
		Severity:         SeverityHigh,
		Action:           ActionBlocked,
		AlertName:        "Unit Test",
		AlertDescription: "High-Block alert from Unit Testing",
	}
	if err := client.Send(alert); err != nil {
		log.Fatal(err)
	}
}

// ExampleXDRClient_explicit creates a XDRClient explicitly and pushed multiple alerts in a single update
//
// Notice the client do not enforce the maximum number of alerts in a single update at it might be
// rejected at the XDR side as it do not accept more than 60 alerts in a single update
func ExampleXDRClient_explicit() {
	client := XDRClient{
		APIKey:   "O4Bw...wEX",
		APIKeyID: "37",
		FQDN:     "myxdr.xdr.us.paloaltonetworks.com",
	}
	if err := client.Init(); err != nil {
		log.Fatal(err)
	}
	alert := []*Alert{
		{
			LocalIP:          "15.14.13.12",
			LocalPort:        11,
			RemoteIP:         "10.9.8.7",
			RemotePort:       6,
			Timestamp:        time.Now().Unix() / int64(time.Millisecond),
			Severity:         SeverityHigh,
			Action:           ActionBlocked,
			AlertName:        "Unit Test",
			AlertDescription: "High-Block alert from Unit Testing",
		},
		{
			LocalIP:          "12.13.14.15",
			LocalPort:        11,
			RemoteIP:         "7.8.9.10",
			RemotePort:       6,
			Timestamp:        time.Now().Unix() / int64(time.Millisecond),
			Severity:         SeverityHigh,
			Action:           ActionBlocked,
			AlertName:        "Unit Test",
			AlertDescription: "High-Block alert from Unit Testing",
		},
	}
	if err := client.SendMulti(alert); err != nil {
		log.Fatal(err)
	}
}

// ExampleAPI implements a HTTP server that can be used to ingest PAN-OS alerts into Cortex XDR
// leveraging the NGFW's HTTP Log Forwarding feature
func ExampleAPI() {
	port := "8080"
	client := NewXDRClientFromEnv()
	parser := NewBasicParser(0, false)
	api := NewAPI(parser, client, "", false, nil)
	http.HandleFunc("/in", api.Ingestion)
	log.Println("payload template to be used in the PAN-OS device")
	fmt.Println(string(parser.DumpPayloadLayout()))
	log.Println("starting http service on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
