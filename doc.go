/*
Package xdrgateway provides the tools needed to create an alert pipeline ingestion into Palo Alto Network Cortex XDR

The main component is the xdrgateway.XDRClient type that implements a client to the Cortex XDR insert parsed alerts API.
A convenience method is provided to configure and initialize a client from environmental variables.

	client := xdrgateway.NewXDRClientFromEnv()

NewXDRClientFromEnv will throw fatal errors if the mandatory environmental variables are not found. They are:

	API_KEY - XDR API Key (Advanced)
	API_KEY_ID - The XDR API Key identifier (its sequence number)
	FQDN - Full Qualified Domain Name of the corresponding XDR Instance (i.e. myxdr.xdr.us.paloaltonetworks.com)

Another way to create the client is by initializing the struct and calling its Init() method

	client := xdrgateway.XDRClient{
		APIKey: "<my API KEY>",
		APIKeyID: "37",
		FQDN: "myxdr.xdr.us.paloaltonetworks.com",
	}
	if err := client.Init(); err != nil {
		log.Fatal(err)
	}

The client exposes the Send(alert *xdrgateway.Alert) (err error) and SendMulti(alert *xdrgateway.Alert) (err error) methods
to push alerts into XDR.

The second main component is the xdrgateway.API type that provides methods to implement an HTTP API to ingest third party alerts into XDR.

The API requires a *xdrgateway.XDRClient and a *xdrgateway.Parser instances. The Parser interface defines the methods to convert
the []byte data received by the API in its ingestion endpoint into a valid *xdrgateway.Alert

	// Parser provides methods to parse PAN-OS alerts into XDR Alerts
	type Parser interface {
		// Parse attempts to fill a XDR alert with the payload pushed by the PAN-OS device
		Parse(data []byte) (*Alert, error)
		// DumpPayloadLayout returns a human-readable helper to assist the PAN-OS administrator preparing the payload for this parser
		DumpPayloadLayout() []byte
	}

Ingestion(w http.ResponseWriter, r *http.Request) is the most important method provided by xdrgateway.API. It is a ready-to-consume
http handler to process POST request containing third party alerts.

Look at the provided cmd/server.go example to see an implementation parsing alerts generated by the HTTP Log Forwarding PAN-OS feature.

The example application can be run as a compact container application (FROM scratch). It binds the HTTP server into the port provided in
the PORT environmental variable (defaults to 8080) which means it can be run in almost any container managed service.

	docker build -t xdrgw https://github.com/xhoms/xdrgateway.git#main

	docker run --rm -p 8080:8080 \
	-e API_KEY="O4Bw...wEX" \
	-e API_KEY_ID="36" \
	-e FQDN="myxdr.xdr.us.paloaltonetworks.com" \
	-e PSK="hello" \
	xdrgw
	2021/02/09 11:51:32 nonce set to EEH4PO4BQY42YSFEY2X2F4KYDKFZKJPCB7NGRET7FMX7QNXXGV4NWD5FJQU7P7MS
	2021/02/09 11:51:32 ednpoint set to https://api-myxdr.xdr.us.paloaltonetworks.com/public_api/v1/alerts/insert_parsed_alerts/
	2021/02/09 11:51:32 starting http service on port 8080
	2021/02/09 11:51:32 starting sender goroutine
	2021/02/09 11:51:32 starting ticker goroutine

The application can be extended to support any third party alert just by providing a type implementing the *xdrgateway.Parse interface
*/
package xdrgateway