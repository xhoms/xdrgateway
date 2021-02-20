/*
Package xdrclient provides code to implement a client to the ingestion parser alerts API in XDR.

The main component is the Client type that implements a client to the Cortex XDR insert parsed alerts API.
A convenience method is provided to configure and initialize a client from environmental variables.

	client := NewClientFromEnv()

NewXDRClientFromEnv will throw fatal errors if the mandatory environmental variables are not found. They are:

	API_KEY     XDR API Key (Advanced)
	API_KEY_ID  The XDR API Key identifier (its sequence number)
	FQDN        Full Qualified Domain Name of the corresponding XDR Instance (i.e. myxdr.xdr.us.paloaltonetworks.com)

Another way to create the client is by initializing the struct and calling its Init() method

	client := Client{
		APIKey: "<my API KEY>",
		APIKeyID: "37",
		FQDN: "myxdr.xdr.us.paloaltonetworks.com",
	}
	if err := client.Init(); err != nil {
		log.Fatal(err)
	}

The client exposes the Send(alert *xdrgateway.Alert) (err error) and SendMulti(alert *xdrgateway.Alert) (err error) methods
to push alerts into XDR.
*/
package xdrclient
