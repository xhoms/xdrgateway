package xdrclient

import (
	"log"
	"time"
)

// Example that creates a Client from environmentala variables to send an alert.
// Notice NewClientFromEnv() will throw a fatal error if the mandatory variables are not found
func ExampleNewClientFromEnv() {
	client := NewClientFromEnv()
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

// Example that creates a Client explicitly and pushes multiple alerts in a single update.
// Notice the client do not enforce the maximum number of alerts in a single update at it might be
// rejected at the XDR side as it do not accept more than 60 alerts in a single update
func ExampleClient() {
	client := Client{
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
