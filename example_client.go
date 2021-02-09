package xdrgateway

import (
	"log"
	"time"
)

// ExampleClient shows how to create an XDRCllient from environmentala variables to send an alert.
// Notice NewXDRClientFromEnv() will throw a fatal error if the mandatory variables are not found
func ExampleClient() {
	client := NewXDRClientFromEnv()
	if err := client.Send(&Alert{
		LocalIP:          "15.14.13.12",
		LocalPort:        11,
		RemoteIP:         "10.9.8.7",
		RemotePort:       6,
		Timestamp:        time.Now().Unix() / int64(time.Millisecond),
		Severity:         SeverityHigh,
		Action:           ActionBlocked,
		AlertName:        "Unit Test",
		AlertDescription: "High-Block alert from Unit Testing",
	}); err != nil {
		log.Fatal(err)
	}
}
