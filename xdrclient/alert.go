package xdrclient

import (
	"fmt"
	"net"
)

// Severities is an enumeration of all supported Cortex XDR alert severities
type Severities int

// Actions is an enumeration of all supported Cortex XDR alert actions
type Actions int

const (
	// SeverityInfo is the string XDR ingestion API expects for info-level alerts
	SeverityInfo Severities = iota
	// SeverityLow is the string XDR ingestion API expects for low-level alerts
	SeverityLow
	// SeverityMedium is the string XDR ingestion API expects for medium-level alerts
	SeverityMedium
	// SeverityHigh is the string XDR ingestion API expects for high-level alerts
	SeverityHigh
	// SeverityUnknown is the string XDR ingestion API expects for unknown-level alerts
	SeverityUnknown
	// ActionReported is the string XDR ingestion API expects for alerts that have just being reported
	ActionReported Actions = iota
	// ActionBlocked is the string XDR ingestion API expects for alerts that have been blocked at the reporting device
	ActionBlocked
)

func severityString(code Severities) (severity string) {
	switch code {
	case SeverityInfo:
		severity = "Informational"
	case SeverityLow:
		severity = "Low"
	case SeverityMedium:
		severity = "Medium"
	case SeverityHigh:
		severity = "High"
	default:
		severity = "Unknown"
	}
	return
}

func actionString(code Actions) (action string) {
	if code == ActionBlocked {
		action = "Blocked"
	} else {
		action = "Reported"
	}
	return
}

// Alert is a representation of Cortex XDR alert fields.
// Fields are exposed for convenience but developers are encourages to use the provided methods to fill them in order
// to perform format validation (to avoid upstream rejects by the API)
type Alert struct {
	// Product is a value that defines the product
	Product string
	// Vendor is a value that defines the product
	Vendor string
	// LocalIP is the value for the source IP address.
	// It is highly recommended to use the method NetData(srcIP string, dstIP string, srcPort uint16, dstPort uint16) (err error)
	// to field this field as well as the rest of network-related alert properties. The method will enforce IPv4/IPv6 address
	// format validity
	LocalIP string
	// LocalPort is the value for the source port
	LocalPort uint16
	// RemoteIP is the value of the destination IP address
	RemoteIP string
	// RemotePort is the value for the destination port
	RemotePort uint16
	// Timestamp is the value representing the epoch of the time the alert occurred in milliseconds
	Timestamp int64
	// Severity is the value of alert severity. Use the corresponding code from the Severities enum
	Severity Severities
	// AlertName defines the alert name
	AlertName string
	// AlertDescription defines the alert description
	AlertDescription string
	// Action defines the alert action taken by the source. Use the corresponding code from the Actions enum
	Action Actions
}

// NewAlert allocates memory for a new Alert struct
func NewAlert(severity Severities, timestamp int64) (alert *Alert) {
	alert = &Alert{
		Severity:  severity,
		Timestamp: timestamp,
	}
	return
}

// NewHighAlert allocates memory for a new Alert struct with severity High
func NewHighAlert(timestamp int64) (alert *Alert) {
	return NewAlert(SeverityHigh, timestamp)
}

// NewLowAlert allocates memory for a new Alert struct with severity Low
func NewLowAlert(timestamp int64) (alert *Alert) {
	return NewAlert(SeverityLow, timestamp)
}

// NetData is used to populate the network data in the struct
func (a *Alert) NetData(srcIP, dstIP string, srcPort, dstPort uint16) (err error) {
	var ipaddr net.IP
	a.LocalIP = ""
	a.RemoteIP = ""
	a.LocalPort = 0
	a.RemotePort = 0
	if ipaddr = net.ParseIP(srcIP); ipaddr != nil {
		a.LocalIP = ipaddr.String()
	} else {
		err = fmt.Errorf("unable to parse Source IP %v", srcIP)
		return
	}
	if ipaddr = net.ParseIP(dstIP); ipaddr != nil {
		a.RemoteIP = ipaddr.String()
	} else {
		err = fmt.Errorf("unable to parse Destination IP %v", dstIP)
		return
	}
	a.LocalPort = srcPort
	a.RemotePort = dstPort
	return
}

// MetaData is used to populate the Meta Data in the struct
func (a *Alert) MetaData(name, description string, action Actions) {
	a.AlertName = name
	a.AlertDescription = description
	a.Action = action
}
