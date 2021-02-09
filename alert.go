package xdrgateway

import (
	"fmt"
	"net"
)

type Severities int
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

type Alert struct {
	LocalIP          string
	LocalPort        uint16
	RemoteIP         string
	RemotePort       uint16
	Timestamp        int64
	Severity         Severities
	AlertName        string
	AlertDescription string
	Action           Actions
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

// NewHighAlert allocates memory for a new Alert struct with severity Low
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

// NetData is used to populate the Meta Data in the struct
func (a *Alert) MetaData(name, description string, action Actions) {
	a.AlertName = name
	a.AlertDescription = description
	a.Action = action
}
