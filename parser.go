package xdrgateway

import (
	"encoding/json"
	"strings"
	"time"
)

// Parser provides methods to parse PAN-OS alerts into XDR Alerts
type Parser interface {
	// Parse attempts to fill a XDR alert with the payload pushed by the PAN-OS device
	Parse(data []byte) (*Alert, error)
	// DumpPayloadLayout returns a human-readable helper to assist the PAN-OS administrator preparing the payload for this parser
	DumpPayloadLayout() []byte
}

const (
	panosTSLayout = "2006/01/02 15:04:05"
)

var (
	defaultLocation    = time.FixedZone("XGW", 0)
	basicPayloadLayout = []byte(`{
	"src": "$src",
	"sport": $sport,
	"dst": "$dst",
	"dport": $dport,
	"time_generated": "$time_generated",
	"rule": "$rule",
	"serial": "$serial",
	"sender_sw_version": "$sender_sw_version",
	"subtype": "$subtype",
	"misc": $misc,
	"threat_name": "$threat_name",
	"severity": "$severity",
	"action": "$action"
}
	`)
)

type basicParserJSON struct {
	Src        string `json:"src"`
	Sport      int    `json:"sport"`
	Dst        string `json:"dst"`
	Dport      int    `json:"dport"`
	Timestamp  string `json:"time_generated"`
	Rule       string `json:"rule"`
	Serial     string `json:"serial"`
	SWVersion  string `json:"sender_sw_version"`
	Subtype    string `json:"subtype"`
	Misc       string `json:"misc"`
	ThreatName string `json:"threat_name"`
	Severity   string `json:"severity"`
	Action     string `json:"action"`
}

// BasicParser implements xdrgateway.Parser interface
type BasicParser struct {
	location        *time.Location
	payloadLayout   []byte
	tsLayout        string
	event           *basicParserJSON
	product, vendor string
}

// NewBasicParser returns a parser with TimeZone set to `offset`-hours (negative values supported)
func NewBasicParser(offset int) (b *BasicParser) {
	b = &BasicParser{
		location:      time.FixedZone("XGW", offset*60*60),
		payloadLayout: basicPayloadLayout,
		tsLayout:      panosTSLayout,
		event:         &basicParserJSON{},
		product:       "PAN-OS",
		vendor:        "Palo Alto Networks",
	}
	return
}

// Parse converts data into a XDR Alert. Return error if parsing fails
func (b *BasicParser) Parse(data []byte) (alert *Alert, err error) {
	if err = json.Unmarshal(data, b.event); err == nil {
		var t time.Time
		if t, err = time.ParseInLocation(b.tsLayout, b.event.Timestamp, b.location); err == nil {
			var level Severities
			switch b.event.Severity {
			case "critical", "high":
				level = SeverityHigh
			case "medium":
				level = SeverityMedium
			case "informational":
				level = SeverityInfo
			case "low":
				level = SeverityLow
			default:
				level = SeverityUnknown
			}
			alert = NewAlert(level, t.UnixNano()/int64(time.Millisecond))
			alert.Product, alert.Vendor = b.product, b.vendor
			if err = alert.NetData(b.event.Src, b.event.Dst, uint16(b.event.Sport), uint16(b.event.Dport)); err == nil {
				var action Actions
				switch b.event.Action {
				case "alert", "allow":
					action = ActionReported
				default:
					action = ActionBlocked
				}
				descParts := make([]string, 1, 4)
				descParts[0] = b.event.Misc
				if b.event.Serial != "" {
					descParts = append(descParts, "serial="+b.event.Serial)
				}
				if b.event.SWVersion != "" {
					descParts = append(descParts, "version="+b.event.SWVersion)
				}
				if b.event.Action != "" {
					descParts = append(descParts, "action="+b.event.Action)
				}
				if b.event.Rule != "" {
					descParts = append(descParts, "rule="+b.event.Rule)
				}
				if b.event.Subtype != "" {
					descParts = append(descParts, "type="+b.event.Subtype)
				}
				description := strings.Join(descParts, ";")
				name := b.event.ThreatName
				alert.MetaData(name, description, action)
			}
		}
	}
	return
}

// DumpPayloadLayout provides human-readable format of the supported PAN-OS payload for this parser
func (b *BasicParser) DumpPayloadLayout() []byte {
	return b.payloadLayout
}
