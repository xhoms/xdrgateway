package xdrgateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

// AppStats hold runtime statistics for the application
type AppStats struct {
	APIStats
	XDRClientStats
	AlertPipeStats
}

// APIStats provides counters for the PAN-OS facing API part
type APIStats struct {
	// ParseErrors is the number of received events that have failed to be parsed
	ParseErrors int64
	// EventsReceived is the total number of API invocations in the ingestion endpoint
	EventsReceived int64
	// PSKErrors is increased each time an event is rejected due to PSK mismatch
	PSKErrors int64
}

// API provides HTTP methods to implement the PAN-OS facing ingestion API
type API struct {
	pipe   *alertPipe
	parser Parser
	stats  *APIStats
	psk    string
	debug  bool
}

// NewAPI creates and initializes a xdrgateway instance from values
func NewAPI(parser Parser, xdrClient *XDRClient, psk string, debug bool, pipe *AlertPipeOps) (api *API) {
	api = &API{
		parser: parser,
		pipe:   newAlertPipe(xdrClient, pipe),
		psk:    psk,
		debug:  debug,
		stats:  &APIStats{},
	}
	return
}

// Ingestion http.HandleFunc compatible handler for PAN-OS alert ingestion
// only POST method supported
func (a *API) Ingestion(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		if err = r.Body.Close(); err == nil {
			a.stats.EventsReceived++
			auth := r.Header.Get("Authorization")
			if auth == a.psk {
				if r.Method == http.MethodPost {
					var alert *Alert
					if alert, err = a.parser.Parse(buff.Bytes()); err == nil {
						if a.debug {
							log.Println("api - sucessfully parsed alert")
						}
						a.pipe.Send(alert)
					} else {
						a.stats.ParseErrors++
						log.Println("api error - unparseable payload")
					}
				} else {
					a.stats.ParseErrors++
					log.Println("api error - non POST request")
				}
			} else {
				a.stats.PSKErrors++
				log.Println("api error - invalid PSK")
			}
		} else {
			log.Println("api error -", err)
		}
	} else {
		log.Println("api error -", err)
	}
	w.Write(nil)
	return
}

// Dump http.HandleFunc compatible handler that dumps the parser layout hint
func (a *API) Dump(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		r.Body.Close()
	}
	auth := r.Header.Get("Authorization")
	var response []byte
	if auth == a.psk {
		response = a.parser.DumpPayloadLayout()
	}
	w.Write(response)
	return
}

// Stats http.HandleFunc compatible handler that dumps runtime statistics
func (a *API) Stats(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		r.Body.Close()
	}
	auth := r.Header.Get("Authorization")
	var response []byte
	if auth == a.psk {
		stats := &AppStats{
			APIStats:       *a.stats,
			XDRClientStats: *a.pipe.xdrAPI.stats,
			AlertPipeStats: *a.pipe.stats,
		}
		if jdata, err := json.MarshalIndent(stats, "", "  "); err == nil {
			response = jdata
		}
	}
	w.Write(response)
	return
}
