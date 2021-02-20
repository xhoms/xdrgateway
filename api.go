package xdrgateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/xhoms/xdrgateway/xdrclient"
)

// AppStats hold runtime statistics for the application
type AppStats struct {
	APIStats
	xdrclient.Stats
	PipeStats
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
func NewAPI(parser Parser, xdrClient *xdrclient.Client, psk string, debug bool, pipe *AlertPipeOps) (api *API) {
	api = &API{
		parser: parser,
		pipe:   newAlertPipe(xdrClient, pipe),
		psk:    psk,
		debug:  debug,
		stats:  &APIStats{},
	}
	return
}

func (a *API) httpAuth(h http.Header) bool {
	auth := h.Get("Authorization")
	if auth == a.psk {
		return true
	}
	a.stats.PSKErrors++
	return false
}

// Close attempts to gracefully shutdown the pipeline goroutines
func (a *API) Close() {
	a.pipe.stats = a.pipe.close()
}

// Ingest attempts to parse the provide payload and, if successful, ingests the resulting alert into the pipe
func (a *API) Ingest(payload []byte) (err error) {
	var alert *xdrclient.Alert
	if alert, err = a.parser.Parse(payload); err == nil {
		a.pipe.ingest(alert)
		a.stats.EventsReceived++
	} else {
		a.stats.ParseErrors++
	}
	return
}

// HandlerIngestion http.HandleFunc compatible handler for PAN-OS alert ingestion
// only POST method supported
func (a *API) HandlerIngestion(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		if err = r.Body.Close(); err == nil {
			a.stats.EventsReceived++
			if a.httpAuth(r.Header) {
				if r.Method == http.MethodPost {
					if err = a.Ingest(buff.Bytes()); err == nil {
						if a.debug {
							log.Println("api - sucessfully parsed alert")
						}
					} else {
						log.Println("api error - unparseable payload")
					}
				} else {
					log.Println("api error - non POST request")
				}
			} else {
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

// HandlerHint http.HandleFunc compatible handler that dumps the parser layout hint
func (a *API) HandlerHint(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		r.Body.Close()
	}
	var response []byte
	if a.httpAuth(r.Header) {
		response = a.parser.DumpPayloadLayout()
	}
	w.Write(response)
	return
}

// HandlerStats http.HandleFunc compatible handler that dumps runtime statistics
func (a *API) HandlerStats(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		r.Body.Close()
	}
	var response []byte
	if a.httpAuth(r.Header) {
		stats := &AppStats{
			APIStats:  *a.stats,
			Stats:     *a.pipe.client.Stats,
			PipeStats: *a.pipe.stats,
		}
		if jdata, err := json.MarshalIndent(stats, "", "  "); err == nil {
			response = jdata
		}
	}
	w.Write(response)
	return
}
