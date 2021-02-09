package xdrgateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

type AppStats struct {
	APIStats
	XDRClientStats
	AlertPipeStats
}

type APIStats struct {
	ParseErrors    int64
	EventsReceived int64
	PSKErrors      int64
}

type API struct {
	pipe   *alertPipe
	parser Parser
	stats  *APIStats
	psk    string
	debug  bool
}

func NewAPI(parser Parser, xdrClient *XDRClient, psk string, debug bool, pipe *AlertPipeOps) (api *API) {
	api = &API{
		parser: parser,
		pipe:   NewAlertPipe(xdrClient, pipe),
		psk:    psk,
		debug:  debug,
		stats:  &APIStats{},
	}
	return
}

func (a *API) Ingestion(w http.ResponseWriter, r *http.Request) {
	buff := new(bytes.Buffer)
	if _, err := buff.ReadFrom(r.Body); err == nil {
		if err = r.Body.Close(); err == nil {
			a.stats.EventsReceived++
			src := r.RemoteAddr
			auth := r.Header.Get("Authorization")
			if auth == a.psk {
				if r.Method == http.MethodPost {
					var alert *Alert
					if alert, err = a.parser.Parse(buff.Bytes()); err == nil {
						if a.debug {
							log.Printf("api - sucessfully parsed alert from %v", src)
						}
						a.pipe.Send(alert)
					} else {
						a.stats.ParseErrors++
						log.Println("api error - unparseable payload from", src)
					}
				} else {
					a.stats.ParseErrors++
					log.Println("api error - non POST request from", src)
				}
			} else {
				a.stats.PSKErrors++
				log.Println("api error - invalid PSK from", src)
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
