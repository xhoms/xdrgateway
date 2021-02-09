package xdrgateway

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"
)

const (
	alertBufferSize  = 6000
	maxUpdate        = 60
	t1BucketSize     = 600
	t1BucketDuration = 60
	t2Timeout        = 2
	product          = "PAN-OS"
	vendor           = "Palo Alto Networks"
)

type jsonalert struct {
	Product          string `json:"product"`
	Vendor           string `json:"vendor"`
	LocalIP          string `json:"local_ip"`
	LocalPort        uint16 `json:"local_port"`
	RemoteIP         string `json:"remote_ip"`
	RemotePort       uint16 `json:"remote_port"`
	Timestamp        int64  `json:"event_timestamp"`
	Severity         string `json:"severity,omitempty"`
	AlertName        string `json:"alert_name"`
	AlertDescription string `json:"alert_description,omitempty"`
	ActionStatus     string `json:"action_status,omitempty"`
}

func (a *jsonalert) copy(alert *Alert) {
	a.Product = product
	a.Vendor = vendor
	a.LocalIP = alert.LocalIP
	a.LocalPort = alert.LocalPort
	a.RemoteIP = alert.RemoteIP
	a.RemotePort = alert.RemotePort
	a.AlertName = alert.AlertName
	a.AlertDescription = alert.AlertDescription
	a.Timestamp = alert.Timestamp
	a.Severity = severityString(alert.Severity)
	a.ActionStatus = actionString(alert.Action)
}

type payload struct {
	RequestData struct {
		Alerts []jsonalert `json:"alerts"`
	} `json:"request_data"`
}

type AlertPipeStats struct {
	AlertsSend   uint64
	SendFailures uint64
	UpdatesSend  uint64
	Discards     uint64
}

type AlertPipeOps struct {
	XDRUpdateSize   int
	XDRMQuotaSize   int
	XDRQuotaSeconds int
	AlertBufferSize int
	T1              int
	Debug           bool
}

func NewOpsFromEnv() (ops *AlertPipeOps) {
	ops = &AlertPipeOps{
		XDRUpdateSize:   maxUpdate,
		XDRMQuotaSize:   t1BucketSize,
		XDRQuotaSeconds: t1BucketDuration,
		AlertBufferSize: alertBufferSize,
		T1:              t2Timeout,
	}
	if t1, exists := os.LookupEnv("T1"); exists {
		if intval, err := strconv.Atoi(t1); err == nil {
			ops.T1 = intval
		}
	}
	if qs, exists := os.LookupEnv("QUOTA_SIZE"); exists {
		if intval, err := strconv.Atoi(qs); err == nil {
			ops.XDRMQuotaSize = intval
		}
	}
	if qs, exists := os.LookupEnv("QUOTA_SECONDS"); exists {
		if intval, err := strconv.Atoi(qs); err == nil {
			ops.XDRQuotaSeconds = intval
		}
	}
	if us, exists := os.LookupEnv("UPDATE_SIZE"); exists {
		if intval, err := strconv.Atoi(us); err == nil {
			ops.XDRUpdateSize = intval
		}
	}
	if bf, exists := os.LookupEnv("BUFFER_SIZE"); exists {
		if intval, err := strconv.Atoi(bf); err == nil {
			ops.AlertBufferSize = intval
		}
	}
	if _, exists := os.LookupEnv("DEBUG"); exists {
		ops.Debug = true
	}
	return
}

type alertPipe struct {
	xdrAPI    *XDRClient
	pipe      chan *Alert
	done      chan chan *AlertPipeStats
	doneChan  chan *AlertPipeStats
	buffer    []jsonalert
	bufferPtr int
	t2Ticker  *time.Ticker
	t1Ticker  *time.Ticker
	t1Bucket  int
	payload   payload
	jsondata  []byte
	jsonerr   error
	alert     *Alert
	stats     *AlertPipeStats
	closed    bool
	debug     bool
}

func NewAlertPipe(xdrAPI *XDRClient, ops *AlertPipeOps) (pipe *alertPipe) {
	t1 := time.Duration(t1BucketDuration)
	t2 := time.Duration(t2Timeout)
	updateSize := maxUpdate
	bufferSize := alertBufferSize
	bucketSize := t1BucketSize
	debug := false
	if ops != nil {
		t1 = time.Duration(ops.XDRQuotaSeconds)
		t2 = time.Duration(ops.T1)
		updateSize = ops.XDRUpdateSize
		bufferSize = ops.AlertBufferSize
		bucketSize = ops.XDRMQuotaSize
		debug = ops.Debug
	}
	pipe = &alertPipe{
		xdrAPI:   xdrAPI,
		done:     make(chan chan *AlertPipeStats),
		doneChan: make(chan *AlertPipeStats),
		buffer:   make([]jsonalert, updateSize),
		t1Bucket: t1BucketSize,
		t1Ticker: time.NewTicker(time.Second * t1),
		t2Ticker: time.NewTicker(time.Second * t2),
		pipe:     make(chan *Alert, bufferSize),
		stats:    &AlertPipeStats{},
		debug:    debug,
	}

	// t1 bucket receiver
	go func() {
		log.Println("starting ticker goroutine")
		for range pipe.t1Ticker.C {
			pipe.t1Bucket = bucketSize
		}
		return
	}()

	// t2 alert sender
	go func() {
		log.Println("starting sender goroutine")
		var ok bool
		for {
			select {
			case done := <-pipe.done:
				pipe.t1Ticker.Stop()
				pipe.t2Ticker.Stop()
				log.Println("tickers stopped")
				for range pipe.pipe {
					pipe.stats.Discards++
				}
				log.Println("pipe drained")
				done <- pipe.stats
				close(done)
				log.Println("ending sender goroutine")
				return
			case <-pipe.t2Ticker.C:
			T2:
				for pipe.t1Bucket > 0 {
					select {
					case pipe.alert, ok = <-pipe.pipe:
						if ok {
							pipe.buffer[pipe.bufferPtr].copy(pipe.alert)
							pipe.bufferPtr++
							pipe.t1Bucket--
							if pipe.bufferPtr >= maxUpdate {
								pipe.encode()
							}
						} else {
							break T2
						}
					default:
						break T2
					}
				}
				pipe.encode()
			}
		}
	}()
	return
}

func (a *alertPipe) encode() {
	if a.bufferPtr > 0 {
		a.payload.RequestData.Alerts = a.buffer[:a.bufferPtr]
		if a.jsondata, a.jsonerr = json.Marshal(a.payload); a.jsonerr == nil {
			a.stats.AlertsSend += uint64(a.bufferPtr)
			a.stats.UpdatesSend++
			if a.debug {
				log.Printf("alert pipe - about to send %v alerts", a.bufferPtr)
			}
			a.xdrAPI.send(a.jsondata)
		} else {
			a.stats.SendFailures += uint64(a.bufferPtr)
		}
		a.bufferPtr = 0
	}
}

func (a *alertPipe) Stats() (stats *AlertPipeStats) {
	stats = a.stats
	return
}

func (a *alertPipe) Send(alert *Alert) {
	if a.closed {
		a.stats.Discards++
		return
	}
	select {
	case a.pipe <- alert:
	default:
		a.stats.Discards++
	}
}

func (a *alertPipe) Close() (stats *AlertPipeStats) {
	close(a.pipe)
	a.closed = true
	a.done <- a.doneChan
	close(a.done)
	stats = <-a.doneChan
	return
}
