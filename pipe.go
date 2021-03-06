package xdrgateway

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/xhoms/xdrgateway/xdrclient"
)

const (
	alertBufferSize  = 6000
	maxUpdate        = 60
	t1BucketSize     = 600
	t1BucketDuration = 60
	t2Timeout        = 2
)

// PipeStats provides counters for the buffered Alert pipe
type PipeStats struct {
	// PipeIn is the amount of alerts that have traversed the pipe
	PipeIn uint64
	// PipeInErr accumulates the number of PAN-OS alerts that have been discarded due to pipe buffer overflow
	PipeInErr uint64
	// PipeOutErr is the number of times the pipe failed to render a XDR API payload
	PipeOutErr uint64
	// PipeOut is the number of valid XDR API payloads generated by the pipe
	PipeOut uint64
}

// AlertPipeOps options to fine-tune the pipe behavior
type AlertPipeOps struct {
	// XDRUpdateSize max amount of alerts in a single XDR API update
	XDRUpdateSize int
	// XDRMQuotaSize max amount of alerts that can be ingested into XDR API per each period
	XDRMQuotaSize int
	// XDRQuotaSeconds XDR API ingestion quota refresh period (seconds)
	XDRQuotaSeconds int
	// AlertBufferSize how many alerts can he held in the buffered pipe
	AlertBufferSize int
	// T1 controls how fast the pipe is polled to drain alerts (seconds)
	T1 int
	// Debug to increase the verbosity of the pipe
	Debug bool
}

// NewPipeOpsFromEnv creates pipe options by reading environmental variables
//
// Optional environmental variables
//
// - DEBUG if it exists then the engine will be more verbose (defaults to false)
//
// - QUOTA_SIZE XDR ingestion alert quota (defaults to 600)
//
// - QUOTA_SECONDS XDR ingestion alert quota refresh period (defaults to 60 seconds)
//
// - UPDATE_SIZE XDR ingestion alert max number of alerts per update (defaults to 60)
//
// - BUFFER_SIZE size of the pipe buffer (defaults to 6000 = 10 minutes)
//
// - T1 how often the pipe buffer is polled for new alerts (defaulst to 2 seconds)
func NewPipeOpsFromEnv() (ops *AlertPipeOps) {
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
	client    *xdrclient.Client
	pipe      chan *xdrclient.Alert
	done      chan chan *PipeStats
	doneChan  chan *PipeStats
	buffer    []*xdrclient.Alert
	bufferPtr int
	t2Ticker  *time.Ticker
	t1Ticker  *time.Ticker
	t1Bucket  int
	jsondata  []byte
	err       error
	alert     *xdrclient.Alert
	stats     *PipeStats
	closed    bool
	debug     bool
}

func newAlertPipe(xdrAPI *xdrclient.Client, ops *AlertPipeOps) (pipe *alertPipe) {
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
		client:   xdrAPI,
		done:     make(chan chan *PipeStats),
		doneChan: make(chan *PipeStats),
		buffer:   make([]*xdrclient.Alert, updateSize),
		t1Bucket: t1BucketSize,
		t1Ticker: time.NewTicker(time.Second * t1),
		t2Ticker: time.NewTicker(time.Second * t2),
		pipe:     make(chan *xdrclient.Alert, bufferSize),
		stats:    &PipeStats{},
		debug:    debug,
	}

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
					pipe.stats.PipeInErr++
				}
				log.Println("pipe drained")
				done <- pipe.stats
				close(done)
				log.Println("ending sender goroutine")
				return
			case <-pipe.t1Ticker.C:
				pipe.t1Bucket = bucketSize
			case <-pipe.t2Ticker.C:
			T2:
				for pipe.t1Bucket > 0 {
					select {
					case pipe.alert, ok = <-pipe.pipe:
						if ok {
							pipe.buffer[pipe.bufferPtr] = pipe.alert
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
		if a.err = a.client.SendMulti(a.buffer[:a.bufferPtr]); a.err == nil {
			a.stats.PipeOut += uint64(a.bufferPtr)
		} else {
			a.stats.PipeOutErr += uint64(a.bufferPtr)
		}
		a.bufferPtr = 0
	}
}

func (a *alertPipe) getStats() (stats *PipeStats) {
	stats = a.stats
	return
}

func (a *alertPipe) ingest(alert *xdrclient.Alert) {
	if a.closed {
		a.stats.PipeInErr++
		return
	}
	select {
	case a.pipe <- alert:
		a.stats.PipeIn++
	default:
		a.stats.PipeInErr++
	}
}

func (a *alertPipe) close() (stats *PipeStats) {
	close(a.pipe)
	a.closed = true
	a.done <- a.doneChan
	close(a.done)
	stats = <-a.doneChan
	return
}
