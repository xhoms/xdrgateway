package xdrgateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const (
	endpointTemplate = "https://api-%v/public_api/v1/alerts/insert_parsed_alerts/"
)

var (
	headerTs          = http.CanonicalHeaderKey("x-xdr-timestamp")
	headerNonce       = http.CanonicalHeaderKey("x-xdr-nonce")
	headerAuthID      = http.CanonicalHeaderKey("x-xdr-auth-id")
	headerAuth        = http.CanonicalHeaderKey("Authorization")
	headerContentType = http.CanonicalHeaderKey("Content-Type")
)

type XDRClientStats struct {
	POSTSend     uint64
	POSTFailures uint64
}

type XDRClient struct {
	APIKey     string
	APIKeyID   string
	FQDN       string
	endpoint   string
	hashprefix string
	nonce      string
	stats      *XDRClientStats
	client     *http.Client
	url        string
	init       bool
	Debug      bool
}

func NewXDRClientFromEnv() (client *XDRClient) {
	client = &XDRClient{}
	if ak, exists := os.LookupEnv("API_KEY"); exists {
		client.APIKey = ak
	} else {
		log.Fatal("API_KEY env variable not provided")
	}
	if akid, exists := os.LookupEnv("API_KEY_ID"); exists {
		client.APIKeyID = akid
	} else {
		log.Fatal("API_KEY_ID env variable not provided")
	}
	if fqdn, exists := os.LookupEnv("FQDN"); exists {
		client.FQDN = fqdn
	} else {
		log.Fatal("FQDN env variable not provided")
	}
	if _, exists := os.LookupEnv("DEBUG"); exists {
		client.Debug = true
	}
	if err := client.Init(); err != nil {
		log.Fatal(err)
	}
	return
}

func (x *XDRClient) Init() (err error) {
	switch {
	case x.APIKey == "":
		err = errors.New("Missing mandatory APIKey property")
		return
	case x.APIKeyID == "":
		err = errors.New("Missing mandatory APIKeyID property")
		return
	case x.FQDN == "":
		err = errors.New("Missing mandatory FQDN property")
		return
	}
	nonce := make([]byte, 40)
	for idx := range nonce {
		nonce[idx] = byte(rand.Intn(256))
	}
	x.nonce = base32.StdEncoding.EncodeToString(nonce)
	x.hashprefix = x.APIKey + x.nonce
	x.stats = &XDRClientStats{}
	x.client = &http.Client{Timeout: 10 * time.Second}
	x.url = fmt.Sprintf(endpointTemplate, x.FQDN)
	log.Println("nonce set to", x.nonce)
	log.Println("endpoint set to", x.url)
	x.init = true
	return
}

func (x *XDRClient) hash(tsmillis string) (apiKeyHash string) {
	sum := sha256.Sum256([]byte(x.hashprefix + tsmillis))
	apiKeyHash = hex.EncodeToString(sum[:])
	return
}

func (x *XDRClient) send(payload []byte) (err error) {
	if !x.init {
		err = errors.New("XDRClient Init() not completed yet")
		log.Print(err)
		return
	}
	now := fmt.Sprint(time.Now().UnixNano() / int64(time.Millisecond))
	var request *http.Request
	request, err = http.NewRequest(http.MethodPost, x.url, bytes.NewReader(payload))
	request.Header[headerContentType] = []string{"application/json"}
	request.Header[headerAuthID] = []string{x.APIKeyID}
	request.Header[headerNonce] = []string{x.nonce}
	request.Header[headerTs] = []string{now}
	request.Header[headerAuth] = []string{x.hash(now)}
	var resp *http.Response
	if resp, err = x.client.Do(request); err == nil {
		buff := new(bytes.Buffer)
		if _, buferr := buff.ReadFrom(resp.Body); buferr == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if x.Debug {
					log.Println("xdrclient - successful call to insert_parsed_alerts")
				}
				x.stats.POSTSend++
			} else {
				log.Printf("xdrclient error %v - %v", resp.Status, buff.String())
				x.stats.POSTFailures++
			}
		} else {
			log.Printf("xdrclient error reading response (%v)", resp.Status)
			err = buferr
		}
	} else {
		x.stats.POSTFailures++
		log.Printf("error - %v", err)
	}
	return
}
