[![godoc](https://img.shields.io/badge/godoc-latest-blue)](https://pkg.go.dev/github.com/xhoms/xdrgateway)

# Basic PAN-OS to XDR HTTP log forwarding GW
A compact application offering a HTTP server that can listen to alerts generated by the HTTP log forwarding feature available on all PAN-OS devices and forward them to Cortex XDR using its alert ingestion API

Features
* configurable buffered pipeline to accomodate alert bursts (XDR alert ingestion API defaults to 600 external alerts per minute)
* support for XDR Advanced API Keys (no support for Standard API Keys)
* engine statistics

## Build the docker image
```bash
docker build -t xdrgw https://github.com/xhoms/xdrgateway.git#main
```

## Running the application
The application requires some mandatory environmental variables and accepts some optional ones.

The following are the required variables (the application will refuse to start without them)
* `API_KEY` - XDR API Key (Advanced)
* `API_KEY_ID` - The XDR API Key identifier (its sequence number)
* `FQDN` - Full Qualified Domain Name of the corresponding XDR Instance (i.e. `myxdr.xdr.us.paloaltonetworks.com`)

The following are optional variables
* `PSK` - the server will check the value in the `Authorization` header to accept the request (default to no authentication)
* `DEBUG` - if it exists then the engine will be more verbose (defaults to `false`)
* `PORT` - TCP port to bind the http server to (defaults to `8080`)
* `OFFSET` - PAN-OS timestamp does not include time zone. By default they will be considerd in UTC (defauls to `+0` hours)
* `QUOTA_SIZE` - XDR ingestion alert quota (defaults to `600`)
* `QUOTA_SECONDS` - XDR ingestion alert quota refresh period (defaults to `60` seconds)
* `UPDATE_SIZE` - XDR ingestion alert max number of alerts per update (defaults to `60`)
* `BUFFER_SIZE` - size of the pipe buffer (defaults to `6000` = 10 minutes)
* `T1` - how often the pipe buffer is polled for new alerts (defaults to `2` seconds)

Example shell session running the application

```text
$ docker run --rm -p 8080:8080 \
-e API_KEY="O4Bw...wEX" \
-e API_KEY_ID="36" \
-e FQDN="myxdr.xdr.us.paloaltonetworks.com" \
-e PSK="hello" \
xdrgw
PAN-OS to Cortex XDR alert ingestion Gateway
--------------------------------------------
  - Send PAN_OS alerts to /in using HTTP POST
  - The endpoint /stats provides runtime statistics
  - Use the following payload in the HTTP Log Forwarding feature
{
        "src": "$src",
        "sport": $sport,
        "dst": "$dst",
        "dport": $dport,
        "time_generated": "$time_generated",
        "rule": "$rule",
        "serial": "$serial",
        "sender_sw_version": "$sender_sw_version",
        "subtype": "$subtype",
        "severity": "$severity",
        "threat_name": "$threat_name", 
        "action": "$action"
}
---annex---
$misc

2021/02/09 11:51:32 nonce set to EEH4PO4BQY42YSFEY2X2F4KYDKFZKJPCB7NGRET7FMX7QNXXGV4NWD5FJQU7P7MS
2021/02/09 11:51:32 ednpoint set to https://api-myxdr.xdr.us.paloaltonetworks.com/public_api/v1/alerts/insert_parsed_alerts/
2021/02/09 11:51:32 starting http service on port 8080
2021/02/09 11:51:32 starting sender goroutine
2021/02/09 11:51:32 starting ticker goroutine
```

## Servicing on TLS
You're encouraged to run this container image behind a forward proxy service providing the TLS frontend (i.e. GCP Cloud Run or a NGINX server)

## Configuring the PAN-OS device
Check PAN-OS documentation on how to configure a HTTP Server and use it in a Log Forwarding Profile. Only Medium/High/Critical threat alerts should be forwarded to avoid exceeding the ingestion quota. The payload seen bellow leverages the attribute `$threat_name` that was introduced in PAN-OS 10.1. For earlier versions use `$threatid` instead.

The application provides the endpoint `/dump` that returns the payload that should be used in the PAN-OS HTTP Server.

Alerts must be sent to the `/in` endpoint in the application using method `POST`

Example bash session retrieving the payload to be configured in the PAN-OS device.

```text
$ curl 127.0.0.1:8080/dump -H "Authorization: hello" 
{
    "src": "$src",
    "sport": $sport,
    "dst": "$dst",
    "dport": $dport,
    "time_generated": "$time_generated",
    "rule": "$rule",
    "serial": "$serial",
    "sender_sw_version": "$sender_sw_version",
    "subtype": "$subtype",
    "severity": "$severity",
    "threat_name": "$threat_name",
    "action": "$action"
}
---annex---
$misc
```

## Runtime Statistics
The application provides, as well, the `/stats` endpoint.

Example session retrieving the statistics
```text
% curl 127.0.0.1:8080/stats -H "Authorization: hello"
{
  "ParseErrors": 0,
  "EventsReceived": 0,
  "PSKErrors": 0,
  "POSTSend": 0,
  "POSTFailures": 0,
  "AlertsSend": 0,
  "SendFailures": 0,
  "UpdatesSend": 0,
  "Discards": 0
}
```

* `ParseErrors` - events received by the application in the `/in` endpoint that could not be parsed into alerts (payload error?)
* `EventsReceived` - number of times the `/in` endpoint has been reached
* `PSKErrors` - authentication errors
* `POSTSend` - successful updates to the XDR insert alert API (status = 200 OK)
* `POSTFailures` - unsuccessful updates to the XDR insert alert API (status != 200 OK)
* `AlertsSend` - Amount of alerts successfully moved across the buffered pipe
* `SendFailures` - Internal errors rendering the XDR API update payload
* `UpdatesSend` - Successful XDR API update payloads rendered
* `Discards` - alerts dropped in the buffered pipe (too many?)
