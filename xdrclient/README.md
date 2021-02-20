[![godoc](https://img.shields.io/badge/godoc-latest-blue)](https://pkg.go.dev/github.com/xhoms/xdrgateway/xdrclient)

# Basic implementation of a XDR client for parsed alert ingestion API

This package provides basic types to interface with the parsed alert ingestion API provided by Palo
Alto Networks Cortex XDR. It can be used to stitch third party alerts (i.e. logs from closed systems)
with the incident management provided by the XDR application.