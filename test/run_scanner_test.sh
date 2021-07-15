#!/bin/bash

#go test -v -run TestSyncRepo cmd/scanner/service/registry_test.go
go test -v -run TestValidApiKey pkg/api/apikey/apikey_test.go
