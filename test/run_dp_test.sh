#!/bin/bash

#go test -v -run TestInject cmd/daemon/dp/dp_test.go
#go test -v -run TestBlock cmd/daemon/dp/dp_test.go
#go test -v -run TestWhiteList cmd/daemon/dp/dp_test.go
#go test -v -run TestChainId cmd/daemon/dp/whitelist/analyzer/devicemapper/devicemapper_test.go
go test -v -race -run TestDeviceMapper cmd/daemon/dp/whitelist/analyzer/analyzer_test.go
