#!/bin/bash

#go test -v -run TestSyncRepo cmd/scanner/service/registry_test.go
#go test -v -run TestValidApiKey pkg/api/apikey/apikey_test.go
#go test -v -run  TestListImages cmd/scanner/component/registry/registry_test.go
#go test -v -run TestAddFlowConf cmd/scanner/component/flow-conf/flow_conf_test.go
#go test -v -run TestPullImage cmd/scanner/component/jobs/mock-pull-image/pull_image_test.go
#go test -v -run TestPullImage cmd/scanner/component/jobs/pull-image/pull_image_test.go
#go test -v -run TestMockDequeue cmd/scanner/component/dequeue/dequeue_test.go
#go test -v -run TestMockScan cmd/scanner/component/jobs/scan/scan_test.go
go test -v -run TestEngine cmd/scanner/component/engine/engine_test.go
