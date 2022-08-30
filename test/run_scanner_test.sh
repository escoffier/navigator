#!/bin/bash

#go test -v -run TestSyncRepo cmd/scanner/service/registry_test.go
#go test -v -run TestValidApiKey pkg/api/apikey/apikey_test.go
#go test -v -run  TestListImages cmd/scanner/component/registry/registry_test.go
#go test -v -run TestAddFlowConf cmd/scanner/component/flow-conf/flow_conf_test.go
#go test -v -run TestPullImage cmd/scanner/component/jobs/mock-pull-image/pull_image_test.go
#go test -v -run TestPullImage cmd/scanner/component/jobs/pull-image/pull_image_test.go
#go test -v -run TestMockDequeue cmd/scanner/component/dequeue/dequeue_test.go
#go test -v -run TestMockScan cmd/scanner/component/jobs/scan/scan_test.go
#go test -v -run TestEngine cmd/scanner/component/engine/engine_test.go

# ci test
#go test -v -run TestVulnMatch cmd/scanner/component/vuln-match/matcher_test.go
#go test -v -run TestAnalyzeImage cmd/scanner-cicd/ci_test.go
#go test -v -run TestMatchVulnAPI cmd/scanner/api/ci_test.go
#go test -v -run TestGetPolicyAPI cmd/scanner/api/ci_test.go
#go test -v -run TestSaveResultAPI cmd/scanner/api/ci_test.go
#go test -v -covermode=count -coverprofile=coverprofile.cov -coverpkg=$(go list ./... | grep -v "/test" | grep scanner-cicd | tr '\n' ',') -run TestIntegrateCI cmd/scanner-cicd/ci_test.go

#go test -v -run TestIntergrateVulnCi cmd/scanner-cicd/ci_test.go
go test -v -cover -coverpkg=$(go list ../... | grep -v "/test" | grep scanner-cicd | tr '\n' ',') cmd/scanner-cicd/ci_test.go
