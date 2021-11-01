package mock_scan

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	MockExecutorScanVirusName = "mock-scan-virus"
)

type MockExecutorScanVirus struct {
	imageCacheUrl string
}

func (e *MockExecutorScanVirus) Scan(ctx context.Context, param scan.Param) (scan.Artifact, error) {
	// get image cache url
	url, ok := param["imageCacheUrl"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'imageCacheUrl' in parameter")
		return nil, errors.New("miss 'imageCacheUrl' in parameter")
	}
	e.imageCacheUrl = url

	result := make(scan.Artifact)

	// scan
	logging.GetLogger().Info().Str("imageCacheUrl", url).Msg("mock scan virus  start")

	// result
	result["virus-num"] = "123"

	return result, nil
}

func init() {
	err := scan.Register(MockExecutorScanVirusName, newMockScanVirus)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", MockExecutorScanVulnName).Msg("int executor err")
	}
}

func newMockScanVirus(config scan.ExecutorConfig) (scan.Executor, error) {
	e := &MockExecutorScanVirus{}
	return e, nil
}
