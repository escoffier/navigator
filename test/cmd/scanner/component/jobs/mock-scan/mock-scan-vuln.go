package mock_scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	MockExecutorScanVulnName = "mock-scan-vuln"
)

type MockExecutorScanVuln struct {
	imageCacheUrl string
}

type VulnRes struct {
	Target string `json:"target"`
	Class  string `json:"class"`
	Type   string `json:"type"`
}

func (e *MockExecutorScanVuln) Scan(ctx context.Context, param scan.Param) (scan.Artifact, error) {
	// get image cache url
	url, ok := param["imageCacheUrl"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'imageCacheUrl' in parameter")
		return nil, errors.New("miss 'imageCacheUrl' in parameter")
	}
	e.imageCacheUrl = url

	result := make(scan.Artifact)

	// scan
	logging.GetLogger().Info().Str("imageCacheUrl", url).Msg("mock scan vuln  start")

	// get trivy path
	//u, _ := user.Current()
	// cmdPath := fmt.Sprintf("%s/go/src/scm.tensorsecurity.cn/tensorsecurity-rd/trivy/", u.HomeDir)
	cmd := exec.Command("sh", "-c", "trivy image -f json -o tmpscan.log "+e.imageCacheUrl)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	file, err := os.Open("tmpscan.log")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	tmpRes := make([]VulnRes, 0)
	err = json.Unmarshal(content, &tmpRes)
	if err != nil {
		return nil, err
	}
	//logging.GetLogger().Info().Interface("tmpRes", tmpRes).Msg("result")

	// result
	result["vuln-num"] = "123"
	result["scan-vuln-res"] = tmpRes

	time.Sleep(time.Duration(5) * time.Second)
	return result, nil
}

func init() {
	err := scan.Register(MockExecutorScanVulnName, newMockScanVuln)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", MockExecutorScanVulnName).Msg("int executor err")
	}
}

func newMockScanVuln(config scan.ExecutorConfig) (scan.Executor, error) {
	e := &MockExecutorScanVuln{}
	return e, nil
}
