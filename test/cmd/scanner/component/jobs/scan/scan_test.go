package scan

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/jobs/mock-scan"
	"testing"
)

func TestMockScan(t *testing.T) {
	config := scan.ExecutorConfig{
		Type: "mock-scan-vuln",
	}
	scanner, err := scan.Open(config)
	if err != nil {
		t.Fatalf("open scanner err:%v", err)
	}
	param := scan.Param{
		"imageCacheUrl": "nignx:1.20",
	}
	res, err := scanner.Scan(context.Background(), param)
	if err != nil {
		t.Fatalf("scan err:%v", err)
	}
	t.Logf("res:%+v", res)
}
