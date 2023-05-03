package attck

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func readBytesFromDir(dirPath string) []byte {
	fileInfos, err := os.ReadDir(dirPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(7)
	}
	fileBytes := make([]byte, 0, 50)
	partFileBytes := make([]byte, 0, 50)
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			partFileBytes = readBytesFromDir(dirPath + "/" + fileInfo.Name())
		} else {
			partFileBytes, err = os.ReadFile(dirPath + "/" + fileInfo.Name())
			if err != nil {
				fmt.Println(err)
				os.Exit(8)
			}
		}
		fileBytes = append(fileBytes, append([]byte("\n\n"), partFileBytes...)...)
		partFileBytes = make([]byte, 0, 50)
	}

	return fileBytes
}
func TestProcessorBuilder(t *testing.T) {
	bytes := readBytesFromDir("./../../../../configs/holmes/rules/v2")
	processor, _, err := ProcessorBuilder(context.Background(), bytes)
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}

	pocPlugin := newPocSwitchPluginWithGiven("qt")
	ccPlugin := NewCustomConfigPlugin(func(ctx context.Context) ([]CconfigItem, error) {
		return []CconfigItem{
			{
				CconfigKey: "miner_domains",
				RuleKey:    "Detect outbound connections to common miner pool ports",
				Values: []string{
					"/etc/hello",
					"/etc/world",
				},
			},
			{
				CconfigKey: "sensitive_paths",
				RuleKey:    "Gaining environment information",
				Values: []string{
					"/etc/hello",
					"/etc/world",
				},
			},
		}, nil
	})
	processor.AddPlugin(pocPlugin)
	processor.AddPlugin(ccPlugin)

	_, pctx, perr := processor.Process(context.Background())
	if perr != nil {
		t.Errorf("errorf: %v", perr)
		return
	}
	qtExist := false
	if len(pctx.rulesTmp) == 0 {
		t.Errorf("error empty")
	}
	for _, r := range pctx.rulesTmp {
		t.Logf("%s", r.Rule)
		if r.Rule == "Container process started" {
			t.Error("error: Container process started")
		} else if r.Rule == "Suspected malicious script execution" {
			qtExist = true
		}
	}
	if !qtExist {
		t.Error("error: Suspected malicious script execution no exist")
	}

	for k, l := range pctx.lists {
		if k == "miner_domains" {
			found := false
			for _, v := range l.Items {
				if v == "/etc/hello" {
					found = true
					break
				}
			}
			if !found {
				t.Error("error not found for miner")
			}
		} else if k == "sensitive_paths" {
			found := false
			for _, v := range l.Items {
				if v == "/etc/world" {
					found = true
					break
				}
			}
			if !found {
				t.Error("error not found for miner")
			}
		}
	}
}
