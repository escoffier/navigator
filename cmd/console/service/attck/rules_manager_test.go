package attck

import (
	"context"
	"fmt"
	"os"
	"testing"

	"gitlab.com/security-rd/go-pkg/cryption"
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
	_, store, err := ProcessorBuilder(context.Background(), bytes)
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}
	// t.Errorf("rules len: %d", len(store.rmap))
	// t.Errorf("iconfigs len: %d", len(store.configsInit))

	rawBytes, _ := os.ReadFile("./../../../../dist/holmes-rules-v2.1894.thr")
	_, rulesContext, _, err := cryption.ReadRulesData(rawBytes)
	_, store, err = ProcessorBuilder(context.Background(), rulesContext)
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}
	t.Errorf("rules len: %d", len(store.rmap))
	t.Errorf("iconfigs len: %d", len(store.configsInit))
}
