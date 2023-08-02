package hm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	hmBinaryFile = "/usr/bin/hm"
	resultFile   = "result.csv"
)

type HMWebshell struct {
	cmdDir   string
	hmBinary string
}

type ResultItem struct {
	Name       string
	Suggestion string
	Path       string
}

type Option func(hmw *HMWebshell)

func NewHMWebshell(opts ...Option) *HMWebshell {
	return &HMWebshell{
		cmdDir: "/tmp",
	}
}

func (hmw *HMWebshell) GenerateCmdDir(path string) error {
	sum := sha256.Sum256([]byte(path))
	hmw.cmdDir = "/tmp/" + hex.EncodeToString(sum[:])
	logging.GetLogger().Debug().Str("cmdDir", hmw.cmdDir).Msg("generate cmd dir")

	err := os.Mkdir(hmw.cmdDir, 0777)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create cmd dir failed")
		return err
	}

	// copy hm binary
	hmBinaryPath := filepath.Join(hmw.cmdDir, "hm")
	hmw.hmBinary = hmBinaryPath
	src, err := os.Open(hmBinaryFile)
	if err != nil {
		logging.GetLogger().Err(err).Msg("open hm binary failed")
		return err
	}
	defer src.Close()

	dst, err := os.Create(hmw.hmBinary)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create hm binary failed")
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	if err != nil {
		logging.GetLogger().Err(err).Msg("copy hm binary failed")
		return err
	}

	srcInfo, err := os.Stat(hmBinaryFile)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get hm binary info failed")
		return err
	}
	err = os.Chmod(hmw.hmBinary, srcInfo.Mode())
	if err != nil {
		logging.GetLogger().Err(err).Msg("chmod hm binary failed")
		return err
	}

	return nil
}

func (hmw *HMWebshell) ScanFile(path string) {
	cmd := exec.Command(hmw.hmBinary, "scan", path)
	cmd.Dir = hmw.cmdDir
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Str("stdout", outb.String()).Str("stderr", errb.String()).Msg("scan file failed")
		return
	}
}

func (hmw *HMWebshell) ReadAndCleanResult() ([]ResultItem, error) {
	// result.csv:
	// 序号,类型,路径
	// 1,Godzilla ASPX-ASPX后门，建议清理,../test_webshell/123.aspx
	// 2,Godzilla JSP-JSP后门，建议清理,../test_webshell/123.jsp

	defer func() {
		//delete cmd dir
		err := os.RemoveAll(hmw.cmdDir)
		if err != nil {
			logging.GetLogger().Err(err).Str("cmd dir", hmw.cmdDir).Msg("remove cmd dir failed")
		}
	}()

	resultPath := filepath.Join(hmw.cmdDir, resultFile)
	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read result file failed")
		return nil, err
	}

	result := string(resultBytes)
	logging.GetLogger().Debug().Str("result", result).Str("file path", resultPath).Msg("read result file")
	if len(result) > 0 {
		resultLines := strings.Split(result, "\n")
		resultItems := make([]ResultItem, 0)
		for _, line := range resultLines[1:] {
			if len(line) == 0 {
				continue
			}
			lineParts := strings.Split(line, ",")
			if len(lineParts) != 3 {
				logging.GetLogger().Warn().Str("line", line).Msg("result line format error")
				continue
			}
			resultItem := ResultItem{
				Name: lineParts[1],
				Path: lineParts[2],
			}
			// suggestion := strings.Split(lineParts[1], "，")[1]
			// resultItem.Suggestion = suggestion
			resultItems = append(resultItems, resultItem)
		}
		return resultItems, nil
	}
	return nil, nil

}
