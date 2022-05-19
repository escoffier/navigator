package component

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"

	dockerarchive "github.com/docker/docker/pkg/archive"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type WebshellScan struct {
	WebshellAddr string
	TotalFileNum int64
}

func (w *WebshellScan) ScanLayer(ctx context.Context, digest string, layerPath string) ([]model.WebShellInfo, error) {

	sendCh := make(chan *fileContent, 10)
	revcCh := w.webShellTask(ctx, sendCh, 0)
	fileCount, err := w.parseLayerTar(layerPath, sendCh)
	if err != nil {
		return []model.WebShellInfo{}, fmt.Errorf("Failed to parseLayerTar: %w", err)
	}
	if fileCount == 0 {
		return []model.WebShellInfo{}, nil
	}
	webshellResult := <-revcCh
	return webshellResult, nil

}

func (w *WebshellScan) parseLayerTar(tarFileName string, ch chan<- *fileContent) (uint64, error) {
	defer func() { close(ch) }() // close the channel
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return 0, fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader

	tarReader := tar.NewReader(decompressStreamReader)
	var count uint64 = 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return count, fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		// 检查类型，过滤文件夹、软链接和硬链接
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
			continue
		}
		if w.webshellFileExt(filepath.Ext(header.Name)) {
			content, err := ioutil.ReadAll(tarReader)
			if err != nil {
				continue
			}
			ch <- &fileContent{fileName: header.Name, reader: bytes.NewReader(content)}
			count++
		}
	}
	return count, nil
}

func (w *WebshellScan) webShellTask(ctx context.Context, ch <-chan *fileContent, taskNum int32) <-chan []model.WebShellInfo {
	// The default value of taskNum is 6
	if taskNum <= 0 {
		taskNum = 6
	}

	var resultChan = make(chan model.WebShellInfo)
	var resultChan1 = make(chan []model.WebShellInfo)

	for i, end := int32(0), taskNum; i < end; i++ {

		// run task
		go func() {
			defer func() {
				// The last completed task closes the channel resultChan
				if atomic.AddInt32(&taskNum, -1) == 0 {
					close(resultChan)
				}
			}()

			for {
				file, ok := <-ch
				if !ok {
					break
				}

				w.TotalFileNum = w.TotalFileNum + 1
				webshellInfo, err := w.webShellCall(ctx, file.reader)
				if err != nil {
					logging.GetLogger().
						Err(err).
						Str("fileName", file.fileName).
						Msg("webshell call failed ")
					continue
				}
				if webshellInfo == nil {
					logging.GetLogger().Error().
						Msg("webshell info is nil")
					continue
				}
				if webshellInfo.Score < 4 {
					logging.GetLogger().Trace().
						Int64("score", webshellInfo.Score).
						Msg("webshell score below watermark")
					continue
				}

				webshellInfo.FilePath, webshellInfo.FileName = filepath.Split(file.fileName)

				resultChan <- *webshellInfo
			}

		}()
	}

	// result collector
	go func() {
		defer func() { close(resultChan1) }()

		r := make([]model.WebShellInfo, 0)
		for webshellResult := range resultChan {
			r = append(r, webshellResult)
		}

		// send all results
		resultChan1 <- r
	}()

	return resultChan1
}

func (w *WebshellScan) webShellCall(ctx context.Context, reader io.Reader) (*model.WebShellInfo, error) {

	defer func() {
		if err := recover(); err != nil {
			logging.GetLogger().Error().Msgf("call webshell server failed, panic: %v Stack: %s", err, string(debug.Stack()))
		}
	}()

	req, err := http.NewRequest(http.MethodPost, w.WebshellAddr, reader)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Close = true

	var tmpClient = &http.Client{
		Timeout: time.Duration(global.ScannerOpts.ScanWebshellTimeout) * time.Second,
	}
	res, err := tmpClient.Do(req)
	// res, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.GetLogger().Err(err).Msg("request webshell server err")
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(ioutil.Discard, res.Body)
		return nil, fmt.Errorf("error http code: %d", res.StatusCode)
	}
	var s = &model.WebShellInfo{}
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// webshell文件后缀列表
var extSlice = []string{
	".php", ".php5", ".php4", ".asp", ".aspx", ".asmx", ".ashx", ".jsp",
	".jspa", ".jspx", ".jspf", ".cer", ".htaccess",
}

// 判断webshell文件后缀是否是给定的后缀
func (w *WebshellScan) webshellFileExt(ext string) bool {

	for i := range extSlice {
		if extSlice[i] == ext {
			return true
		}
	}

	return false
}
