package watch

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	token         = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	UploadThrPath = "/tmp/holmes_rules.thr"
	tokenHeader   = "X-Tensorsec-cicd-key"
)

type HTTPRequestInfo struct {
	token                 string
	url                   string
	currentRulesVersion   int64
	currentSettingVersion int64
	closeRulesVal         atomic.Value // []string
}

func (i *HTTPRequestInfo) setCurrentRulesVersion(v int64) {
	atomic.StoreInt64(&i.currentRulesVersion, v)
}
func (i *HTTPRequestInfo) setCurrentSettingVersion(v int64) {
	atomic.StoreInt64(&i.currentSettingVersion, v)
}
func (i *HTTPRequestInfo) getCurrentRulesVersion() int64 {
	return atomic.LoadInt64(&i.currentRulesVersion)
}
func (i *HTTPRequestInfo) getCurrentSettingVersion() int64 {
	return atomic.LoadInt64(&i.currentSettingVersion)
}
func (i *HTTPRequestInfo) CloseRules() []string {
	return i.closeRulesVal.Load().([]string)
}
func (i *HTTPRequestInfo) setCloseRules(r []string) {
	i.closeRulesVal.Store(r)
}

type latestVersionResp struct {
	Data struct {
		Item struct {
			Data                 string   `json:"data"`
			Closerules           []string `json:"closedRules"`
			LatestDataVersion    int64    `json:"latestDataVersion"`
			LatestSettingVersion int64    `json:"latestSettingVersion"`
			DataChanged          bool     `json:"dataChanged"`
			SettingChanged       bool     `json:"settingChanged"`
		} `json:"item"`
	} `json:"data"`
}

func NewHTTPRequest(url string) *HTTPRequestInfo {
	r := &HTTPRequestInfo{
		token:                 token,
		url:                   url,
		currentRulesVersion:   -1,
		currentSettingVersion: -1,
		closeRulesVal:         atomic.Value{},
	}
	r.setCloseRules(make([]string, 0))
	return r
}

func saveRulesFile(writeBytes []byte, path string) {
	fp, err := os.Create(path)
	if err != nil {
		logging.Get().Err(err).Msgf("create file error. path: %s", path)
		return
	}
	defer fp.Close()
	_, err = fp.Write(writeBytes)
	if err != nil {
		logging.Get().Err(err).Msgf("write rules files error")
		return
	}
	err = fp.Sync()
	if err != nil {
		logging.Get().Err(err).Msgf("sync write error")
	}
}

func (i *HTTPRequestInfo) rulesUpdate() ([]byte, bool, bool, error) {
	httpStreamData, err := i.getData()
	if err != nil {
		logging.Get().Err(err).Msg("get data err")
		return nil, false, false, err
	}
	var tmpBytes []byte
	var rulesUpdated, settingsUpdated bool
	if httpStreamData.Data.Item.DataChanged || httpStreamData.Data.Item.SettingChanged {
		if i.getCurrentRulesVersion() != httpStreamData.Data.Item.LatestDataVersion {
			i.setCurrentRulesVersion(httpStreamData.Data.Item.LatestDataVersion)
			tmpBytes, _ = base64.StdEncoding.DecodeString(httpStreamData.Data.Item.Data)
			saveRulesFile(tmpBytes, UploadThrPath)
			rulesUpdated = true
		}
		if i.getCurrentSettingVersion() != httpStreamData.Data.Item.LatestSettingVersion {
			i.setCurrentSettingVersion(httpStreamData.Data.Item.LatestSettingVersion)
			i.setCloseRules(httpStreamData.Data.Item.Closerules)
			settingsUpdated = true
		}

	}
	return tmpBytes, rulesUpdated, settingsUpdated, nil
}
func (i *HTTPRequestInfo) RulesUpdateLoop(udpateC chan<- struct{}, errorC chan error) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		_, rulesUpdated, settingsUpdated, err := i.rulesUpdate()
		if err != nil {
			errorC <- err
		} else if rulesUpdated || settingsUpdated {
			udpateC <- struct{}{}
		}
	}
}

func (i *HTTPRequestInfo) getData() (latestVersionResp, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s?curDataVersion=%d&curSettingVersion=%d", i.url, i.getCurrentRulesVersion(), i.getCurrentSettingVersion())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return latestVersionResp{}, err
	}
	req.Header.Set(tokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return latestVersionResp{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStru := latestVersionResp{}
	err = json.Unmarshal(body, &respStru)
	if err != nil {
		return latestVersionResp{}, err
	}
	return respStru, nil
}
