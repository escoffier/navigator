package watch

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
func (i *HTTPRequestInfo) CloseRules() map[string]struct{} {
	return i.closeRulesVal.Load().(map[string]struct{})
}
func (i *HTTPRequestInfo) setCloseRules(r map[string]struct{}) {
	i.closeRulesVal.Store(r)
}

func NewHTTPRequest(url string) *HTTPRequestInfo {
	r := &HTTPRequestInfo{
		token:                 token,
		url:                   url,
		currentRulesVersion:   -1,
		currentSettingVersion: -1,
		closeRulesVal:         atomic.Value{},
	}
	r.setCloseRules(make(map[string]struct{}, 0))
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

func toClosedRules(arr []string) map[string]struct{} {
	m := make(map[string]struct{}, len(arr))
	for _, r := range arr {
		m[r] = struct{}{}
	}
	return m
}
func (i *HTTPRequestInfo) rulesUpdate() ([]byte, bool, bool, error) {
	data, err := i.getData()
	if err != nil {
		logging.Get().Err(err).Msg("get data err")
		return nil, false, false, err
	}
	var tmpBytes []byte
	var rulesUpdated, settingsUpdated bool
	if data.DataChanged || data.SettingChanged {
		if i.getCurrentRulesVersion() != data.LatestDataVersion {
			i.setCurrentRulesVersion(data.LatestDataVersion)
			tmpBytes, err = base64.StdEncoding.DecodeString(data.Data)
			if err != nil {
				return nil, false, false, fmt.Errorf("data decode error: %v", err)
			}
			saveRulesFile(tmpBytes, UploadThrPath)
			rulesUpdated = true
		}
		if i.getCurrentSettingVersion() != data.LatestSettingVersion {
			i.setCurrentSettingVersion(data.LatestSettingVersion)
			i.setCloseRules(toClosedRules(data.ClosedRules))
			settingsUpdated = true
		}

	}
	return tmpBytes, rulesUpdated, settingsUpdated, nil
}
func (i *HTTPRequestInfo) RulesUpdateLoop(udpateC chan<- struct{}, errorC chan error) {
	randSec := rand.Int63n(5 * int64(time.Second/time.Nanosecond))
	time.Sleep(time.Duration(randSec) * time.Nanosecond)
	
	for {
		_, rulesUpdated, settingsUpdated, err := i.rulesUpdate()
		if err != nil {
			errorC <- err
		} else if rulesUpdated || settingsUpdated {
			udpateC <- struct{}{}
		}

		randSec := rand.Int63n(20)
		time.Sleep(time.Second * time.Duration(20+randSec))
	}
}

func (i *HTTPRequestInfo) getData() (*model.LatestATTCKRuleInfo, error) {
	return dal.LoadAttackRules(context.Background(), i.url, i.getCurrentRulesVersion(), i.getCurrentSettingVersion())
}
