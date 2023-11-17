package attack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"

	clusterAgent "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cryption"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	consoleAPIPath = "/api/openapi/ATTCK/latestData"
)

type data struct {
	Version int64
	Data    string
}
type config struct {
	Version     int64
	ClosedRules []string
}
type CacheService struct {
	consoleURL string

	versionVal atomic.Int64

	dataVal atomic.Value

	configVal atomic.Value

	agent *clusterAgent.ClusterAgent
}

func NewCacheService(consoleURL string, agent *clusterAgent.ClusterAgent) *CacheService {
	cs := &CacheService{
		consoleURL: consoleURL,
		agent:      agent,
	}
	cs.setData("", 0)
	cs.setConfig(nil, 0)
	err := cs.load()
	if err != nil {
		logging.Get().Err(err).Msg("load at init error")
	}
	cs.asyncLoop()
	return cs
}
func (c *CacheService) setVersion(v int64) {
	c.versionVal.Store(v)
}
func (c *CacheService) version() int64 {
	// 随holmes版本升级
	return c.versionVal.Load()
}

func (c *CacheService) setData(d string, version int64) {
	c.dataVal.Store(data{
		Version: version,
		Data:    d,
	})
}
func (c *CacheService) data() data {
	return c.dataVal.Load().(data)
}

func (c *CacheService) setConfig(r []string, version int64) {
	c.configVal.Store(config{
		Version:     version,
		ClosedRules: r,
	})
}
func (c *CacheService) config() config {
	return c.configVal.Load().(config)
}

func (c *CacheService) load() error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic in load: %v", r)
		}
	}()

	var respData *model.LatestATTCKRuleInfo
	err := util.RetryWithBackoff(context.Background(), func() error {
		var err error
		currentVersion := c.version()
		if currentVersion == int64(0) {
			err = errors.New("invalid current rule primary version")
			return err
		}
		respData, err = dal.LoadAttackRules(context.Background(), c.consoleURL, currentVersion, c.data().Version, c.config().Version)
		return err
	}, retry.Attempts(3))
	if err != nil {
		return err
	}

	brd, err := json.Marshal(respData)
	logging.Get().Debug().Str("respData", string(brd)).Err(err).Msg("LoadAttackRules resp")
	if respData.DataChanged {
		data := c.data()
		logging.Get().Debug().Int64("respData.LatestDataVersion", respData.LatestDataVersion).Int64("data.Version", data.Version).Msg("respData.DataChanged")
		if respData.LatestDataVersion != data.Version {
			// 同步集群最新规则库版本
			b64Decoded, err := base64.StdEncoding.DecodeString(respData.Data)
			if err != nil {
				logging.Get().Debug().Err(err).Msg("base64.StdEncoding.DecodeString")
				return err
			}
			header, _, _, err := cryption.ReadRulesData(b64Decoded)
			if err != nil {
				logging.Get().Debug().Err(err).Msg("cryption.ReadRulesData")
				return err
			}
			err = c.agent.UpdateRuleVersion(fmt.Sprintf("v%d.%d", header.Version[0], header.Version[1]))
			if err != nil {
				logging.Get().Debug().Err(err).Msg("c.agent.UpdateRuleVersion")
				return err
			}
			// 缓存数据
			c.setData(respData.Data, respData.LatestDataVersion)
		}
	}
	if respData.SettingChanged {
		config := c.config()
		logging.Get().Debug().Int64("respData.LatestSettingVersion", respData.LatestSettingVersion).Int64("config.Version", config.Version).Msg("respData.SettingChanged")
		if respData.LatestSettingVersion != config.Version {
			c.setConfig(respData.ClosedRules, respData.LatestSettingVersion)
		}
	}
	return nil
}

func (c *CacheService) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic in asyncLoop: %v", r)
			}
		}()

		for {
			// request to server in a random interval
			randMills := rand.Int63n(8 * 1000)
			time.Sleep(time.Millisecond * time.Duration(2000+randMills))

			if err := c.load(); err != nil {
				logging.Get().Err(err).Msg("load from console error")
			}
		}
	}()
}

func (c *CacheService) GetLatestData(ctx context.Context, reqVersion, reqDataVersion, reqSettingVersion int64) (*model.LatestATTCKRuleInfo, error) {
	data := c.data()
	config := c.config()
	c.setVersion(reqVersion)
	if data.Version == 0 || config.Version == 0 {
		return nil, errors.New("cache empty")
	}

	var info = &model.LatestATTCKRuleInfo{
		LatestDataVersion:    data.Version,
		LatestSettingVersion: config.Version,
	}
	if info.LatestDataVersion > reqDataVersion {
		info.DataChanged = true
		info.Data = data.Data
	}

	if info.LatestSettingVersion > reqSettingVersion {
		info.SettingChanged = true
		info.ClosedRules = config.ClosedRules
	}
	return info, nil
}
