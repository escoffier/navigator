package attack

import (
	"context"
	"errors"
	"math/rand"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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

	dataVal atomic.Value

	configVal atomic.Value
}

func NewCacheService(consoleURL string) *CacheService {
	cs := &CacheService{
		consoleURL: consoleURL,
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
		respData, err = dal.LoadAttackRules(context.Background(), c.consoleURL, c.data().Version, c.config().Version)
		return err
	}, retry.Attempts(3))
	if err != nil {
		return err
	}

	if respData.DataChanged {
		data := c.data()
		if respData.LatestDataVersion != data.Version {
			// tmpBytes, err := base64.StdEncoding.DecodeString(respData.Data)
			// if err != nil {
			// 	return fmt.Errorf("data decode error: %v", err)
			// }
			c.setData(respData.Data, respData.LatestDataVersion)
		}
	}
	if respData.SettingChanged {
		config := c.config()
		if respData.LatestDataVersion != config.Version {
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
func (c *CacheService) GetLatestData(ctx context.Context, reqDataVersion, reqSettingVersion int64) (*model.LatestATTCKRuleInfo, error) {
	data := c.data()
	config := c.config()
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
