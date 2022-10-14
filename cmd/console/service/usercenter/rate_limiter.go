package usercenter

import (
	"context"
	"encoding/json"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
)

const (
	ConfigKey = "usercenter_loginfailconf"
)

var (
	instance *LoginRateLimiter
)

func GetLimiter(_ context.Context) *LoginRateLimiter {
	return instance
}

func Init(rdb *databases.RDBInstance) error {
	instance = newLoginRateLimiter(rdb)
	return nil
}

type LoginRateLimiter struct {
	counts *sync.Map
	config LimiterConfig
	rdb    *databases.RDBInstance
}

type LimiterConfig struct {
	RateLimitWindowSecs int64 `json:"rateLimitWindowSecs"`
	RateLimitThreshold  int32 `json:"rateLimitThreshold"`
	RateLimitEnable     int32 `json:"rateLimitEnable"`
}

func (l *LimiterConfig) SetEnable(enable int32) {
	atomic.StoreInt32(&l.RateLimitEnable, enable)
}
func (l *LimiterConfig) GetEnable() int32 {
	return atomic.LoadInt32(&l.RateLimitEnable)
}
func (l *LimiterConfig) SetWindowSec(sec int64) {
	atomic.StoreInt64(&l.RateLimitWindowSecs, sec)
}

func (l *LimiterConfig) SetThreshold(t int32) {
	atomic.StoreInt32(&l.RateLimitThreshold, t)
}

func (l *LimiterConfig) windowSec(sec int64) int64 {
	return atomic.LoadInt64(&l.RateLimitWindowSecs)
}

func (l *LimiterConfig) getThreshold() int32 {
	return atomic.LoadInt32(&l.RateLimitThreshold)
}

func newLoginRateLimiter(rdb *databases.RDBInstance) *LoginRateLimiter {
	l := new(LoginRateLimiter)
	config, err := readConfigs(rdb)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read configs error")
		config.RateLimitEnable = 0
	}
	l.config = config
	l.rdb = rdb
	l.counts = new(sync.Map)
	l.asyncLoop()

	return l
}

func readConfigs(rdb *databases.RDBInstance) (LimiterConfig, error) {
	var config LimiterConfig
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conf, err := dal.GetConfig(ctx, rdb.GetReadDB(), ConfigKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		logging.GetLogger().Err(err).Msg("read configs from postgre error")
		return config, err
	} else if conf == nil || err == gorm.ErrRecordNotFound {
		return LimiterConfig{
			RateLimitEnable: 0,
		}, nil
	}
	err = json.Unmarshal(conf.Config, &config)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("read configs unmarshal error, conf: %s. data: %+v", string(conf.Config), conf)
		return config, err
	}
	return config, nil
}

// NOTICE: should use cycled arrays here
type failStatus struct {
	count     int32
	createdAt time.Time
}

func (s *failStatus) Incr() {
	atomic.AddInt32(&s.count, 1)
}
func (s *failStatus) Count() int32 {
	return atomic.LoadInt32(&s.count)
}

func newFailStatus() *failStatus {
	return &failStatus{
		count:     0,
		createdAt: time.Now(),
	}
}

func (l *LoginRateLimiter) UpdateTimeWindow(secs int64) {
	l.config.SetWindowSec(secs)
}
func (l *LoginRateLimiter) UpdateThreshold(t int32) {
	l.config.SetThreshold(t)
}
func (l *LoginRateLimiter) UpdateEnable(enable int32) {
	l.config.SetEnable(enable)
}

func (l *LoginRateLimiter) getOrCreateStatus(_ context.Context, userName string) *failStatus {
	status, _ := l.counts.LoadOrStore(userName, newFailStatus())
	return status.(*failStatus)
}

func (l *LoginRateLimiter) LoginFailToReachLimit(ctx context.Context, userName string) bool {
	if l.config.GetEnable() == 0 {
		return false
	}

	status := l.getOrCreateStatus(ctx, userName)
	status.Incr()

	if status.Count() >= l.config.getThreshold() {
		err := dal.SetAccountBanStatus(ctx, l.rdb.Get(), userName, true)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("banning user %s error", userName)
		}
		return true
	}
	return false
}

func (l *LoginRateLimiter) clean(now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, string(debug.Stack()))
		}
	}()

	toDelete := make([]string, 0, 2)
	l.counts.Range(func(key, value interface{}) bool {
		ct := value.(*failStatus)
		if ct != nil {
			if now.Sub(ct.createdAt) > time.Duration(l.config.RateLimitWindowSecs)*time.Second {
				toDelete = append(toDelete, key.(string))
			}
		}
		return true
	})
	for _, userName := range toDelete {
		l.counts.Delete(userName)
	}
}

func (l *LoginRateLimiter) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, string(debug.Stack()))
			}
		}()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for now := range ticker.C {
			l.clean(now)
		}
	}()
}
