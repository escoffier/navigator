package usercenter

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
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
	RateLimitThreshold int32 `json:"rateLimitThreshold"`
	RateLimitEnable    bool  `json:"rateLimitEnable"`
}

func (l *LimiterConfig) SetEnable(enable bool) {
	l.RateLimitEnable = enable
}
func (l *LimiterConfig) GetEnable() bool {
	return l.RateLimitEnable
}

func (l *LimiterConfig) SetThreshold(t int32) {
	atomic.StoreInt32(&l.RateLimitThreshold, t)
}

func (l *LimiterConfig) getThreshold() int32 {
	return atomic.LoadInt32(&l.RateLimitThreshold)
}

func newLoginRateLimiter(rdb *databases.RDBInstance) *LoginRateLimiter {
	l := new(LoginRateLimiter)
	config, err := readConfigs(rdb)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read configs error")
		config.RateLimitEnable = false
	}
	l.config = config
	l.rdb = rdb
	l.counts = new(sync.Map)

	return l
}

func readConfigs(rdb *databases.RDBInstance) (LimiterConfig, error) {
	var config LimiterConfig
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conf, err := dal.GetConfig(ctx, rdb.GetReadDB(), model.ConfLogin)
	if err != nil && err != gorm.ErrRecordNotFound {
		logging.GetLogger().Err(err).Msg("read configs from postgre error")
		return config, err
	} else if conf == nil || err == gorm.ErrRecordNotFound {
		return LimiterConfig{
			RateLimitEnable: false,
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

func (l *LoginRateLimiter) UpdateThreshold(t int32) {
	l.config.SetThreshold(t)
}
func (l *LoginRateLimiter) UpdateEnable(enable bool) {
	l.config.SetEnable(enable)
}

func (l *LoginRateLimiter) getOrCreateStatus(_ context.Context, account string) *failStatus {
	status, _ := l.counts.LoadOrStore(account, newFailStatus())
	return status.(*failStatus)
}

func (l *LoginRateLimiter) LoginFailToReachLimit(ctx context.Context, account string) bool {
	if !l.config.GetEnable() {
		return false
	}

	status := l.getOrCreateStatus(ctx, account)
	status.Incr()

	if status.Count() >= l.config.getThreshold() {
		err := dal.SetAccountStatus(ctx, l.rdb.Get(), account, model.UserStatusLock)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("banning user %s error", account)
		}
		return true
	}
	return false
}

func (l *LoginRateLimiter) LoginSuccessClean(account string) {
	l.counts.Delete(account)
}
