package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	ErrNotFound = errors.New("not found")
)

const (
	userSessionPrefix = "session@"
	defaultOneTimeout = time.Millisecond * 500
)

type Conf struct {
	SessionExpiration time.Duration
}

var (
	DefaultConf = &Conf{
		SessionExpiration: 12 * time.Hour,
	}
)

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(redisCli *redis.Client, conf *Conf) error {
	if redisCli == nil || conf == nil {
		return errors.New("unexpected empty pointer")
	}

	once.Do(func() {
		var service = newService(redisCli, conf)
		instance.Store(service)
	})

	return nil
}

func GetService() (*Service, bool) {
	service := instance.Load()
	if service == nil {
		return nil, false
	}

	return service.(*Service), true
}

func newService(redisCli *redis.Client, conf *Conf) *Service {
	return &Service{
		redisCli: redisCli,
		conf:     conf,
	}
}

type Service struct {
	redisCli *redis.Client
	conf     *Conf
}

func (s *Service) GetUserSession(ctx context.Context, username string) (*model.UserSession, error) {
	var cacheContent string
	get := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
		defer oneCancel()
		var _err error
		cacheContent, _err = s.redisCli.Get(oneCtx, getRedisKey(username)).Result()
		if _err == redis.Nil {
			return nil
		}
		return _err
	}

	if err := util.RetryWithBackoff(ctx, get); err != nil {
		logging.GetLogger().Err(err).Msg("get user session fail")
		return nil, err
	}

	if cacheContent == "" {
		return nil, ErrNotFound
	}

	return decode(cacheContent)
}

func (s *Service) SaveUserSession(ctx context.Context, user *model.UserSession) error {
	content := encode(user)
	set := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
		defer oneCancel()
		return s.redisCli.Set(oneCtx, getRedisKey(user.Username), content, s.conf.SessionExpiration).Err()
	}

	if err := util.RetryWithBackoff(ctx, set); err != nil {
		logging.GetLogger().Err(err).Msg("save user session fail")
		return err
	}
	return nil
}

func (s *Service) DeleteUserSession(ctx context.Context, username string) error {
	del := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
		defer oneCancel()
		return s.redisCli.Del(oneCtx, getRedisKey(username)).Err()
	}

	if err := util.RetryWithBackoff(ctx, del); err != nil {
		logging.GetLogger().Err(err).Msg("delete user session fail")
		return err
	}
	return nil
}

func (s *Service) RefreshUserSession(ctx context.Context, username string) error {
	expire := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
		defer oneCancel()
		return s.redisCli.Expire(oneCtx, getRedisKey(username), s.conf.SessionExpiration).Err()
	}

	if err := util.RetryWithBackoff(ctx, expire); err != nil {
		logging.GetLogger().Err(err).Msg("refresh user session fail")
		return err
	}

	return nil
}

func encode(userSession *model.UserSession) string {
	jsonBytes, _ := json.Marshal(userSession)
	return util.Bytes2StringNoCopy(jsonBytes)
}

func decode(content string) (*model.UserSession, error) {
	var result *model.UserSession
	jsonBytes := util.String2BytesNoCopy(content)
	var err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func getRedisKey(username string) string {
	return fmt.Sprintf("%s%s", userSessionPrefix, username)
}
