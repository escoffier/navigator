package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"

	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"github.com/go-redis/redis/v8"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	ErrNotFound = errors.New("not found")
)

const (
	userSessionPrefix        = "session@"
	loginSecretSessionPrefix = "loginsecret@"
	userTokenPrefix          = "session@token@"
	defaultOneTimeout        = time.Millisecond * 500
	loginSecretExpireTime    = time.Minute

	DefaultTokenTTL = time.Minute * 30 // 默认的token ttl
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

func (s *Service) SaveToken(ctx context.Context, username, tokenStr string) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()
	return s.redisCli.Set(oneCtx, userTokenPrefix+username, tokenStr, DefaultTokenTTL).Err()
}

func (s *Service) RenewalToken(ctx context.Context, username string) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()
	return s.redisCli.Expire(oneCtx, userTokenPrefix+username, DefaultTokenTTL).Err()
}

func (s *Service) DeleteToken(ctx context.Context, db *gorm.DB, username string) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	err := dal.UpdateUserToken(ctx, db, username, "", time.Now().Unix())
	if err != nil {
		return fmt.Errorf("delete user token fail:%w", err)
	}

	return s.redisCli.Del(oneCtx, userTokenPrefix+username).Err()
}

func (s *Service) GetToken(ctx context.Context, db *gorm.DB, username string) (string, error) {
	redisCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	tokenStr, err := s.redisCli.Get(redisCtx, userTokenPrefix+username).Result()
	if err != nil {
		logging.GetLogger().Warn().Err(err)

		exist, user, err := dal.SelectUser(context.Background(), db, username)
		if err != nil {
			return "", err
		}

		if exist {
			if time.Now().Unix() > user.TokenExpireAt {
				return "", fmt.Errorf("token is expired, plase try again")
			}

			tokenStr = user.Token

			// attempt save to redis
			// The odds are 1 in 10
			go func(chance int) {
				if chance != 1 && tokenStr != "" {
					return
				}

				if err = s.SaveToken(context.Background(), username, tokenStr); err != nil {
					logging.GetLogger().Warn().Err(err)
				}
			}(rand.Intn(10))
		}
	}

	return tokenStr, nil
}

func (s *Service) SaveUserLoginSecret(ctx context.Context, username, key string) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()
	return s.redisCli.Set(oneCtx, getLoginSecretRedisKey(username), key, loginSecretExpireTime).Err()
}

func (s *Service) GetUserLoginSecret(ctx context.Context, db *gorm.DB, username string) (string, error) {
	redisCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	key, err := s.redisCli.Get(redisCtx, getLoginSecretRedisKey(username)).Result()
	if err != nil {
		logging.GetLogger().Warn().Err(err)

		exist, user, err := dal.SelectUser(context.Background(), db, username)
		if err != nil {
			return "", err
		}

		if exist {
			if time.Now().Unix() > user.LoginSecretKeyExpireAt {
				return "", fmt.Errorf("login expire, Plase try again")
			}

			key = user.LoginSecretKey
		}
	}

	if key == "" {
		return "", fmt.Errorf("login secret key not found")
	}

	return key, nil
}

func (s *Service) GetUserSession(ctx context.Context, db *gorm.DB, username string, external bool) (*model.UserSession, error) {
	redisCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	cacheContent, err := s.redisCli.Get(redisCtx, getRedisKey(username)).Result()
	if err == nil && cacheContent != "" {
		return decode(cacheContent)
	}

	logging.GetLogger().Warn().Err(err)

	mysqlCtx, mysqlCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer mysqlCancel()

	exist, user, err := dal.SelectUser(mysqlCtx, db, username)
	if err != nil {
		return nil, err
	}

	if !exist {
		return nil, ErrNotFound
	}

	return user.GenerateSession(external), nil

}

func (s *Service) SaveUserSession(ctx context.Context, user *model.UserSession) error {
	return nil
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	content := encode(user)
	return s.redisCli.Set(oneCtx, getRedisKey(user.Username), content, s.conf.SessionExpiration).Err()
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
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()
	return s.redisCli.Expire(oneCtx, getRedisKey(username), s.conf.SessionExpiration).Err()
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

func getLoginSecretRedisKey(username string) string {
	return fmt.Sprintf("%s%s", loginSecretSessionPrefix, username)
}
