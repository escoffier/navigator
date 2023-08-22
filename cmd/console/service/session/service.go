package session

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"

	"github.com/go-redis/redis/v8"
)

var (
	ErrNotFound = errors.New("not found")
)

const (
	// userSessionPrefix        = "session@"
	loginSecretSessionPrefix = "loginsecret@"
	userTokenPrefix          = "session@token@"
	loginConfig              = "loginConfig"
	ipBlackList              = "ipBlackList"
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
		logging.Get().Warn().Err(err).Msg("")

		// 这里不能用redisCtx
		// 这个err可能就是redisCtx超时导致的
		exist, user, err := dal.SelectUser(ctx, db, username)
		if err != nil {
			return "", err
		}

		if exist {
			if time.Now().Unix() > user.TokenExpireAt {
				return "", fmt.Errorf("token is expired, plase try again")
			}

			tokenStr = user.Token

			// redis may still be in crash state
			// attempt save to redis, the odds are 1 in 10
			go func(chance int) {
				if chance != 1 && tokenStr != "" {
					return
				}

				if gerr := s.SaveToken(context.Background(), username, tokenStr); err != nil {
					logging.Get().Warn().Err(gerr).Msg("")
				}
			}(rand.Intn(10))
		}
	}

	return tokenStr, nil
}

func (s *Service) SaveUserLoginSecret(ctx context.Context, account, key string) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()
	return s.redisCli.Set(oneCtx, getLoginSecretRedisKey(account), key, loginSecretExpireTime).Err()
}

func (s *Service) GetUserLoginSecret(ctx context.Context, db *gorm.DB, account string) (string, error) {
	redisCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	key, err := s.redisCli.Get(redisCtx, getLoginSecretRedisKey(account)).Result()
	if err != nil {
		logging.Get().Warn().Err(err).Msg("")

		exist, user, err := dal.SelectUserByAccount(context.Background(), db, account)
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

func getLoginSecretRedisKey(username string) string {
	return fmt.Sprintf("%s%s", loginSecretSessionPrefix, username)
}

func (s *Service) SaveLoginConf(ctx context.Context, tokenStr []byte) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	return s.redisCli.Set(oneCtx, loginConfig, tokenStr, DefaultTokenTTL).Err()
}

func (s *Service) GetLoginConf(ctx context.Context) ([]byte, error) {
	redisCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	return s.redisCli.Get(redisCtx, loginConfig).Bytes()
}

func (s *Service) DelLoginConf(ctx context.Context) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	return s.redisCli.Del(oneCtx, loginConfig).Err()
}

func (s *Service) SaveBlackList(ctx context.Context, ip map[string]interface{}) (err error) {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	for k, _ := range ip {
		err = s.redisCli.HSet(oneCtx, ipBlackList, k, DefaultTokenTTL).Err()
	}
	return
}

func (s *Service) DelBlackList(ctx context.Context) error {
	oneCtx, oneCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer oneCancel()

	return s.redisCli.Del(oneCtx, ipBlackList).Err()
}

func (s *Service) CheckIP(ctx context.Context, ip string) (bool, error) {
	oneCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	return s.redisCli.HExists(oneCtx, ipBlackList, ip).Result()
}

func (s *Service) CheckBlackListExists(ctx context.Context) (int64, error) {
	oneCtx, redisCancel := context.WithTimeout(ctx, defaultOneTimeout)
	defer redisCancel()

	return s.redisCli.Exists(oneCtx, ipBlackList).Result()
}
