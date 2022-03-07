package openapiauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"go.uber.org/atomic"
)

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(rdb *databases.RDBInstance, redisCli *redis.Client) error {
	if rdb == nil || redisCli == nil {
		return errors.New("unexpected empty pointer")
	}

	once.Do(func() {
		var service = newService(rdb, redisCli)
		instance.Store(service)
	})

	return nil
}

func GetServiceInstance() (*Service, bool) {
	service := instance.Load()
	if service == nil {
		return nil, false
	}

	return service.(*Service), true
}

type Service struct {
	db       *databases.RDBInstance
	redisCli *redis.Client
}

func newService(rdb *databases.RDBInstance, redisCli *redis.Client) *Service {
	return &Service{
		db:       rdb,
		redisCli: redisCli,
	}
}

const (
	OpenAPITokenUserKeyPrefix = "openapi-token@"
	TokenExpiration           = time.Hour
)

var (
	ErrInvalidToken = errors.New("invalid open api token")
)

func (s *Service) ObtainToken(ctx context.Context, username string) (string, error) {
	token := util.GenerateUUIDHex()
	err := s.redisCli.Set(ctx, OpenAPITokenUserKeyPrefix+token, username, TokenExpiration).Err()
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) GetUsernameByToken(ctx context.Context, token string) (string, error) {
	username, err := s.redisCli.Get(ctx, OpenAPITokenUserKeyPrefix+token).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrInvalidToken
		}

		logging.Get().Err(err).Msg("get username by token fail")
		return "", err
	}

	return username, nil
}
