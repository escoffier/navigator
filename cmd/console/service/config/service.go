package config

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/go-redis/redis/v8"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(postgresDB *rdbtools.GormWrapper, redisCli *redis.Client) error {
	if postgresDB == nil || redisCli == nil {
		return errors.New("empty db client")
	}
	var err error
	once.Do(func() {
		var service *Service
		service, err = newService(postgresDB, redisCli)
		if err == nil {
			instance.Store(service)
		}
	})

	return err
}

func GetServiceInstance() (*Service, bool) {
	service := instance.Load()
	if service == nil {
		return nil, false
	}

	return service.(*Service), true
}

type Service struct {
	*ATTCKHandler
}

func newService(db *rdbtools.GormWrapper, redisCli *redis.Client) (*Service, error) {
	attckHandler, err := NewATTCKHandler(db, redisCli)
	if err != nil {
		return nil, err
	}
	return &Service{
		ATTCKHandler: attckHandler,
	}, nil
}
