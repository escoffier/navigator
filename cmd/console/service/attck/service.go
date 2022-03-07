package attck

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/security-rd/go-pkg/databases"
)

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(rdb *databases.RDBInstance, redisCli *redis.Client, ecCli *echelper.EventCenterClient) error {
	if rdb == nil || redisCli == nil {
		return errors.New("empty db client")
	}
	var err error
	once.Do(func() {
		var service *Service
		service, err = newService(rdb, redisCli, ecCli)
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

func newService(db *databases.RDBInstance, redisCli *redis.Client, ecCli *echelper.EventCenterClient) (*Service, error) {
	attckHandler, err := NewATTCKHandler(db, redisCli, ecCli)
	if err != nil {
		return nil, err
	}
	return &Service{
		ATTCKHandler: attckHandler,
	}, nil
}
