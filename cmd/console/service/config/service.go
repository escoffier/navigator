package config

import (
	"errors"
	"sync"
	"sync/atomic"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	instance atomic.Value // *Service
	once     sync.Once
)

func Init(postgresDB *rdbtools.GormWrapper) error {
	if postgresDB == nil {
		return errors.New("empty db client")
	}
	var err error
	once.Do(func() {
		var service *Service
		service, err = newService(postgresDB)
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

func newService(db *rdbtools.GormWrapper) (*Service, error) {
	attckHandler, err := NewATTCKHandler(db)
	if err != nil {
		return nil, err
	}
	return &Service{
		ATTCKHandler: attckHandler,
	}, nil
}
