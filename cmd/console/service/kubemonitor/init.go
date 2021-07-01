package kubemonitor

import (
	"context"
	"errors"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
)

var (
	instance *Service
	once     sync.Once
)

const (
	eventsCategory   = "kubeMonitor"
	eventsCategoryCN = "集群风险监控"
	eventsModule     = "ContainerSecurity"
	eventsModuleCN   = "容器安全"
)

func Init(ecCli pb.EventsCenterCollectionServiceClient) error {
	if ecCli == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		instance, err = newService(ecCli)
		if err != nil {
			logging.GetLogger().Err(err).Msg("new kubemonitor service error")
		}
	})
	return err
}

func Get(ctx context.Context) (*Service, bool) {
	return instance, instance != nil
}
