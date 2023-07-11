package services

import (
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"runtime/debug"
	"sync"
)

var (
	services = map[consts.ServiceType]Service{}
)

type Service interface {
	Type() consts.ServiceType

	// Run service run.
	Run() error

	// PreRun some prepare job before service run.
	// @param cfg config.Config: init config loaded form yaml
	// @param nc NodeImageConfig: last synced from console
	// @param bs : broadcast server,used for subscribe notify event
	PreRun(cfg config.Config, nc imagesecModel.NodeImageConfig, bs *util.BroadcastServer) error
}

func RegisterService(service Service) error {
	_, ok := services[service.Type()]
	if ok {
		return fmt.Errorf("duplicate service:%v", service.Type())
	}
	services[service.Type()] = service
	return nil
}

func GetService(t consts.ServiceType) (Service, error) {
	v, ok := services[t]
	if !ok {
		return nil, fmt.Errorf("not found service:%v", t)
	}
	return v, nil
}

// RunServices run all service
func RunServices(cfg *config.Config, nc *imagesecModel.NodeImageConfig) error {
	// 先处理所有的准备工作，比如订阅广播事件，避免极端情况下grpc先收到消息而部分服务没启动错过了消息
	for k, v := range services {
		err := v.PreRun(*cfg, *nc, helper.BroadcastServer)
		if err != nil {
			logging.Get().Err(err).Str("service", string(k)).Msg("pre run err")
		}
	}

	// then start service
	wg := sync.WaitGroup{}
	for _, v := range services {
		wg.Add(1)
		go func(s Service) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("recover error:%v,%s", r, debug.Stack())
				}
			}()
			defer wg.Done()

			err := s.Run()
			if err != nil {
				logging.Get().Err(err).Str("service", string(s.Type())).Msg("failed to run service")
			}
		}(v)
	}
	wg.Wait()
	return nil
}
