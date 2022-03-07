package data

import (
	"context"
	"errors"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/notifyhandler"
	"gitlab.com/piccolo_su/vegeta/cmd/data/taskmanager"
	"gitlab.com/piccolo_su/vegeta/cmd/data/ttlmanager"
	"gitlab.com/piccolo_su/vegeta/cmd/data/waterlinemanager"
	"gitlab.com/security-rd/go-pkg/databases"
)

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(conf *Conf) error {
	if conf == nil {
		return errors.New("illegal argument")
	}
	once.Do(func() {
		instance = newService(conf)
	})
	return nil
}

type Service struct {
	taskManager      def.TaskManager
	ttlManager       def.TTLManager
	waterlineManager def.WaterlineManager
	notifyHandler    def.NotifyHandler

	esPod  *PodInfo
	rdbPod *PodInfo
}

type PodInfo struct {
	PVC       string
	Pod       string
	Container string
	DataPath  string
}

type Conf struct {
	RDB       *databases.RDBInstance
	EmailConf *notifyhandler.EmailConf

	ESPod  *PodInfo
	RDBPod *PodInfo
}

func newService(conf *Conf) *Service {
	service := &Service{
		esPod:            conf.ESPod,
		rdbPod:           conf.RDBPod,
		taskManager:      taskmanager.NewManager(conf.RDB, def.TaskMaxTime+time.Hour),
		ttlManager:       ttlmanager.NewManager(conf.RDB),
		waterlineManager: waterlinemanager.NewManager(conf.RDB),
		notifyHandler:    notifyhandler.NewHandler(conf.RDB, conf.EmailConf),
	}

	go service.checkStorageLoop()
	go service.expireGCTaskLoop()
	return service
}
