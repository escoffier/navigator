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
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	instance *Service
	once     sync.Once
)

func Get(ctx context.Context) (*Service, bool) {
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

	mongoPod   *PodInfo
	esPod      *PodInfo
	postgrePod *PodInfo
	auditPod   *PodInfo
}

type PodInfo struct {
	PVC      string
	Pod      string
	DataPath string
}

type Conf struct {
	Mongodb    *mongotools.DatabaseWrapper
	PostgresDB *rdbtools.GormWrapper
	EmailConf  *notifyhandler.EmailConf
	MongoPod   *PodInfo
	ESPod      *PodInfo
	PostgrePod *PodInfo
	AuditPod   *PodInfo
}

func newService(conf *Conf) *Service {
	service := &Service{
		mongoPod:         conf.MongoPod,
		esPod:            conf.ESPod,
		postgrePod:       conf.PostgrePod,
		auditPod:         conf.AuditPod,
		taskManager:      taskmanager.NewManager(conf.Mongodb, model.GCTaskCollection.String(), def.TaskMaxTime+time.Hour),
		ttlManager:       ttlmanager.NewManager(conf.Mongodb, model.DataTTLSettingCollection.String()),
		waterlineManager: waterlinemanager.NewManager(conf.Mongodb, model.DataWaterlineSettingCollection.String()),
		notifyHandler:    notifyhandler.NewHandler(conf.PostgresDB, conf.EmailConf),
	}

	go service.checkStorageLoop()
	go service.expireGCTaskLoop()
	return service
}
