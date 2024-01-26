package sync

import (
	"context"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

var sinRegSyncSrv *RegSyncSrv

type RegSyncSrv struct {
	MqWriter      mq.Writer
	FullSyncChan  chan imagesecModel.ImageSyncTask
	IncSyncChan   chan imagesecModel.ImageSyncTask
	FullSyncQueue *TaskQueue
	registryDal   imagesecStore.RegistryDal
	syncTaskDal   imagesecStore.SyncTaskDal
	scanInsDal    imagesecStore.ScanInstanceDal
	PreImageDal   adaptStore.ImageDal
	Log           *scannerUtils.LogEvent
}

type ImageSyncService interface {
	CreateSyncTask(ctx context.Context) error
	SyncImageMeta(ctx context.Context) error
}

func NewRegSyncSrv(
	mqWriter mq.Writer,
	registryDal imagesecStore.RegistryDal,
	syncTaskDal imagesecStore.SyncTaskDal,
	scanInsDal imagesecStore.ScanInstanceDal,
	preImageDal adaptStore.ImageDal,
) *RegSyncSrv {
	if sinRegSyncSrv != nil {
		return sinRegSyncSrv
	}
	s := &RegSyncSrv{
		MqWriter:      mqWriter,
		FullSyncChan:  make(chan imagesecModel.ImageSyncTask),
		IncSyncChan:   make(chan imagesecModel.ImageSyncTask),
		FullSyncQueue: NewTaskQueue(),
		registryDal:   registryDal,
		syncTaskDal:   syncTaskDal,
		scanInsDal:    scanInsDal,
		PreImageDal:   preImageDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("Sync"),
			scannerUtils.WithModule(consts.ModuleRegistryImage),
		),
	}
	// 开启增量同步
	s.incSyncRegImage(context.Background())
	// 开启全量同步
	s.fullSyncRegImage(context.Background())
	sinRegSyncSrv = s

	return sinRegSyncSrv
}

// 接收同步任务
func (s *RegSyncSrv) ReceiveSyncImage(ctx context.Context, task imagesecModel.ImageSyncTask) string {
	switch task.SyncType {
	case imagesecModel.CycleIncSync.String():
		go func() { s.IncSyncChan <- task }()
	default:
		status, exit := s.FullSyncQueue.Get(task.RegistryID)
		if !exit {
			s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusInprogressStr)
			go func() { s.FullSyncChan <- task }()
			return imagesecModel.TaskStatusInprogressStr
		}

		if status != imagesecModel.TaskStatusInprogressStr {
			go func() { s.FullSyncQueue.Delete(task.RegistryID) }()
		}
		return status
	}
	return ""
}

// 执行全量同步
func (s *RegSyncSrv) fullSyncRegImage(ctx context.Context) {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("fullSyncRegImage recover panic")
			}
		}()

		for task := range s.FullSyncChan {
			reg := task.Registry
			s.Log.Info().Str("regName", reg.Name).Int64("regID", reg.ID).Msg("fullSyncRegImage start")

			if reg.ScannerInstance != global.ScannerInstance {
				s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusFailedStr)
				s.Log.Error().Str("regName", reg.Name).Str("url", reg.Url).Msg("fullSyncRegImage registry not in this cluster")
				continue
			}

			s.Log.Info().Str("regName", reg.Name).Int64("regID", reg.ID).Str("regUrl", reg.Url).
				Msg("fullSyncRegImage start")

			driver, err := warehouse.GetRegistryDriver(reg)
			if err != nil {
				s.Log.Err(err).Str("regName", reg.Name).Msg("fullSyncRegImage getRegistryDriver")

				s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusFailedStr)

				continue
			}

			_, err = driver.ListImages(ctx, s.getExtender(), warehouse.ListImagesRequest{})

			s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusImageSyncFinishedStr)

			s.Log.Info().Str("regName", reg.Name).Int64("regID", reg.ID).
				Str("regUrl", reg.Url).Msg("fullSyncRegImage end")
		}
	}()
}

// 增量同步
func (s *RegSyncSrv) incSyncRegImage(ctx context.Context) {

	go func() {
		if r := recover(); r != nil {
			s.Log.Error().Str("Stack", string(debug.Stack())).Msg("fullSyncRegImage recover panic")
		}

		for ta := range s.IncSyncChan {

			reg := ta.Registry

			s.Log.Debug().Str("regName", reg.Name).
				Int64("regID", reg.ID).Str("regUrl", reg.Url).Msg("incSyncRegImage start")
			if reg.ScannerInstance != global.ScannerInstance {
				s.Log.Error().Str("regName", reg.Name).Str("url", reg.Url).Msg("incSyncRegImage registry not in this cluster")
				continue
			}
			if time.Now().Unix()-reg.LastSyncAt/1000 > 60*60*24 {
				// 增量同步最多同步一天的，防止audit log过多
				s.Log.Info().Str("regName", reg.Name).
					Int64("regID", reg.ID).Int64("LastSyncAt", reg.LastSyncAt).
					Str("regUrl", reg.Url).Msg("incSyncRegImage LastSyncAt")
				continue
			}

			driver, err := warehouse.GetRegistryDriver(reg)
			if err != nil {
				s.Log.Err(err).Str("regName", reg.Name).Msg("SyncRegImage getRegistryDriver")
				continue
			}

			if !driver.SupportIncrementalSync(ctx) {
				s.Log.Info().Str("regName", reg.Name).Int64("regID", reg.ID).
					Str("regUrl", reg.Url).Msg("incSyncRegImage not support incremental sync")
				continue
			}
			_, err = driver.ListImagesWithAuditLog(ctx, s.getExtender(),
				warehouse.ListImagesAuditLog{StartAt: reg.LastSyncAt / 1000, EndAt: time.Now().Unix()},
			)
			s.Log.Debug().Str("regName", reg.Name).Int64("regID", reg.ID).
				Str("regUrl", reg.Url).Msg("incSyncRegImage end")
		}
	}()
}
