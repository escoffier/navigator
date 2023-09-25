package sync

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

var sinRegSyncSrv *RegSyncSrv

type RegSyncSrv struct {
	MqWriter      mq.Writer
	FullSyncChan  chan imagesecModel.ImageSyncTask
	IncSyncChan   chan imagesecModel.ImageSyncTask
	FullSyncQueue *TaskQueue

	registryDal imagesecStore.RegistryDal
	syncTaskDal imagesecStore.SyncTaskDal
	scanInsDal  imagesecStore.ScanInstanceDal
}

type ImageSyncService interface {
	SyncImage(ctx context.Context, task imagesecModel.ImageSyncTask) string
	AddSyncTask(ctx context.Context) error
}

func NewRegSyncSrv(
	mqWriter mq.Writer,
	registryDal imagesecStore.RegistryDal,
	syncTaskDal imagesecStore.SyncTaskDal,
	scanInsDal imagesecStore.ScanInstanceDal,
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
	}
	// 开启增量同步
	s.incSyncRegImage(context.Background())
	// 开启全量同步
	s.fullSyncRegImage(context.Background())
	sinRegSyncSrv = s

	return sinRegSyncSrv
}

func (s *RegSyncSrv) SyncImage(ctx context.Context, task imagesecModel.ImageSyncTask) string {
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
				logging.Get().Error().Msg("fullSyncRegImage recover panic")
			}
		}()

		for task := range s.FullSyncChan {
			reg := task.Registry
			logging.Get().Info().Str("module", "RegistryImage").Str("regName", reg.Name).Int64("regID", reg.ID).Msg("fullSyncRegImage start")

			if reg.ScannerInstance != global.ScannerInstance {
				s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusFailedStr)
				logging.Get().Error().Str("regName", reg.Name).Str("url", reg.Url).Msg("fullSyncRegImage registry not in this cluster")
				continue
			}

			logging.Get().Info().Str("module", "RegistryImage").Str("regName", reg.Name).Int64("regID", reg.ID).Str("regUrl", reg.Url).
				Msg("fullSyncRegImage start")

			driver, err := warehouse.GetRegistryDriver(reg)
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", reg.Name).Msg("fullSyncRegImage getRegistryDriver")

				s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusFailedStr)

				continue
			}

			_, err = driver.ListImages(ctx, s.getExtender(), warehouse.ListImagesRequest{})

			s.FullSyncQueue.Set(task.RegistryID, imagesecModel.TaskStatusImageSyncFinishedStr)

			logging.Get().Info().Str("module", "RegistryImage").Str("regName", reg.Name).Int64("regID", reg.ID).
				Str("regUrl", reg.Url).Msg("fullSyncRegImage end")
		}
	}()
}

// 增量同步
func (s *RegSyncSrv) incSyncRegImage(ctx context.Context) {

	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msg("fullSyncRegImage recover panic")
		}

		for ta := range s.IncSyncChan {

			reg := ta.Registry

			logging.Get().Debug().Str("module", "RegistryImage").Str("regName", reg.Name).
				Int64("regID", reg.ID).Str("regUrl", reg.Url).Msg("incSyncRegImage start")
			if reg.ScannerInstance != global.ScannerInstance {
				logging.Get().Error().Str("regName", reg.Name).Str("url", reg.Url).Msg("incSyncRegImage registry not in this cluster")
				continue
			}
			if time.Now().Unix()-reg.LastSyncAt/1000 > 60*60*24 {
				// 增量同步最多同步一天的，防止audit log过多
				logging.Get().Info().Str("module", "RegistryImage").Str("regName", reg.Name).
					Int64("regID", reg.ID).Int64("LastSyncAt", reg.LastSyncAt).
					Str("regUrl", reg.Url).Msg("incSyncRegImage LastSyncAt")
				continue
			}

			driver, err := warehouse.GetRegistryDriver(reg)
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", reg.Name).Msg("SyncRegImage getRegistryDriver")
				continue
			}

			if !driver.SupportIncrementalSync(ctx) {
				logging.Get().Info().Str("module", "RegistryImage").Str("regName", reg.Name).Int64("regID", reg.ID).
					Str("regUrl", reg.Url).Msg("incSyncRegImage not support incremental sync")
				continue
			}
			_, err = driver.ListImagesWithAuditLog(ctx, s.getExtender(),
				warehouse.ListImagesAuditLog{StartAt: reg.LastSyncAt / 1000, EndAt: time.Now().Unix()},
			)
			logging.Get().Debug().Str("module", "RegistryImage").Str("regName", reg.Name).Int64("regID", reg.ID).
				Str("regUrl", reg.Url).Msg("incSyncRegImage end")
		}
	}()
}
