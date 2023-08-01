package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.com/security-rd/go-pkg/logging"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type SyncTaskDispatcher interface {
	DispatchSyncTask(ctx context.Context) error
}

type RegDispatchSrv struct {
	registryDal imagesecStore.RegistryDal
	syncTaskDal imagesecStore.SyncTaskDal
	scanInsDal  imagesecStore.ScanInstanceDal

	SyncTaskUpdateChan chan SyncTaskUpdate
}

func NewRegDispatchSrv(
	registryDal imagesecStore.RegistryDal,
	syncTaskDal imagesecStore.SyncTaskDal,
	scanInsDal imagesecStore.ScanInstanceDal,
) *RegDispatchSrv {

	s := &RegDispatchSrv{
		registryDal:        registryDal,
		syncTaskDal:        syncTaskDal,
		scanInsDal:         scanInsDal,
		SyncTaskUpdateChan: make(chan SyncTaskUpdate),
	}
	s.UpdateSyncTask(context.Background())
	return s
}

func (s *RegDispatchSrv) DispatchSyncTask(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "RegistryImage").Msg("DispatchSyncTask not in main cluster did not PublishSubtask")
		return nil
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("dispatchFullSyncTask panic recover")
			}
		}()

		s.dispatchFullSyncTask(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("dispatchIncrSyncTask panic recover")
			}
		}()

		s.dispatchIncrSyncTask(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("CheckRegistryHealth panic recover")
			}
		}()

		s.CheckRegistryHealth(ctx)
	}()

	return nil
}

func (s *RegDispatchSrv) sendRegSyncTask(ctx context.Context, task imagesecModel.ImageSyncTask) (int64, error) {

	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 20*time.Second)
	defer timeOutFunc()
	data, err := json.Marshal(task)
	if err != nil {
		return 0, err
	}

	defer timeOutFunc()

	req := &pb.ImageSecReq{
		ImageSecReqType: pb.ImageSecReqType_RegistryImageSync,
		ClusterKey:      task.ScanInsInfo.ClusterKey,
		RequestID:       uuid.New().String(),
		Payload:         data,
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("reg", req).Msg("DispatchSyncTask sendMsg")

	streamClient := imagesecStream.MustGetGrpcStream()

	rsp, err := streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Interface("req", req).Msg("DispatchSyncTask")
		return 0, err
	}

	return int64(rsp.Status), nil
}

func (s *RegDispatchSrv) UpdateSyncTask(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("recover panic")
			}
		}()

		for up := range s.SyncTaskUpdateChan {
			where := fmt.Sprintf("id = %d", up.SyncTaskID)

			updater := map[string]interface{}{}
			updater["result"] = up.Result
			if up.Start {
				updater["start_at"] = time.Now().UnixMilli()
			}
			if up.End {
				updater["finish_at"] = time.Now().UnixMilli()
				delete(updater, "start_at")
			}
			if up.Result == imagesecModel.TaskStatusImageSyncFinishedStr {
				task, err := s.syncTaskDal.SearchSyncTask(ctx, imagesecModel.SearchSyncTaskParam{TaskID: up.SyncTaskID})
				if err != nil {
					logging.Get().Err(err).Str("module", "RegistryImage").Int64("syncTaskID", up.SyncTaskID).
						Msg("SearchSyncTask")
					continue
				}
				if len(task) == 0 {
					logging.Get().Err(err).Str("module", "RegistryImage").Int64("syncTaskID", up.SyncTaskID).
						Msg("SearchSyncTask not find task")
					continue
				}
				updaterReg := map[string]interface{}{"last_sync_at": task[0].StartAt}
				_ = s.registryDal.UpdateRegistry(ctx, imagesecModel.SearchRegistryParam{ID: task[0].RegistryID}, updaterReg)
			}

			if up.Err != nil {
				updater["result"] = up.Err.Error()
			}
			if err := s.syncTaskDal.UpdateSyncTask(ctx, where, updater); err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Int64("syncTaskID", up.SyncTaskID).Msg("UpdateSyncTask")
				continue
			}
			logging.Get().Info().Str("module", "RegistryImage").Int64("syncTaskID", up.SyncTaskID).Interface("updater", up).Msg("UpdateSyncTask")
		}
	}()
}

func (s *RegDispatchSrv) dispatchFullSyncTask(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortDesc().SetSortFiledByID()

	for {
		<-ticker.C
		tasks, err := s.syncTaskDal.SearchSyncTask(ctx, imagesecModel.SearchSyncTaskParam{
			Finished: consts.FalseString,
			Filter:   filter,
		})
		if err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Msg("SearchSyncTask")
			continue
		}
		for _, ta := range tasks {
			up := SyncTaskUpdate{SyncTaskID: ta.ID, Start: true}
			go func() { s.SyncTaskUpdateChan <- up }()
			regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{ID: ta.RegistryID, Deleted: consts.FalseString})
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Msg("SearchRegistry")
				continue
			}
			if len(regs) == 0 {
				up.End = true
				up.Err = fmt.Errorf("not find reg info")

				go func() { s.SyncTaskUpdateChan <- up }()

				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Msg("dispatchFullSyncTask not find registry")
				continue
			}

			scanInsInfo, err := s.scanInsDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{ScannerInstance: regs[0].ScannerInstance})
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Msg("dispatchFullSyncTask SearchScannerInfo")
				continue
			}

			if len(scanInsInfo) == 0 {
				up.End = true
				up.Err = fmt.Errorf("not find scanInsInfo")

				go func() { s.SyncTaskUpdateChan <- up }()

				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Str("ScannerInstance", regs[0].ScannerInstance).
					Msg("dispatchFullSyncTask not find scan instance")
				continue
			}

			ta.Registry = regs[0]
			ta.ScanInsInfo = scanInsInfo[0]

			logging.Get().Debug().Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Interface("syncTask", ta).
				Msg("dispatchFullSyncTask ready to send")
			syncStatus, err := s.sendRegSyncTask(ctx, ta)
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", ta.RegistryID).
					Msg("dispatchFullSyncTask sendRegSyncTask")
				continue
			}

			if syncStatus != consts.StreamStatusSyncProgress {
				logging.Get().Info().Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Str("syncStatus", getSyncStatus(syncStatus)).
					Msg("dispatchFullSyncTask task finished")
				up.End = true
				if syncStatus == consts.StreamStatusSyncFinished {
					up.Result = "finished"
				}
				if syncStatus == consts.StreamStatusSyncFailed {
					up.Result = "failed"
				}
				go func() { s.SyncTaskUpdateChan <- up }()
				continue
			}
			logging.Get().Info().Str("module", "RegistryImage").Int64("regID", ta.RegistryID).Str("regName", ta.Registry.Name).Str("syncStatus", getSyncStatus(syncStatus)).
				Str("ScannerInstance", regs[0].ScannerInstance).
				Msg("dispatchFullSyncTask succeed")
		}
	}
}

func (s *RegDispatchSrv) dispatchIncrSyncTask(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	var preStart int64

	for {
		<-ticker.C
		start := time.Now().UnixMilli()

		regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
		if err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Msg("SearchRegistry")
			continue
		}
		for i := range regs {
			reg := regs[i]
			scanInsInfo, err := s.scanInsDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{ScannerInstance: reg.ScannerInstance})
			if err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", reg.ID).Msg("dispatchIncrSyncTask SearchScannerInfo")
				continue
			}

			if len(scanInsInfo) == 0 {
				logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", reg.ID).Str("ScannerInstance", regs[0].ScannerInstance).
					Msg("dispatchFullSyncTask not find scan instance")
				continue
			}

			if preStart > 0 {
				reg.LastSyncAt = preStart
			}

			ta := imagesecModel.ImageSyncTask{
				RegistryID:  reg.ID,
				SyncType:    imagesecModel.CycleIncSync.String(),
				Registry:    reg,
				ScanInsInfo: scanInsInfo[0],
			}

			if _, err := s.sendRegSyncTask(ctx, ta); err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Interface("reg", reg).Msg("sendRegSyncTask")
				continue
			}
		}

		preStart = start
	}
}

func (s *RegDispatchSrv) CheckRegistryHealth(ctx context.Context) {
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()

	for {
		<-ticker.C

		regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
		if err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Msg("SearchRegistry")
			continue
		}
		for i := range regs {
			if err := s.SendToScannerCheckHealth(ctx, regs[i]); err != nil {
				logging.Get().Err(err).Str("module", "RegistryImage").Msg("CheckRegistryHealth")
			}
		}
	}
}

type SyncTaskUpdate struct {
	SyncTaskID int64
	Start      bool
	End        bool
	Result     string
	Err        error
}

func getSyncStatus(st int64) string {
	switch st {
	case consts.StreamStatusSyncProgress:
		return imagesecModel.TaskStatusInprogressStr
	case consts.StreamStatusSyncFailed:
		return imagesecModel.TaskStatusFailedStr
	case consts.StreamStatusSyncFinished:
		return imagesecModel.TaskStatusImageSyncFinishedStr
	default:
		logging.Get().Error().Str("module", "RegistryImage").Int64("rpcStatus", st).Msg("getSyncStatus")
		return "unknown"
	}
}

func (s *RegDispatchSrv) SendToScannerCheckHealth(ctx context.Context, reg imagesecModel.Registry) error {

	streamClient := imagesecStream.MustGetGrpcStream()

	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 10*time.Second)
	defer timeOutFunc()
	data, err := json.Marshal(reg)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("SendToScannerCheckHealth")
		return err
	}
	clusterKey := strings.TrimPrefix(reg.ScannerInstance, "scan-")

	defer timeOutFunc()
	req := &pb.ImageSecReq{
		ImageSecReqType: pb.ImageSecReqType_RegistryHealthyCheck,
		ClusterKey:      clusterKey,
		RequestID:       uuid.New().String(),
		Payload:         data,
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("reg", req).Msg("SendToScannerCheckHealth sendMsg")

	rsp, err := streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Interface("req", req).Msg("SendToScannerCheckHealth")
		return err
	}
	switch rsp.Status {
	case consts.StreamStatusRegOK:
		if reg.Status == consts.RegistryNormal {
			return nil
		}
		updater := map[string]interface{}{"status": consts.RegistryNormal}
		return s.registryDal.UpdateRegistry(ctx, imagesecModel.SearchRegistryParam{ID: reg.ID}, updater)
	case consts.StreamStatusRegNotOK:
		if reg.Status == consts.RegistryAbnormal {
			return nil
		}
		updater := map[string]interface{}{"status": consts.RegistryAbnormal}
		return s.registryDal.UpdateRegistry(ctx, imagesecModel.SearchRegistryParam{ID: reg.ID}, updater)
	case consts.StreamStatusFailed:
		return scani18.ConnectRPC()
	}
	return nil
}
