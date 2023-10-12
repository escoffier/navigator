package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type SyncTaskDispatcher interface {
	DispatchSyncTask(ctx context.Context) error
}

type RegDispatchSrv struct {
	registryDal        imagesecStore.RegistryDal
	syncTaskDal        imagesecStore.SyncTaskDal
	scanInsDal         imagesecStore.ScanInstanceDal
	streamClient       rpcstream.MessageStream
	SyncTaskUpdateChan chan SyncTaskUpdate
	Log                *scannerUtils.LogEvent
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

		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("dispatchTask"),
			scannerUtils.WithModule(consts.ModuleRegistryImage),
		),
	}
	s.UpdateSyncTask(context.Background())
	return s
}

func (s *RegDispatchSrv) DispatchSyncTask(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("DispatchSyncTask not in main cluster did not PublishSubtask")
		return nil
	}

	s.streamClient = imagesecStream.MustGetGrpcStream()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("dispatchFullSyncTask panic recover")
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("dispatchFullSyncTask panic recover")
			}
		}()

		s.dispatchFullSyncTask(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("dispatchIncrSyncTask panic recover")
			}
		}()

		s.dispatchIncrSyncTask(ctx)
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("CheckRegistryHealth panic recover")
			}
		}()

		s.CheckRegistryHealth(ctx)
	}()

	return nil
}

func (s *RegDispatchSrv) sendRegSyncTask(ctx context.Context, task imagesecModel.ImageSyncTask) (int64, error) {

	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, time.Minute)
	defer timeOutFunc()
	data, err := json.Marshal(task)
	if err != nil {
		return 0, err
	}

	defer timeOutFunc()

	req := &pb.ImageSecReq{
		ImageSecReqType: pb.ImageSecReqType_RegistryImageSync,
		ClusterKey:      task.ScanInsInfo.ClusterKey,
		Payload:         data,
	}

	req.RequestID = s.GenReqID(req)

	s.Log.Debug().Interface("reg", req).Msg("DispatchSyncTask sendMsg")

	rsp, err := s.streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		s.Log.Err(err).Interface("req", req).Msg("DispatchSyncTask")
		return 0, err
	}

	return int64(rsp.GetBizCode()), nil
}

func (s *RegDispatchSrv) UpdateSyncTask(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("recover panic")
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
					s.Log.Err(err).Int64("syncTaskID", up.SyncTaskID).
						Msg("SearchSyncTask")
					continue
				}
				if len(task) == 0 {
					s.Log.Err(err).Int64("syncTaskID", up.SyncTaskID).
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
				s.Log.Err(err).Int64("syncTaskID", up.SyncTaskID).Msg("UpdateSyncTask")
				continue
			}
			s.Log.Info().Int64("syncTaskID", up.SyncTaskID).Interface("updater", up).Msg("UpdateSyncTask")
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
			s.Log.Err(err).Msg("SearchSyncTask")
			continue
		}
		for _, ta := range tasks {
			up := SyncTaskUpdate{SyncTaskID: ta.ID, Start: true}
			go func() { s.SyncTaskUpdateChan <- up }()
			regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{ID: ta.RegistryID, Deleted: consts.FalseString})
			if err != nil {
				s.Log.Err(err).Msg("SearchRegistry")
				continue
			}
			if len(regs) == 0 {
				up.End = true
				up.Err = fmt.Errorf("not find reg info")

				go func() { s.SyncTaskUpdateChan <- up }()

				s.Log.Err(err).Int64("regID", ta.RegistryID).Msg("dispatchFullSyncTask not find registry")
				continue
			}

			scanInsInfo, err := s.scanInsDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{ScannerInstance: regs[0].ScannerInstance})
			if err != nil {
				s.Log.Err(err).Int64("regID", ta.RegistryID).Msg("dispatchFullSyncTask SearchScannerInfo")
				continue
			}

			if len(scanInsInfo) == 0 {
				up.End = true
				up.Err = fmt.Errorf("not find scanInsInfo")

				go func() { s.SyncTaskUpdateChan <- up }()

				s.Log.Err(err).Int64("regID", ta.RegistryID).Str("ScannerInstance", regs[0].ScannerInstance).
					Msg("dispatchFullSyncTask not find scan instance")
				continue
			}

			ta.Registry = regs[0]
			ta.ScanInsInfo = scanInsInfo[0]

			s.Log.Debug().Int64("regID", ta.RegistryID).Interface("syncTask", ta).
				Msg("dispatchFullSyncTask ready to send")
			syncStatus, err := s.sendRegSyncTask(ctx, ta)
			if err != nil {
				s.Log.Err(err).Int64("regID", ta.RegistryID).
					Msg("dispatchFullSyncTask sendRegSyncTask")
				continue
			}

			if syncStatus != consts.StreamStatusSyncProgress {
				s.Log.Info().Int64("regID", ta.RegistryID).Str("syncStatus", s.getSyncStatus(syncStatus)).
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
			s.Log.Info().Int64("regID", ta.RegistryID).Str("regName", ta.Registry.Name).Str("syncStatus", s.getSyncStatus(syncStatus)).
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
			s.Log.Err(err).Msg("SearchRegistry")
			continue
		}
		for i := range regs {
			reg := regs[i]
			scanInsInfo, err := s.scanInsDal.SearchScannerInfo(ctx, imagesecModel.ScanInstanceParam{ScannerInstance: reg.ScannerInstance})
			if err != nil {
				s.Log.Err(err).Int64("regID", reg.ID).Msg("dispatchIncrSyncTask SearchScannerInfo")
				continue
			}

			if len(scanInsInfo) == 0 {
				s.Log.Err(err).Int64("regID", reg.ID).Str("ScannerInstance", regs[0].ScannerInstance).
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
				s.Log.Err(err).Interface("reg", reg).Msg("sendRegSyncTask")
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
			s.Log.Err(err).Msg("SearchRegistry")
			continue
		}
		for i := range regs {
			if err := s.SendToScannerCheckHealth(ctx, regs[i]); err != nil {
				s.Log.Err(err).Msg("CheckRegistryHealth")
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

func (s *RegDispatchSrv) getSyncStatus(st int64) string {
	switch st {
	case consts.StreamStatusSyncProgress:
		return imagesecModel.TaskStatusInprogressStr
	case consts.StreamStatusSyncFailed:
		return imagesecModel.TaskStatusFailedStr
	case consts.StreamStatusSyncFinished:
		return imagesecModel.TaskStatusImageSyncFinishedStr
	default:
		s.Log.Error().Str("Stack", string(debug.Stack())).Str("module", "RegistryImage").Int64("rpcStatus", st).Msg("getSyncStatus")
		return "unknown"
	}
}

func (s *RegDispatchSrv) SendToScannerCheckHealth(ctx context.Context, reg imagesecModel.Registry) error {

	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 10*time.Second)
	defer timeOutFunc()
	data, err := json.Marshal(reg)
	if err != nil {
		s.Log.Err(err).Msg("SendToScannerCheckHealth")
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
	s.Log.Debug().Interface("reg", req).Msg("SendToScannerCheckHealth sendMsg")

	rsp, err := s.streamClient.ScannerPushImageSecMsg(timeOutCxt, req)
	if err != nil {
		s.Log.Err(err).Interface("req", req).Msg("SendToScannerCheckHealth")
		return err
	}

	switch rsp.GetBizCode() {
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

func (s *RegDispatchSrv) GenReqID(req *pb.ImageSecReq) string {
	return fmt.Sprintf("%s-%s", req.ImageSecReqType.String(), uuid.New().String())
}
