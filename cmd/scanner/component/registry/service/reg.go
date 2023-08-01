package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegistryService interface {
	CreateRegistry(ctx context.Context, reg *imagesecModel.Registry) error
	UpdateRegistry(ctx context.Context, id int64, reg imagesecModel.Registry) error
	DeleteRegistry(ctx context.Context, id int64) error
	SearchRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam) ([]imagesecModel.Registry, int64, error)
	GetRegistryType(ctx context.Context) ([]imagesecModel.LabelValue, error)

	CreateSyncTask(ctx context.Context, reg imagesecModel.CreateSyncTaskParam) error // 添加全量同布的任务
	GetSyncStatus(ctx context.Context) ([]*imagesecModel.RegSyncStatus, error)
}

var sinRegistrySrv *RegistrySrv

type RegistrySrv struct {
	registryDal   imagesecStore.RegistryDal
	syncTaskDal   imagesecStore.SyncTaskDal
	scanInsDal    imagesecStore.ScanInstanceDal
	policyDal     imagesecStore.DetectPolicyDal
	scanConfigDal imagesecStore.ScanImageConfigDal
}

func NewRegistrySrv(
	registryDal imagesecStore.RegistryDal,
	syncTaskDal imagesecStore.SyncTaskDal,
	scanInsDal imagesecStore.ScanInstanceDal,
	policyDal imagesecStore.DetectPolicyDal,
	scanConfigDal imagesecStore.ScanImageConfigDal,
) *RegistrySrv {
	if sinRegistrySrv != nil {
		return sinRegistrySrv
	}
	s := &RegistrySrv{
		registryDal:   registryDal,
		syncTaskDal:   syncTaskDal,
		scanInsDal:    scanInsDal,
		policyDal:     policyDal,
		scanConfigDal: scanConfigDal,
	}
	sinRegistrySrv = s
	return sinRegistrySrv
}

func (s *RegistrySrv) GetRegistryType(ctx context.Context) ([]imagesecModel.LabelValue, error) {
	ans := make([]imagesecModel.LabelValue, 0)
	regTypes := imagesecModel.GetRegType()
	for k := range regTypes {
		ans = append(ans, regTypes[k])
	}
	return ans, nil
}

func (s *RegistrySrv) SearchRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam) ([]imagesecModel.Registry, int64, error) {

	param.Compatible()

	registries, cnt, err := s.registryDal.SearchRegistry(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("SearchRegistry")
		return nil, 0, scani18.SearchReg(err)
	}
	return registries, cnt, nil
}

func (s *RegistrySrv) DeleteRegistry(ctx context.Context, id int64) error {
	if id <= 0 {
		return scani18.NotGetRegID()
	}
	update := make(map[string]interface{})
	update["deleted_at"] = time.Now().UnixMilli()

	err := s.registryDal.UpdateRegistry(ctx, imagesecModel.SearchRegistryParam{ID: id}, update)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("DeleteRegistry")

		return scani18.DeleteReg(err)
	}
	// 不用删除镜像，后台会删除
	go func() { _ = s.updatePolicyAfterDeleteReg(ctx, id) }()
	go func() { _ = s.updateScanConfigAfterDeleteReg(ctx, id) }()

	return nil
}

func (s *RegistrySrv) CreateRegistry(ctx context.Context, reg *imagesecModel.Registry) error {
	if err := reg.Validate(consts.ValidateCreate); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	if err := validateRegistryType(reg.RegType); err != nil {
		return scani18.RegTypeErr()
	}

	// 验证仓库的正确性
	if err := s.CheckHealth(ctx, reg); err != nil {
		return scani18.ValidateReg(err)
	}
	reg.Status = consts.RegistryNormal

	err := s.registryDal.CreateRegistry(ctx, reg)
	if err != nil {
		return scani18.CreateRegistry(err)
	}

	// 新增加的仓库需要自动同步,
	go func(regID int64) {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Error().Msg("CreateRegistry recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 1)
		defer ticker.Stop()
		<-ticker.C

		syncTask := &imagesecModel.ImageSyncTask{RegistryID: regID, SyncType: imagesecModel.CycleFullSync.String()}
		if err := s.syncTaskDal.CreateSyncTask(ctx, syncTask); err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Int64("regID", regID).Msg("createRegistry CreateSyncTask")
		}
	}(reg.ID)

	return nil
}

func (s *RegistrySrv) CheckHealth(ctx context.Context, reg *imagesecModel.Registry) error {
	if reg.RegType == imagesecModel.HarborVersion {
		reg.RegType = imagesecModel.HarborV2Version
		if err := s.SendToScannerCheckHealth(ctx, *reg); err == nil {
			return nil
		}
		reg.RegType = imagesecModel.HarborV1Version
		if err := s.SendToScannerCheckHealth(ctx, *reg); err == nil {
			return nil
		}
		return fmt.Errorf("can not verify registry info")
	}

	if err := s.SendToScannerCheckHealth(ctx, *reg); err != nil {
		return err
	}
	return nil
}

func (s *RegistrySrv) UpdateRegistry(ctx context.Context, id int64, reg imagesecModel.Registry) error {
	if id <= 0 {
		return scani18.NotGetID()
	}
	if err := reg.Check(); err != nil {
		return err
	}
	prePass := reg.PasswordString

	registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{ID: id, Deleted: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("UpdateRegistry.SearchRegistry")
		return scani18.UpdateRegistry(err)
	}
	if len(registries) == 0 {
		return scani18.UpdateRegistry(fmt.Errorf("not find the registry:%d", id))
	}

	reg.RegType = registries[0].RegType
	reg.Url = registries[0].Url

	if prePass == "" {
		reg.PasswordString = registries[0].PasswordString
	}
	if err := reg.Validate(consts.ValidateUpdate); err != nil {
		return scani18.UpdateRegistry(err)
	}
	if err := s.CheckHealth(ctx, &reg); err != nil {
		return scani18.ValidateReg(err)
	}

	if prePass != "" {
		encryPass, err := util.DesEncrypt([]byte(prePass), []byte(consts.EncryptPasswordKey))
		if err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Msg("DesEncrypt")
			return scani18.UpdateRegistry(err)
		}
		reg.Password = encryPass
	}
	reg.PasswordString = prePass

	updater := reg.ToUpdater()

	err = s.registryDal.UpdateRegistry(ctx, imagesecModel.SearchRegistryParam{ID: id}, updater)
	if err != nil {
		return scani18.UpdateRegistry(err)
	}
	return nil
}

func (s *RegistrySrv) CreateSyncTask(ctx context.Context, param imagesecModel.CreateSyncTaskParam) error {
	regs, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{ID: param.RegID,
		ScannerInstance: param.ScannerInstance, Deleted: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Interface("param", param).Msg("SearchRegistry")
		return err
	}
	for i := range regs {
		syncTask := &imagesecModel.ImageSyncTask{RegistryID: regs[i].ID, SyncType: param.SyncType.String()}
		err = s.syncTaskDal.CreateSyncTask(ctx, syncTask)
		if err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				logging.Get().Info().Str("module", "RegistryImage").Interface("syncTask", syncTask).Msg("has one sync task is running")
				continue
			}
			logging.Get().Err(err).Str("module", "RegistryImage").Interface("syncTask", syncTask).Msg("CreateSyncTask")
			return err
		}
		logging.Get().Info().Str("module", "RegistryImage").Interface("syncTask", syncTask).Msg("CreateSyncTask")
	}
	return nil
}

func (s *RegistrySrv) GetSyncStatus(ctx context.Context) ([]*imagesecModel.RegSyncStatus, error) {
	registries, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("GetSyncStatus")
		return nil, err
	}
	exit := make(map[int64]*imagesecModel.RegSyncStatus)

	for i := range registries {
		exit[registries[i].ID] = &imagesecModel.RegSyncStatus{RegID: registries[i].ID}
	}

	syncTask, err := s.syncTaskDal.SearchSyncTask(ctx, imagesecModel.SearchSyncTaskParam{Finished: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("GetSyncStatus SearchSyncTask")
		return nil, err
	}
	for i := range syncTask {
		_, ok := exit[syncTask[i].RegistryID]
		if !ok {
			continue
		}
		exit[syncTask[i].RegistryID].Status = true
	}
	ans := make([]*imagesecModel.RegSyncStatus, 0)
	for k := range exit {
		ans = append(ans, exit[k])
	}
	return ans, nil
}

func (s *RegistrySrv) ValidateRegistry(ctx context.Context, reg imagesecModel.Registry) error {
	if reg.ScannerInstance != global.ScannerInstance {
		err := fmt.Errorf("registry not in correct cluster")
		logging.Get().Err(err).Str("module", "RegistryImage").Str("ScannerInstance", reg.ScannerInstance).Str("regName", reg.Name).
			Msg("the registry not in this cluster")
		return err
	}
	conf := warehouse.RegToRegistryConf(reg)
	driver, err := warehouse.Open(conf)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("ScannerInstance", reg.ScannerInstance).Str("regName", reg.Name).
			Msg("can not get registry driver")
		return err
	}
	if err := driver.Ping(); err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("ScannerInstance", reg.ScannerInstance).Str("regName", reg.Name).
			Msg("can not ping registry")
		return err
	}
	return nil
}

func (s *RegistrySrv) SendToScannerCheckHealth(ctx context.Context, reg imagesecModel.Registry) error {

	streamClient := imagesecStream.MustGetGrpcStream()

	timeOutCxt, timeOutFunc := context.WithTimeout(ctx, 60*time.Second)
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
		return nil
	case consts.StreamStatusRegNotOK:
		return scani18.ValidateReg(nil)
	case consts.StreamStatusFailed:
		return scani18.ConnectRPC()
	}
	return nil
}

func (s *RegistrySrv) updatePolicyAfterDeleteReg(ctx context.Context, regID int64) error {
	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{})
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("SearchDetectPolicy")
		return err
	}
	for i := range policy {
		po := policy[i]
		if po.Scope.AllReg {
			continue
		}
		if util.ExistInInt64Slice(po.Scope.RegIds, regID) {
			regIds := make([]int64, 0)
			for _, reg := range po.Scope.RegIds {
				if reg != regID {
					regIds = append(regIds, reg)
				}
			}
			po.Scope.RegIds = regIds
			po.Serialize()
			param := imagesecModel.UpdateSecurityPolicyParam{
				ID: po.ID, Updater: po.ToUpdater()}
			if err := s.policyDal.UpdateDetectPolicy(ctx, param); err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("UpdateDetectPolicy")
				return err
			}
		}
	}
	return nil
}

func (s *RegistrySrv) updateScanConfigAfterDeleteReg(ctx context.Context, regID int64) error {
	policy, err := s.scanConfigDal.SearchImageConfig(ctx)
	if err != nil {
		logging.Get().Err(err).Str("module", "imageMeta").Msg("SearchImageConfig")
		return err
	}
	for i := range policy {
		po := policy[i].ImageScanConfig
		if po.ScanCycle.AllReg {
			continue
		}
		if util.ExistInInt64Slice(po.ScanCycle.RegIds, regID) {
			regIds := make([]int64, 0)
			for _, reg := range po.ScanCycle.RegIds {
				if reg != regID {
					regIds = append(regIds, reg)
				}
			}
			po.ScanCycle.RegIds = regIds
			data := policy[i]
			data.ImageScanConfig = po

			if err := s.scanConfigDal.UpdateScanImageConfig(ctx, po.ID, data); err != nil {
				logging.Get().Err(err).Str("module", "imageMeta").Msg("UpdateScanImageConfig")
				return err
			}
		}
	}
	return nil
}

func validateRegistryType(regType string) error {
	regTypes := append([]string{imagesecModel.HarborVersion}, warehouse.DriverTypes...)
	if !util.ExistInStringSlice(regTypes, regType) {
		return errors.New("registry type is illegal")
	}
	return nil
}
