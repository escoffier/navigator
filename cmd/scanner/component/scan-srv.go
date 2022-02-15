package component

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/rogpeppe/go-internal/cache"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/compress"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SearchImageWithScanParam struct {
	SearchWord        string   `json:"search_word"`
	FromType          int64    `json:"from_type"`
	Kind              string   `json:"kind"`
	Online            string   `json:"online"`
	ImageType         string   `json:"image_type"`
	ImageID           int64    `json:"image_id"`
	ImageIds          []int64  `json:"image_ids"`
	Library           string   `json:"library"`
	ScanStatus        []int    `json:"scan_status"`
	Trusted           string   `json:"trusted"`
	HasFixedVulu      string   `json:"has_fixed_vulu"`
	IsReinforce       string   `json:"is_reinforce"`
	NodeHostname      string   `json:"node_hostname"`
	SpecialImageType  string   `json:"special_image_type"`
	JustReturnImage   bool     `json:"just_return_image"`
	UUIDs             []uint32 `json:"uuids"`
	NotDeleteRegistry string   // 不返回已经删除的仓库的镜像
}

type SearchImageParam struct {
	ImageIds     []int64
	ImageType    string
	ImageID      int64
	FullRepoName string
	Tags         string
	RegistryID   int64
	Search       string
	FromType     int64
	UUIDs        []uint32
}

type ScannerSrv interface {
	CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error
	SearchImageWithScan(ctx context.Context, param SearchImageWithScanParam, filter *model.Filter) ([]*model.ImageResponse, int64, error)
	SearchImages(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)

	UpdateImage(ctx context.Context, where SearchImageParam, update map[string]interface{}) error
	GetImageDetail(ctx context.Context, imgID int64) (*model.ImageList, error)
	GetImageOverView(ctx context.Context, fromType int64) (*model.OverView, error)
	GetScanOneStatus(ctx context.Context, imgID int64, fromURL string) (*model.ImageResponse, error)
	TickScanOne(ctx context.Context, imgID int64, info task.UpdateTaskInfo) error
	ScanOneForCICD(ctx context.Context, req *model.ScanOneForCICDRequest) (*model.ScanOneCICDResultRequest, error)
	ScanOneForCICDResult(ctx context.Context, req *model.ScanOneCICDResultRequest) (*model.ScanOneForCICDResponse, error)
	ScanAllNow(ctx context.Context, info task.UpdateTaskInfo, search SearchImageWithScanParam) error
	GetScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus
	GetVulnOverView(ctx context.Context) (model.VulnOverview, error)
	ListImgLayers(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ReportImgBackInfo, error)
	ImgLayerInfo(ctx context.Context, imageID int64, layerDigest string, filter *model.Filter) (*model.ScanLayerResponse, error)
	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)
	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail

	TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMonitorImage) bool

	DeleteCICDImage(ctx context.Context)
	ListBaseImageOfApp(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error)
	ListAppImageOfBase(ctx context.Context, baseImageID int64, filter *model.Filter) ([]model.ImageList, int64, error)

	ScanReportCreate(ctx context.Context, data *scanreport.TensorScanReportTasks) (uint, error)
	ScanReportUpdate(ctx context.Context, data *scanreport.TensorScanReportTasks) error
	ScanReportList(ctx context.Context, keyword string, limit, offset int, _type []uint8) ([]scanreport.TensorScanReportTasks, int64, error)
	ScanReportDetail(ctx context.Context, id uint) (*scanreport.TensorScanReportTasks, error)
	ScanReportDelete(ctx context.Context, id uint) error
	ScanReportFiles(ctx context.Context, id uint, limit, offset int) ([]scanreport.TensorScanReportSubTasks, int64, error)
	ScanReportDownload(ctx context.Context, taskID, subTaskID uint) (*scanreport.ScanReportResult, error)
	ScanReportGenerate(ctx context.Context, taskID uint) (uint, error)

	GetScanTaskList(ctx context.Context, limit, offset int64) ([]*model.Task, int64, error)
	GetScanSubTaskList(ctx context.Context, taskID, limit, offset int64) ([]model.SubTask, int64, error)
	UpdateScanTaskStatus(ctx context.Context, taskID int64, status uint8) error

	GetStrategyForEnv(ctx context.Context, envName string) ([]model.ScanStrategy, error)
	SetEnvToStrategy(ctx context.Context, envName string, policyID []int64) error
}

type ConScannerSrv struct {
	dbdal           store.ScannerDalInterface
	taskdal         store.ScanTaskInterface
	trustedImageDal store.TrustedImageInterface
	registryDal     store.RegistryDalInterface
	scanConfigDal   store.ScanConfigDalInterface
	redclair        *RedClairService
	virusScan       *VirusScan
	scannerDB       *store.ScannerDB
	globalCache     *cache.Cache
	scannerList     *ScannerList
}

func (s *ConScannerSrv) SearchImages(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error) {
	// 先查仓库
	registryIds := make([]int64, 0)
	if param.RegistryID > 0 {
		registryIds = append(registryIds, param.RegistryID)
	}

	regMap := make(map[int64]*model.Registry)
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImages.SearchRegistry")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	for i := range registries {
		regMap[registries[i].ID] = &registries[i]
	}

	images, cnt, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{
		Ids:          param.ImageIds,
		Tag:          param.Tags,
		FullRepoName: param.FullRepoName,
		Search:       param.Search,
		FromType:     param.FromType,
		RegistryIds:  registryIds,
		UUIDs:        param.UUIDs,
	}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchImages.SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	for i := range images {
		images[i].Registry = regMap[images[i].RegistryID]
	}

	return images, cnt, nil
}

func NewConScannerSrv(dbdal store.ScannerDalInterface, registryDal store.RegistryDalInterface, redclair *RedClairService, virusScan *VirusScan, scdb *store.ScannerDB, globalCache *cache.Cache, scannerList *ScannerList, taskdal store.ScanTaskInterface, trustedImageDal store.TrustedImageInterface, scanConfigDal store.ScanConfigDalInterface) *ConScannerSrv {
	return &ConScannerSrv{
		dbdal:           dbdal,
		registryDal:     registryDal,
		redclair:        redclair,
		virusScan:       virusScan,
		scannerDB:       scdb,
		globalCache:     globalCache,
		scannerList:     scannerList,
		taskdal:         taskdal,
		trustedImageDal: trustedImageDal,
		scanConfigDal:   scanConfigDal,
	}
}

func (s *ConScannerSrv) SetEnvToStrategy(ctx context.Context, envName string, policyID []int64) error {
	return s.dbdal.SetSingleStrategy(ctx, envName, policyID)
}

func (s *ConScannerSrv) GetStrategyForEnv(ctx context.Context, envName string) ([]model.ScanStrategy, error) {
	scanStrategies, err := s.dbdal.GetAllScanStrategyEnv(ctx)
	if err != nil {
		return nil, err
	}
	var res []model.ScanStrategy
	for k := range scanStrategies {
		var tmpEnv []string
		if len(scanStrategies[k].EnvsJson) != 0 {
			err := json.Unmarshal([]byte(scanStrategies[k].EnvsJson), &tmpEnv)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msgf("GetStrategyForEnv Unmarshal error")
				continue
			}
		}
		flag := 0
		for i := range tmpEnv {
			if tmpEnv[i] == envName {
				flag = 1
				break
			}
		}
		if flag == 0 {
			res = append(res, scanStrategies[k])
		}
	}
	return res, nil
}

func (s *ConScannerSrv) ListBaseImageOfApp(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error) {
	images, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imageID}, ImageType: consts.AppImageTypeString}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
	}
	if len(images) == 0 {
		return nil, 0, response.NewHttpError(http.StatusExpectationFailed, errors.New("not find the app image"))
	}

	baseImages, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{ImageType: consts.BaseImageTypeString}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListBaseImageOfApp")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
	}
	baseImageMap := make(map[int64]model.ImageList)
	for i := range baseImages {
		baseImageMap[baseImages[i].ID] = baseImages[i]
	}

	baseLayerMap := make(map[int64]string)
	for i := range baseImages {
		lay := getLayerString(baseImages[i])
		if len(lay) > 0 {
			baseLayerMap[baseImages[i].ID] = lay
		}
	}
	appLayer := getLayerString(images[0])
	ans := make([]model.ImageList, 0)
	for i, l := range baseLayerMap {
		if strings.HasPrefix(appLayer, l) {
			ans = append(ans, baseImageMap[i])
		}
	}
	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("SearchImageWithScan.SearchRegistry:error:%s", err.Error()))
		return nil, 0, response.NewHttpError(http.StatusGone, err)
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}
	for i := range ans {
		if re, ok := regMap[ans[i].RegistryID]; ok {
			ans[i].Registry = &re
		}
	}
	// 应付前端分页
	if filter != nil && len(ans) > 0 {
		start := int(filter.Offset)
		end := int(filter.Offset + filter.Limit)

		if len(ans) <= start {
			return make([]model.ImageList, 0), int64(len(ans)), nil
		}
		if end > len(ans) {
			end = len(ans)
		}
		return ans[start:end], int64(len(ans)), nil
	}
	return ans, int64(len(ans)), nil
}

func (s *ConScannerSrv) ListAppImageOfBase(ctx context.Context, baseImageID int64, filter *model.Filter) ([]model.ImageList, int64, error) {
	baseImages, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{baseImageID}, ImageType: consts.BaseImageTypeString, Fields: []string{"id", "layers"}}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListAppImageOfBase")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取应用镜像出错"))
	}
	if len(baseImages) == 0 {
		return nil, 0, response.NewHttpError(http.StatusExpectationFailed, errors.New("not find the base image"))
	}
	baseLayer := getLayerString(baseImages[0])
	images, cnt, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{ImageType: consts.AppImageTypeString, LayersPrefix: baseLayer,
		Fields: []string{"id", "layers", "full_repo_name", "image_type", "library", "tags", "digest"}}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListAppImageOfBase")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取应用镜像出错"))
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}
	for i := range images {
		if re, ok := regMap[images[i].RegistryID]; ok {
			images[i].Registry = &re
		}
	}

	return images, cnt, nil
}

func (s *ConScannerSrv) UpdateImage(ctx context.Context, param SearchImageParam, update map[string]interface{}) error {

	where := make([]string, 0)
	if param.ImageType == consts.AppImageTypeString {
		where = append(where, fmt.Sprintf("image_type = %d", consts.AppImageType))
	} else if param.ImageType == consts.BaseImageTypeString {
		where = append(where, fmt.Sprintf("image_type = %d", consts.BaseImageType))
	}

	if param.ImageID > 0 {
		where = append(where, fmt.Sprintf("id = %d", param.ImageID))
	}
	if len(param.ImageIds) > 0 {
		ids := make([]string, 0)
		for i := range param.ImageIds {
			ids = append(ids, strconv.Itoa(int(param.ImageIds[i])))
		}
		where = append(where, fmt.Sprintf("id IN ( %s )", strings.Join(ids, ",")))
	}
	if len(where) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, errors.New("no where condition for update"))
	}
	ims, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Where: strings.Join(where, " AND ")}, nil)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, errors.New("查询要更新镜像出错"))
	}
	safeNodeImage := make([]string, 0)
	for i := range ims {
		if ims[i].FromType == model.ImageFromSafeNode {
			safeNodeImage = append(safeNodeImage, fmt.Sprintf("%s/%s:%s", ims[i].Library, ims[i].FullRepoName, ims[i].Tags))
		}
	}
	if len(safeNodeImage) > 0 {
		logging.GetLogger().Error().Err(fmt.Errorf("k8s node image not editable")).Msg(strings.Join(safeNodeImage, ","))
		return response.NewHttpError(http.StatusInternalServerError, errors.New("被更新镜像包括节点镜像，节点镜像不可以编辑"))
	}

	if len(update) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, errors.New("no update data for update"))
	}

	if err := s.dbdal.UpdateImage(ctx, strings.Join(where, " AND "), update); err != nil {
		logging.GetLogger().Error().Err(err).Msg("updating image error")
		return response.NewHttpError(http.StatusInternalServerError, errors.New("更新镜像出错"))
	}
	return nil
}

func (s *ConScannerSrv) K8sDeployDetect(ctx context.Context, containerInfo []model.RejectOnlineMonitorImage) bool {
	resConfig, err := s.dbdal.GetGlobalPolicyConfig(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("K8sDeployDetect search global policy")
		return false
	}
	if len(resConfig) == 0 {
		logging.GetLogger().Info().Msg("K8sDeployDetect not find global policy")
		return true
	}
	if !resConfig[0].K8sEnable {
		logging.GetLogger().Info().Msg("K8sDeployDetect k8s deploy is not enable")
		return true
	}

	var flag bool = true
	msgType := consts.AlertKindK8s
	for k := range containerInfo {
		tmpImage, err := s.GetImageLibraryNameTag(containerInfo[k].Image)
		if err != nil {
			logging.GetLogger().Info().Msgf("K8sDeployDetect parsing image:%s error %s", containerInfo[k].Image, err.Error())
			continue
		}
		tmpImage.Digest = containerInfo[k].Digest

		if tmpImage.Library == "" {
			flag = false
			logging.GetLogger().Info().Msg("K8sDeployDetect Library is empty")
			// 存储阻断记录
			s.CreateSafeReject(ctx, *tmpImage, msgType, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary], containerInfo[k])
			continue
		}

		imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{
			Libraries:    []string{tmpImage.Library, "https://" + tmpImage.Library, "http://" + tmpImage.Library},
			Tag:          tmpImage.Tags,
			FullRepoName: tmpImage.FullRepoName,
		}, nil)

		if err != nil {
			logging.GetLogger().Err(err).Msg("search image error")
			return false
		}

		if len(imgs) == 0 {
			if resConfig[0].Mode == model.RejectPolicySafeModel {
				if !strings.Contains(tmpImage.Library, "https://") && !strings.Contains(tmpImage.Library, "http://") && !strings.Contains(tmpImage.Library, "docker.io") {
					tmpImage.Library = "https://" + tmpImage.Library
				}
				logging.GetLogger().Info().Msgf("K8sDeployDetect not find the image and the mode is safe mode, digest: %s", containerInfo[k].Digest)
				s.CreateSafeReject(ctx, *tmpImage, msgType, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary], containerInfo[k])
				flag = false
			} else {
				logging.GetLogger().Info().Msgf("K8sDeployDetect not find the image and the mode not is safe mode, digest:%s", containerInfo[k].Digest)
			}
			continue
		}
		img := imgs[0]
		safe, records, msgs, _ := s.DetectImageForK8s(ctx, &img)
		if len(msgs) > 0 {
			notify := model.NotifyContext{
				ServiceID: fmt.Sprintf("%s/%s:%s(image)", img.Library, img.FullRepoName, img.Tags),
				CustomKV:  msgs,
			}

			notify.PodName = containerInfo[k].NotifyContext.PodName
			notify.PodUID = containerInfo[k].NotifyContext.PodUID
			notify.Cluster = containerInfo[k].NotifyContext.Cluster
			notify.Namespace = containerInfo[k].NotifyContext.Namespace
			notify.CustomKV = append(notify.CustomKV, containerInfo[k].NotifyContext.CustomKV...)
			notify.CustomKV = append(notify.CustomKV, model.KVHashs{KVHash: model.KVHash{
				EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
				ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
			}})

			msg := model.NewReqBody(model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity), notify, generateUUID(img, msgType, consts.EventIntervalUUID))
			if err := sendMsgToEventCenter(ctx, msg); err != nil {
				logging.GetLogger().Error().Err(err).Msgf("TickOnlineScan sendMsgToEventCenter sending message to event center, msg Type: %s error:%s", msgType, err.Error())
			}
		}
		// 存储阻断记录
		if !safe && len(records) > 0 {
			res := mergeRejectRecord(img, records)
			if _, err := s.dbdal.CreateRejectRecord(ctx, res); err != nil {
				logging.GetLogger().Error().Err(err).Msgf("TickOnlineScan CreateRejectRecord create record error %s", err.Error())
			}
		}

		if !safe {
			flag = false
		}
	}
	return flag
}

func (s *ConScannerSrv) TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMonitorImage) bool {

	if strings.Contains(containerInfo[0].FromType, "k8s") {
		return s.K8sDeployDetect(ctx, containerInfo)
	}
	if containerInfo[0].FromType == model.UsePatternForOnline {
		s.K8sOnlineMonitor(ctx, containerInfo)
		return true
	}
	return true
}

// K8sOnlineMonitor  k8s在线监控时的镜像检测
func (s *ConScannerSrv) K8sOnlineMonitor(ctx context.Context, containerInfo []model.RejectOnlineMonitorImage) {
	if len(containerInfo) == 0 {
		logging.GetLogger().Info().Msg("K8sOnlineMonitor containerInfo is empty")
		return
	}

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor get global  policy")
		return
	}
	if len(globalReg) == 0 {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor not find  global policy")
		return
	}

	if !globalReg[0].OnlineMonitor {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor global policy is not enable ")
		return
	}

	for k := range containerInfo {
		tmpImageList, err := s.GetImageLibraryNameTag(containerInfo[k].Image)
		if err != nil {
			logging.GetLogger().Info().Msgf("K8sOnlineMonitor parsing image:%s error %s", containerInfo[k].Image, err.Error())
			continue
		}
		tmpImageList.Digest = containerInfo[k].Digest

		if tmpImageList.Library == "" {
			logging.GetLogger().Info().Msg("K8sOnlineMonitor Library is empty: image")
			// 存储阻断记录
			s.CreateSafeReject(ctx, *tmpImageList, consts.AlertKindOnline, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary], containerInfo[k])
			continue
		}

		// 进行检测
		_, _, msgs, _ := s.DetectImageForK8sOnlineMonitor(ctx, tmpImageList)
		// 发送消息
		if len(msgs) > 0 {
			notify := model.NotifyContext{
				CustomKV: msgs,
			}

			notify.PodName = containerInfo[k].NotifyContext.PodName
			notify.PodUID = containerInfo[k].NotifyContext.PodUID
			notify.Cluster = containerInfo[k].NotifyContext.Cluster
			notify.Namespace = containerInfo[k].NotifyContext.Namespace
			notify.CustomKV = append(notify.CustomKV, containerInfo[k].NotifyContext.CustomKV...)
			notify.CustomKV = append(notify.CustomKV, model.KVHashs{KVHash: model.KVHash{
				EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", tmpImageList.Library, tmpImageList.FullRepoName, tmpImageList.Tags)},
				ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", tmpImageList.Library, tmpImageList.FullRepoName, tmpImageList.Tags)},
			}})

			msg := model.NewReqBody(model.NewEventCenterRule(consts.AlertKindOnline, consts.AlertModuleContainerSecurity, consts.ImageSecurity),
				notify, generateUUID(*tmpImageList, consts.AlertKindOnline, consts.EventIntervalUUID))
			if err := sendMsgToEventCenter(ctx, msg); err != nil {
				logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor sendMsgToEventCenter sending message to event center, msg Type: %s error:%s", consts.AlertKindOnline, err.Error())
			}
		}
	}
	// return
}

func (s *ConScannerSrv) CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error {
	regi, err := s.getRegistry(ctx, "", model.RegistryUseTypeCICDBuff)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("can not connect harborV2")
		return response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not connect harborV2 error is %s", err.Error())))
	}
	if err := regi.CheckProject(projectName); err != nil {
		if err := regi.CreateProject(projectName, true); err != nil {
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(fmt.Sprintf("can not create project error is %s", err.Error())))
		}
	}
	return nil
}

func (s *ConScannerSrv) ScanOneForCICDResult(ctx context.Context, req *model.ScanOneCICDResultRequest) (*model.ScanOneForCICDResponse, error) {

	img, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{req.ImageID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult search image detail error :%s", err.Error())
		return nil, err
	}
	if len(img) == 0 {
		logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult has not search the image :%s/%d", req.Library, req.ImageID)
		return nil, err
	}

	scanImage, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{req.ImageID}, NoStatus: model.ScanStatusInProgress}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult search scan_image error:%s", err.Error())
		return nil, err
	}
	if len(scanImage) == 0 {
		logging.GetLogger().Info().Msgf("CICD ScanOneForCICDResult scanning")
		return nil, fmt.Errorf("CICD 镜像正在扫描中")
	}
	imgDetail, _ := s.GetImageDetail(ctx, req.ImageID)
	imgDetail.ScanImage = &scanImage[0]

	safe, records, msgs, err := s.DetectImageForCICD(ctx, &img[0])
	// 向事件中心发送消息
	if len(msgs) > 0 {
		logging.GetLogger().Info().Msgf("CICD ScanOneForCICDResult detect complete,send message to the event center")

		msgs = append(msgs, model.KVHashs{KVHash: model.KVHash{
			EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", img[0].Library, img[0].FullRepoName, img[0].Tags)},
			ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", img[0].Library, img[0].FullRepoName, img[0].Tags)},
		}})

		msg := model.NewReqBody(
			model.NewEventCenterRule(consts.AlertKindCICD, consts.AlertModuleContainerSecurity, consts.ImageSecurity),
			model.NotifyContext{
				ServiceID: fmt.Sprintf("%s/%s:%s(image)", img[0].Library, img[0].FullRepoName, img[0].Tags),
				CustomKV:  msgs},
			generateUUID(img[0], consts.AlertKindCICD, consts.EventIntervalUUID),
		)

		if err := sendMsgToEventCenter(ctx, msg); err != nil {
			logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult sending message to event center error:%s", err.Error())
		}
	}
	// 存储阻断记录
	logging.GetLogger().Info().Msgf("CICD ScanOneForCICDResult detect complete, image: %s%s:%s safe: %t, length of records: %d, length of msg: %d", req.Library, img[0].FullRepoName, img[0].Tags, safe, len(records), len(msgs))
	if !safe && len(records) > 0 {
		logging.GetLogger().Info().Msgf("CICD ScanOneForCICDResult detect completed ,blocked, insert reject record")
		res := mergeRejectRecord(img[0], records)
		res.Library = req.Library
		if _, err := s.dbdal.CreateRejectRecord(ctx, res); err != nil {
			logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult insert reject record error %s", err.Error())
		}
	}

	return &model.ScanOneForCICDResponse{
		IsScan:      true,
		Safe:        safe,
		ImageDetail: imgDetail,
		Msg:         msgs,
	}, err
}

func (s *ConScannerSrv) ScanOneForCICD(ctx context.Context, req *model.ScanOneForCICDRequest) (*model.ScanOneCICDResultRequest, error) {
	// cicd集成时，首先会把公司镜像推送到我们自己搭建的仓库中(默认docker-registry),然后拉取镜像进行扫描，
	// 通过library查registryID
	if req == nil {
		return nil, fmt.Errorf("CICD no ScanOneForCICD req")
	}
	hasHTTP := strings.Contains(req.Image, "http://")
	hasHTTPS := strings.Contains(req.Image, "https://")

	req.Image = strings.Replace(strings.Replace(req.Image, "http://", "", 1), "https://", "", 1)
	lib, repo, tag := getLibRepoTag(req.Image)
	if hasHTTP {
		lib = "http://" + lib
	} else if hasHTTPS || (!hasHTTPS && !hasHTTP) {
		lib = "https://" + lib
	}
	logging.GetLogger().Info().Msgf("CICD parsed the image: %s%s:%s", lib, repo, tag)
	regs, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{UseType: model.RegistryUseTypeCICDBuff}, nil)

	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD find the BuffRegistry library error")
		return nil, response.NewHttpError(http.StatusPreconditionFailed, fmt.Errorf("can not find the RegistryUseTypeBuff library"))
	}
	if len(regs) == 0 {
		logging.GetLogger().Err(err).Msgf("CICD can not find the BuffRegistry library")
		return nil, response.NewHttpError(http.StatusPreconditionFailed, fmt.Errorf("can not find the RegistryUseTypeBuff library"))
	}
	logging.GetLogger().Info().Msgf("CICD BuffRegistry registry is :%s", regs[0].Url)
	regi, err := s.getRegistry(ctx, "", model.RegistryUseTypeCICDBuff)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD  connection BuffRegistry error :%s", regs[0].Url)
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("CICD can not connect docker-registry error is %s", err.Error())))
	}
	projectName, repoName := "", repo
	split := strings.Split(repo, "/")
	if len(split) >= 2 {
		projectName = split[0]
		repoName = strings.Join(split[1:], "/")
	}
	logging.GetLogger().Info().Msgf(fmt.Sprintf("CICD ScanOneForCICD library:%s,projectName:%s,repoName:%s,tag:%s", regs[0].Url, projectName, repoName, tag))
	image, err := regi.GetImage(projectName, repoName, tag)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("CICD pull the image from BuffRegistry erorr，library:%s,projectName:%s,repoName:%s,tag:%s", regs[0].Url, projectName, repoName, tag))
		return nil, err
	}
	logging.GetLogger().Info().Msgf("CICD pull image from BuffRegistry: %s%s:%s", regs[0].Url, image.Repository, image.Tag)
	img := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        lib,
		RegistryID:     regs[0].ID,
		FirstPushTime:  time.Now(),
		LastPushTime:   time.Now(),
		LastPullTime:   time.Now(),
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJSON:     []byte(image.ConfigJSON),
		CompleteTime:   image.Created.UTC().String(),
		FromType:       model.ImageFromTypeCICD,
		ImageType:      consts.AppImageType,
	}

	var config model.ConfigFile
	err = json.Unmarshal(img.ConfigJSON, &config)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("unmarshal config json error")
	} else {
		if config.Config.User == "" || strings.Contains(config.Config.User, "root") {
			img.PrivilegedBoot = consts.PrivilegedBootImage
		}
		for _, v := range config.History {
			if strings.Contains(v.CreatedBy, "/tmp/file-checker") {
				img.IsReinforce = consts.IsReinforceImage
				break
			}
		}
	}
	img.Layers = getLayerString(img)
	// 同步镜像到数据库
	createdImage, err := s.dbdal.CreateImage(ctx, &img)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD insert image image_list error image %s/%s:%s", regs[0].Url, img.FullRepoName, tag)
		return nil, err
	}
	// 下达扫描指令,这里会去拉取镜像，所以只能存中转镜像的library
	logging.GetLogger().Info().Msgf("CICD start scan,imagId:%d,image:%s/%s:%s", createdImage.ID, regs[0].Url, image.Repository, image.Tag)
	var scanStrategyID int64
	libs, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryURL: lib}, nil)
	if err == nil && len(libs) > 0 {
		config, _, err := s.scanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("CICD SearchScanConfig")
		} else if len(config) > 0 {
			if config[0].LibraryImageConfig != nil {
				if config[0].LibraryImageConfig.ScanAll {
					scanStrategyID = config[0].LibraryImageConfig.StrategyId
				}
				for i := range config[0].LibraryImageConfig.Libraries {
					if config[0].LibraryImageConfig.Libraries[i] == libs[0].ID {
						scanStrategyID = config[0].LibraryImageConfig.StrategyId
						continue
					}
				}
			}
			// scanStrategyId = config[0].ID
		}
	}
	logging.GetLogger().Info().Msgf("CICD get scanStrategyId:%d", scanStrategyID)

	if err := s.TickScanOne(ctx, createdImage.ID, task.UpdateTaskInfo{
		Scope:       consts.SingleScan,
		TriggerType: consts.CiCdTrigger,
		StrategyID:  scanStrategyID,
		Operator:    consts.CicdOperator,
	}); err != nil {
		logging.GetLogger().Err(err).Msgf("CICD TickScanOne failure, imag Id:" + strconv.Itoa(int(createdImage.ID)))
		return nil, fmt.Errorf("issuing scan command error:%s", err.Error())
	}

	if err := s.dbdal.SetImageStatus(ctx, []int64{createdImage.ID}, model.ScanStatusInProgress); err != nil {
		logging.GetLogger().Err(err).Msgf("CICD update SetImageStatus library error %s", err.Error())
		return nil, fmt.Errorf("initialization scan state error :%s", err.Error())
	}
	return &model.ScanOneCICDResultRequest{
		ImageID: createdImage.ID,
		Library: lib,
	}, nil
}

func (s *ConScannerSrv) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	res := s.dbdal.GetSimpleImageDetail(ctx, tag, digest, library, fullRepoName)
	return res
}

func (s *ConScannerSrv) GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error) {
	res, err := s.dbdal.GetImagesFromVuln(ctx, name)
	return res, err
}

func (s *ConScannerSrv) GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error) {
	res, err := s.dbdal.GetVulnDetails(ctx, name)
	return res, err
}

func (s *ConScannerSrv) SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error) {
	filter = filter.SetDefault()
	vulns, cnt, err := s.dbdal.SearchVulns(ctx, searchWord, filter)
	return vulns, cnt, err
}

func (s *ConScannerSrv) GetVulnOverView(ctx context.Context) (model.VulnOverview, error) {
	res := model.VulnOverview{}
	var err error
	res.VulnTotal, err = s.dbdal.GetVulnTotal(ctx)
	if err != nil {
		return model.VulnOverview{}, err
	}
	res.Severity, err = s.dbdal.GetVulnSeverityCount(ctx)
	if err != nil {
		return res, err
	}
	res.Top5, err = s.dbdal.GetVulnTop5(ctx)
	if err != nil {
		return res, err
	}
	return res, nil
}

// ImgLayerInfo Get detailed information about  the layer
func (s *ConScannerSrv) ImgLayerInfo(ctx context.Context, imageID int64, layerDigest string, filter *model.Filter) (*model.ScanLayerResponse, error) {
	layers, _, err := s.dbdal.SearchScanLayer(ctx, store.SearchScanLayerParam{LayerDigests: []string{layerDigest}, ImageIds: []int64{imageID}}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ReportImgBackInfo.SearchScanLayer")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(layers) == 0 {
		logging.GetLogger().Error().Err(err).Msg("ImgLayerInfo.SearchScanLayer not fond the image layer")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	res := model.ScanLayerResponse{
		ID:            layers[0].ID,
		CreatedAt:     layers[0].CreatedAt,
		UpdatedAt:     layers[0].UpdatedAt,
		DeletedAt:     layers[0].DeletedAt,
		ImageID:       layers[0].ImageID,
		LayerDigest:   layers[0].LayerDigest,
		PkgInfo:       layers[0].PkgInfo,
		SensitiveFile: layers[0].SensitiveFile,
		IsBasic:       layers[0].IsBasic,
	}

	malic := make([]model.VirusInfo, 0)
	for i := range layers[0].MaliciousInfo {
		malic = append(malic, layers[0].MaliciousInfo[i].VirusInfo)
	}
	res.MaliciousInfo = malic

	webshell := make([]model.WebShellInfo, 0)
	for i := range layers[0].WebshellInfo {
		webshell = append(webshell, layers[0].WebshellInfo[i].WebShellInfo)
	}
	res.WebshellInfo = webshell

	vulnInfo := FilterVulnsFromScanImage(layers[0].VulnInfo)
	sort.Sort(model.RespSingleVulnDetails(vulnInfo))
	res.VulnInfo = vulnInfo

	return &res, nil
}

// ListImgLayers List  all layers  information  with  this image. order by created time
func (s *ConScannerSrv) ListImgLayers(ctx context.Context, imaID int64, filter *model.Filter) ([]model.ReportImgBackInfo, error) {
	// step1 get image info
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imaID}}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("ReportImgBackInfo.SearchImage error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(imgs) == 0 {
		logging.GetLogger().Err(err).Msgf("ReportImgBackInfo.SearchImage not fond the image")
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond thd image"))
	}
	// step2 组装信息
	manifest := imgs[0].ManifestV2.Layers
	history := imgs[0].ConfigFile.History
	layerDigests := make([]string, 0)

	res := make([]model.ReportImgBackInfo, 0)
	for i := range history {
		if !history[i].EmptyLayer {
			re := model.ReportImgBackInfo{
				Created:   history[i].Created,
				CreatedBy: history[i].CreatedBy,
				ImageID:   imaID,
			}
			res = append(res, re)
		}
	}
	min := util.MinInt(len(manifest), len(history))
	res = res[:min]
	for i := 0; i < min; i++ {
		res[i].ImageDigest = manifest[i].Digest
		layerDigests = append(layerDigests, manifest[i].Digest)
	}

	// 可能是V1版本，这里要做兼容
	if len(layerDigests) == 0 {
		historyV1 := imgs[0].ManifestV1.HistoryV1
		for i := range historyV1 {
			if !historyV1[i].Throwaway {
				re := model.ReportImgBackInfo{
					ImageDigest: "sha256:" + historyV1[i].LayerDegest,
					Created:     historyV1[i].Created,
					CreatedBy:   strings.Join(historyV1[i].ContainerConfig.Cmd, ","),
				}
				res = append(res, re)
				layerDigests = append(layerDigests, historyV1[i].LayerDegest)
			}
		}
	}

	// 获取各层的信息
	if len(layerDigests) > 0 {
		layers, _, err := s.dbdal.SearchScanLayer(ctx, store.SearchScanLayerParam{LayerDigests: layerDigests, ImageIds: []int64{imgs[0].ID}}, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf(fmt.Sprintf("ReportImgBackInfo.SearchScanLayer error:%s", err.Error()))
			return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}

		for i := range res {
			for j := range layers {
				if res[i].ImageDigest == layers[j].LayerDigest {
					for k := range layers[j].VulnInfo {
						for r := range layers[j].VulnInfo[k].Vulns {
							res[i].Vulus = append(res[i].Vulus, layers[j].VulnInfo[k].Vulns[r].CVEID)
						}
					}
					for k := range layers[j].SensitiveFile {
						res[i].SensitiveFiles = append(res[i].SensitiveFiles, layers[j].SensitiveFile[k].Name)
					}
					for k := range layers[j].MaliciousInfo {
						res[i].Malicious = append(res[i].Malicious, layers[j].MaliciousInfo[k].VirusInfo.VirusName)
					}
					for k := range layers[j].WebshellInfo {
						res[i].WebshellInfo = append(res[i].WebshellInfo, layers[j].WebshellInfo[k].WebShellInfo.FileName)
					}
				}
			}
		}
	}

	return res, nil
}

func (s *ConScannerSrv) GetScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus {
	return s.dbdal.SearchScanAllStatus(ctx, fromType)
}

func (s *ConScannerSrv) ScanAllNow(ctx context.Context, info task.UpdateTaskInfo, search SearchImageWithScanParam) error {
	logging.GetLogger().Info().Int64("fromType", search.FromType).Msg("start full scan")

	images, _, err := s.SearchImageWithScan(ctx, search, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ScanAllNow find image error")
		return err
	}

	// 先查询当前时刻已存在的仓库列表
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("not found registry info")
		return err
	}
	registryMap := make(map[int64]bool)
	for i := range registries {
		registryMap[registries[i].ID] = true
	}

	imgIDs := make([]int64, 0)
	for i := range images {
		if registryMap[images[i].RegistryID] {
			imgIDs = append(imgIDs, images[i].ID)
		}
	}
	ts := task.NewTaskSrv()
	if err := ts.GenerateScanTask(ctx, imgIDs, task.UpdateTaskInfo{
		TriggerType: consts.ManualTrigger, Scope: consts.FullScan,
		Operator: info.Operator, StrategyID: info.StrategyID}); err != nil {
		logging.GetLogger().Error().Err(err).Msg("add full scan task failed")
		return response.NewHttpError(http.StatusBadRequest, err)
	}
	logging.GetLogger().Info().Msg("add full scan task end")
	return nil
}

func (s *ConScannerSrv) TickScanOne(ctx context.Context, imgID int64, info task.UpdateTaskInfo) error {
	ts := task.NewTaskSrv()
	err := ts.GenerateScanTask(ctx, []int64{imgID}, info)
	if err != nil {
		logging.GetLogger().Error().Err(err).Int64("imageId", imgID).Msg("add scan task failed")
		return err
	}
	return nil
}

func (s *ConScannerSrv) GetScanOneStatus(ctx context.Context, imgID int64, fromURL string) (*model.ImageResponse, error) {
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imgID}, Library: fromURL}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetScanOneStatus.SearchImage error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	if len(imgs) == 0 {
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("not fond the iamge"))
	}
	// 拼装信息
	ans := model.ImageResponse{
		ID:             imgs[0].ID,
		Digest:         imgs[0].Digest,
		Library:        imgs[0].Library,
		NodeIP:         imgs[0].NodeIP,
		ScanStatus:     consts.ImageNotScan,
		Questions:      make([]model.QuestionInfo, 0),
		FullRepoName:   imgs[0].FullRepoName,
		Tags:           imgs[0].Tags,
		ImageType:      imgs[0].ImageType,
		RegistryID:     imgs[0].RegistryID,
		FromType:       imgs[0].FromType,
		Os:             imgs[0].OS,
		NodeHostname:   imgs[0].NodeHostname,
		IsReinforce:    int64(imgs[0].IsReinforce),
		PrivilegedBoot: imgs[0].PrivilegedBoot,
	}

	// 查状态
	status, err := s.taskdal.SearchSubTasksWithScanStatus(ctx, []int64{imgID}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetScanOneStatus.SearchScanImage error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}

	// 查scan_image
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{imgs[0].ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetScanOneStatus.SearchScanImage error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}

	// 查在线
	onlineSQL := fmt.Sprintf("select distinct a.id  from  %s a  join %s b  on  a.image_uuid = b.image_uuid where a.id = %d ;", model.ImageList{}.TableName(), model.TensorContainer{}.TableName(), imgID)
	online, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	// 可信镜像的筛选
	trustedImages, err := s.dbdal.SearchTrustedImages(ctx, store.SearchTrustedImageParam{IsTrusted: consts.IsTrustedImageString, Digests: []string{imgs[0].Digest}})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ID: imgs[0].RegistryID}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchRegistry")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	if len(online) > 0 {
		ans.Online = true
	}

	if len(registries) > 0 {
		ans.RegistryName = registries[0].Name
		ans.Library = registries[0].Url
		ans.RegistryDeletedAt = registries[0].DeletedAt
	}

	if len(trustedImages) > 0 {
		ans.Trusted = consts.TrustedImage
	}
	if len(status) > 0 {
		ans.ScanStatus = int(status[0].Status)
		if status[0].FinishedAt != nil && !status[0].FinishedAt.IsZero() {
			ans.CompleteTime = status[0].FinishedAt.UnixMilli()
		}
	}

	if len(scs) == 0 {
		return &ans, nil
	}

	qus := make([]model.QuestionInfo, 0)

	ans.HasFixedVulu = int64(scs[0].HasFixedVuln)
	if scs[0].VulnScore > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VULN})
	}

	if scs[0].SensitiveScore > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_SENSITIVE})
	}
	if scs[0].VirusScore > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VIRUS})
	}
	if scs[0].WebshellScore > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_WEB_SHELL})
	}

	if scs[0].ScanEnableCollection.EnvEnable > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_ENV})
	}

	if scs[0].ScanEnableCollection.LicenseEnable > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_LICENSE, Info: ParseLicense(scs[0].LicenseInfo)})
	}

	if scs[0].ScanEnableCollection.SoftwareEnable > 0 {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_SOFTWARE, Info: ParseSoftWare(scs[0].Software)})
	}
	// 特权启动
	if imgs[0].PrivilegedBoot == consts.PrivilegedBootImage {
		qus = append(qus, model.QuestionInfo{ID: model.QUESTION_PRIORITY})
	}

	ans.Questions = append(ans.Questions, qus...)
	ans.RiskScore = scs[0].VulnScore + scs[0].SensitiveScore + math.Min(scs[0].WebshellScore+scs[0].VirusScore, 40)

	return &ans, nil
}

func (s *ConScannerSrv) GetImageDetail(ctx context.Context, imgID int64) (*model.ImageList, error) {
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imgID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetImageDetail.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(imgs) == 0 {
		logging.GetLogger().Err(err).Msgf("GetImageDetail.not find the image")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("not find the image"))
	}

	rr, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{RegistryIds: []int64{imgs[0].RegistryID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("GetImageDetail.not find the registry")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("not find the registry"))
	}

	img := &imgs[0]
	if len(rr) > 0 {
		img.Registry = &(rr[0])
	}
	// 查扫描结果
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{img.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("SearchImageWithScan.SearchScanImage:error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(scs) == 0 {
		var config model.ConfigFile
		err := json.Unmarshal(img.ConfigJSON, &config)
		if err == nil {
			envs := ParseConfigEnv(config.Config.Env)
			for k := range envs {
				img.ImageScanEnv = append(img.ImageScanEnv, model.SummaryEnv{EnvName: envs[k].Key, EnvValue: envs[k].Value})
			}
		}
		logging.GetLogger().Info().Msgf("GetImageDetail not found the scan_image,imageID:%d", imgID)
		return img, nil
	}
	respVuln := FilterVulnsFromScanImage(scs[0].VulnInfo)
	sort.Sort(model.RespSingleVulnDetails(respVuln))

	// 增加漏洞和敏感文件信息
	scanTaskID, _ := primitive.ObjectIDFromHex(scs[0].ScanTaskID)
	imageScanResult := model.ImageScanSummaryResult{
		TopVulns:          respVuln,
		SensitiveFiles:    scs[0].SensitiveFile,
		Repository:        img.FullRepoName,
		HarborURL:         img.Library,
		Tag:               img.Tags,
		Digest:            img.Digest,
		TaskID:            scanTaskID,
		StartedAt:         scs[0].StartedAt,
		FinishedAt:        scs[0].FinishAt,
		OverallSeverity:   scs[0].OverallSeverity,
		SeverityHistogram: scs[0].SeverityHistogram,
		VulnScore:         scs[0].VulnScore,
		VirusScore:        scs[0].VirusScore,
		WebshellScore:     scs[0].WebshellScore,
		SensitiveScore:    scs[0].SensitiveScore,
		RiskScore:         scs[0].VulnScore + scs[0].SensitiveScore + math.Min(scs[0].WebshellScore+scs[0].VirusScore, 40),
	}
	img.ImageScanVuln = imageScanResult
	// 增加病毒信息
	for i := range scs[0].MaliciousInfo {
		img.ImageScanVirus = append(img.ImageScanVirus,
			model.VirusFileInfo{Filename: scs[0].MaliciousInfo[i].VirusInfo.FileName,
				Filepath:  scs[0].MaliciousInfo[i].VirusInfo.FilePath,
				Virusname: scs[0].MaliciousInfo[i].VirusInfo.VirusName})
	}

	img.ImageScanWebshell = make([]model.WebshellFileInfo, 0, len(scs[0].WebshellInfo))
	logging.GetLogger().Info().Msgf("%v", scs[0].WebshellInfo)
	// 增加webshell信息
	for i := range scs[0].WebshellInfo {
		img.ImageScanWebshell = append(img.ImageScanWebshell,
			model.WebshellFileInfo{
				Filename: scs[0].WebshellInfo[i].WebShellInfo.FileName,
				Filepath: scs[0].WebshellInfo[i].WebShellInfo.FilePath,
				Score:    scs[0].WebshellInfo[i].WebShellInfo.Score,
				Codes:    scs[0].WebshellInfo[i].WebShellInfo.Codes,
			},
		)
	}

	// 整合Env信息
	scanStrategies, err := s.dbdal.GetAllScanStrategyEnv(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("get ScanStrategy error")
	} else {
		dbEnvSum := make(map[string]int)
		for k := range scanStrategies {
			var tmpEnvs []string
			if len(scanStrategies[k].EnvsJson) != 0 {
				err := json.Unmarshal([]byte(scanStrategies[k].EnvsJson), &tmpEnvs)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msgf("Unmarshal EnvJson error")
					continue
				}
			}
			for i := range tmpEnvs {
				v, ok := dbEnvSum[tmpEnvs[i]]
				if !ok {
					dbEnvSum[tmpEnvs[i]] = 1
				} else {
					dbEnvSum[tmpEnvs[i]] = v + 1
				}
			}
		}
		strategySum := len(scanStrategies)
		var scsEnv []model.EnvKeyValue
		if len(scs[0].EnvJSON) != 0 {
			err := json.Unmarshal(scs[0].EnvJSON, &scsEnv)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msgf("Unmarshal ScanImages EnvJson error")
			}
		}
		for k := range scsEnv {
			tmpEnvSummary := model.SummaryEnv{}
			tmpEnvSummary.EnvName = scsEnv[k].Key
			tmpEnvSummary.EnvValue = scsEnv[k].Value
			tmpEnvSummary.IsAbnormal = scsEnv[k].IsAbnormal
			v, ok := dbEnvSum[scsEnv[k].Key]
			if ok {
				if v == strategySum {
					tmpEnvSummary.IsInPolicy = 1 // 如果strategySum为0，还是会显示添加按钮，只不过是空，看产品逻辑
				}
			}
			if strategySum == 0 {
				tmpEnvSummary.IsInPolicy = 1
			}
			img.ImageScanEnv = append(img.ImageScanEnv, tmpEnvSummary)
		}

	}

	if img.FromType == model.ImageFromSafeNode {
		split := strings.Split(img.FullRepoName, "/")
		if len(split) <= 6 {
			return img, nil
		}
		img.FullRepoName = fmt.Sprintf("%s-%s-%s", img.NodeHostname, img.NodeIP, strings.Join(split[5:], "/"))
		img.FullRepoName = strings.Replace(img.FullRepoName, consts.ColonSalt, ":", -1)
	}
	// docker-registry(GET /v2/<name>/tags/list)入库是没有这三个时间，做一步兼容
	if img.LastPullTime.IsZero() {
		img.LastPullTime = img.UpdatedAt
	}
	if img.FirstPushTime.IsZero() {
		img.FirstPushTime = img.CreatedAt
	}
	if img.LastPushTime.IsZero() {
		img.LastPushTime = img.CreatedAt
	}

	return img, nil
}

func (s *ConScannerSrv) GetImageOverView(ctx context.Context, fromType int64) (*model.OverView, error) {
	overView := new(model.OverView)
	// 查总数
	_, total, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{FromType: fromType, JustCount: true}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("GetImageOverView.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	// map[imageId_uuid][type]*store.ImageGroup
	allResMap := make(map[string]map[string]int)

	if err := s.getOverViewHelper(ctx, fromType, allResMap); err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("GetImageOverView.getOverViewHelper error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	// 查在线
	onlineSQL := fmt.Sprintf("select distinct a.id,a.image_uuid from  %s a  join %s b  on  a.image_uuid = b.image_uuid where a.from_type = %d ;", model.ImageList{}.TableName(), model.TensorContainer{}.TableName(), fromType)
	onlineRes, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetImageOverView.GetOnlineImage")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	// 由于uuid是由不带schema的library生成的，这里需要过滤掉同时拥有http与https头但只有一个扫描另一个未扫描的情况
	onlineMap := make(map[string]*store.OnlineImage)
	for i := range onlineRes {
		key := fmt.Sprintf("%d_%d", onlineRes[i].ID, onlineRes[i].ImageUUID)
		onlineMap[key] = &onlineRes[i]
	}
	// 组装结果
	for key, resMap := range allResMap {
		for typ, cnt := range resMap {
			if _, ok := onlineMap[key]; ok {
				switch typ {
				case consts.VulnType:
					overView.Online.VULN += cnt
				case consts.SensitiveFileType:
					overView.Online.SENSITIVE += cnt
				case consts.MaliciousInfoType:
					overView.Online.VIRUS += cnt
				case consts.WebsellInfoType:
					overView.Online.Webshell += cnt
				case consts.EnvEnableType:
					overView.Online.Envs += cnt
				case consts.SoftWoreType:
					overView.Online.Software += cnt
				case consts.LicenseEnableType:
					overView.Online.License += cnt
				case consts.PrivilegedEnableType:
					overView.Online.PrivilegedBoot += cnt
				}
			}

			switch typ {
			case consts.VulnType:
				overView.Sum.VULN += cnt
			case consts.SensitiveFileType:
				overView.Sum.SENSITIVE += cnt
			case consts.MaliciousInfoType:
				overView.Sum.VIRUS += cnt
			case consts.WebsellInfoType:
				overView.Sum.Webshell += cnt
			case consts.EnvEnableType:
				overView.Sum.Envs += cnt
			case consts.SoftWoreType:
				overView.Sum.Software += cnt
			case consts.LicenseEnableType:
				overView.Sum.License += cnt
			case consts.PrivilegedEnableType:
				overView.Sum.PrivilegedBoot += cnt
			}
		}
	}

	overView.ImageTotal = total
	overView.OnlineTotal = int64(len(onlineRes))
	return overView, nil
}

// getOverViewHelper 连表查询tensor_image_list和scan_image表，查询各个镜像下漏洞，病毒等的数据
func (s *ConScannerSrv) getOverViewHelper(ctx context.Context, fromType int64, allResMap map[string]map[string]int) error {
	type ImageGroup struct {
		ImageID   int64  `json:"image_id"`
		ImageUUID uint32 `json:"image_uuid"`
		Count     int    `json:"count"`
	}

	type ScanImageJonin struct {
		ImageID                  int64                       `json:"image_id"`
		ImageUUID                uint32                      `json:"image_uuid"`
		VulnScore                int                         `json:"vuln_score"`
		ScanEnableCollection     *model.ScanEnableCollection `gorm:"-" json:"-"`
		ScanEnableCollectionJSON string                      `json:"scan_enable_collection_json"`
	}
	type ImageSinge struct {
		ID             int64  `json:"id"`
		ImageUUID      uint32 `json:"image_uuid"`
		PrivilegedBoot int64  `gorm:"privileged_boot" json:"privileged_boot"`
	}

	for _, searchType := range []string{consts.MaliciousInfoType, consts.SensitiveFileType, consts.WebsellInfoType} {
		hasVuluSQL := fmt.Sprintf("select count(b.image_id), b.image_id,a.image_uuid from %s a join %s b on a.id = b.image_id where a.from_type = %d and  b.%s is not null group by b.image_id,a.image_uuid;", model.ImageList{}.TableName(), model.ScanImage{}.TableName(), fromType, searchType)

		res := make([]ImageGroup, 0)
		err := s.dbdal.GetImageOverView(ctx, store.GetImageOverViewParm{SQL: hasVuluSQL}, &res)
		if err != nil {
			return response.NewHttpError(http.StatusInternalServerError, err)
		}
		for i := range res {
			key := fmt.Sprintf("%d_%d", res[i].ImageID, res[i].ImageUUID)
			if allResMap[key] == nil {
				allResMap[key] = make(map[string]int)
			}
			allResMap[key][searchType] += res[i].Count
		}
	}
	// 查漏洞，异常环境变量，不允许开源许可,漏洞
	hasSQL := fmt.Sprintf("select  b.image_id,a.image_uuid,b.vuln_score,b.scan_enable_collection_json from %s a join %s b on a.id = b.image_id where a.from_type = %d ;", model.ImageList{}.TableName(), model.ScanImage{}.TableName(), fromType)
	res := make([]ScanImageJonin, 0)
	err := s.dbdal.GetImageOverView(ctx, store.GetImageOverViewParm{SQL: hasSQL}, &res)
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	for i := range res {
		sc := new(model.ScanEnableCollection)
		if err := json.Unmarshal([]byte(res[i].ScanEnableCollectionJSON), sc); err != nil {
			logging.GetLogger().Err(err).Msg("getOverViewHelper Unmarshal")
		}
		res[i].ScanEnableCollection = sc
		key := fmt.Sprintf("%d_%d", res[i].ImageID, res[i].ImageUUID)
		if allResMap[key] == nil {
			allResMap[key] = make(map[string]int)
		}

		if res[i].ScanEnableCollection.LicenseEnable > 0 {
			allResMap[key][consts.LicenseEnableType]++
		}
		if res[i].ScanEnableCollection.EnvEnable > 0 {
			allResMap[key][consts.EnvEnableType]++
		}
		if res[i].ScanEnableCollection.SoftwareEnable > 0 {
			allResMap[key][consts.SoftWoreType]++
		}
		if res[i].VulnScore > 0 {
			allResMap[key][consts.VulnType]++
		}
	}

	// 再查特权启动
	privilegedSQL := fmt.Sprintf("select id,image_uuid ,privileged_boot from %s where from_type = %d", model.ImageList{}.TableName(), fromType)
	privilegedRes := make([]ImageSinge, 0)
	if err := s.dbdal.GetImageOverView(ctx, store.GetImageOverViewParm{SQL: privilegedSQL}, &privilegedRes); err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}

	for i := range privilegedRes {
		key := fmt.Sprintf("%d_%d", privilegedRes[i].ID, privilegedRes[i].ImageUUID)
		if privilegedRes[i].PrivilegedBoot == consts.PrivilegedBootImage {
			if allResMap[key] == nil {
				allResMap[key] = make(map[string]int)
			}
			allResMap[key][consts.PrivilegedEnableType]++
		}
	}

	return nil
}

func (s *ConScannerSrv) SearchImageWithScan(ctx context.Context, param SearchImageWithScanParam, filter *model.Filter) ([]*model.ImageResponse, int64, error) {
	registryIds := make([]int64, 0)
	if param.NotDeleteRegistry == consts.TrueString {
		registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
		if err != nil {
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		if len(registries) == 0 {
			return make([]*model.ImageResponse, 0), 0, err
		}
		for i := range registries {
			registryIds = append(registryIds, registries[i].ID)
		}
	}

	daoParam := store.SearchImageWithScanParam{
		UUIDs:            param.UUIDs,
		RegistryIds:      registryIds,
		FromType:         param.FromType,
		ImageType:        param.ImageType,
		Library:          param.Library,
		Kind:             param.Kind,
		HasFixedVulu:     param.HasFixedVulu,
		SearchWord:       param.SearchWord,
		IsReinforce:      param.IsReinforce, // 是否已加固
		NodeHostname:     param.NodeHostname,
		SpecialImageType: param.SpecialImageType,
	}
	// 查在线
	onlineSQL := fmt.Sprintf("select distinct a.id  from  %s a  join %s b  on  a.image_uuid = b.image_uuid ;", model.ImageList{}.TableName(), model.TensorContainer{}.TableName())
	online, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSQL})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	onlineIds := make([]int64, 0)
	onlineMap := make(map[int64]bool)
	for i := range online {
		onlineIds = append(onlineIds, online[i].ID)
		onlineMap[online[i].ID] = true
	}
	if param.Online == consts.TrueString {
		daoParam.InIDs = onlineIds
		if len(daoParam.InIDs) == 0 {
			return make([]*model.ImageResponse, 0), 0, nil
		}
	} else if param.Online == consts.FalseString {
		daoParam.NotInIDs = onlineIds
	}

	// 可信镜像的筛选
	trustedImages, err := s.dbdal.SearchTrustedImages(ctx, store.SearchTrustedImageParam{IsTrusted: consts.IsTrustedImageString})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchQuestionInfo")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	trustedDigests := make([]string, 0)
	trustedMap := make(map[string]int64)
	for i := range trustedImages {
		trustedDigests = append(trustedDigests, trustedImages[i].Digest)
		trustedMap[trustedImages[i].Digest] = consts.IsTrustedImage
	}

	if param.Trusted != "" {
		if param.Trusted == consts.IsTrustedImageString {
			daoParam.InDigests = trustedDigests
			if len(daoParam.InDigests) == 0 {
				return make([]*model.ImageResponse, 0), 0, nil
			}
		} else if param.Trusted == consts.NotTrustedImageString {
			daoParam.NotInDigests = trustedDigests
		}
	}
	// 状态筛选
	if len(param.ScanStatus) > 0 {
		statusInIds, err := s.filterScanStatus(ctx, param.ScanStatus)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchSubTasksWithStatusFilter")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		if len(statusInIds) == 0 {
			return make([]*model.ImageResponse, 0), 0, nil
		}

		daoParam.InIDs = append(daoParam.InIDs, statusInIds...)
	}
	daoParam.InIDs = DeDuplicationInt64Slice(daoParam.InIDs)
	daoParam.NotInIDs = DeDuplicationInt64Slice(daoParam.NotInIDs)

	res, cnt, err := s.dbdal.SearchImageWithScan(ctx, daoParam, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if param.JustReturnImage {
		return res, cnt, nil
	}
	if len(res) == 0 {
		return res, 0, nil
	}
	imagesIds := make([]int64, 0)
	imageMap := make(map[int64]*model.ImageResponse)
	for i := range res {
		imagesIds = append(imagesIds, res[i].ID)
		imageMap[res[i].ID] = res[i]
		imageMap[res[i].ID].Questions = make([]model.QuestionInfo, 0)
	}

	statusMap := make(map[int64]model.SubTask)
	subtasks, err := s.taskdal.SearchSubTasksWithScanStatus(ctx, imagesIds, param.ScanStatus)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchSubTasksWithStatusFilter")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	for i := range subtasks {
		statusMap[subtasks[i].ImageID] = subtasks[i]
	}

	for i := range res {
		// 加上在线离线状态
		if on, ok := onlineMap[res[i].ID]; ok && on {
			res[i].Online = true
		}
		res[i].FullRepoName = strings.Replace(res[i].FullRepoName, consts.ColonSalt, ":", -1)
		// 加上扫描状态
		if sc, ok := statusMap[res[i].ID]; ok {
			res[i].ScanStatus = int(sc.Status)
			if sc.FinishedAt != nil && sc.FinishedAt.IsZero() {
				res[i].CompleteTime = sc.FinishedAt.UnixMilli()
			}
		} else {
			res[i].ScanStatus = consts.ImageNotScan
		}
		// 是否可信
		if on, ok := trustedMap[res[i].Digest]; ok {
			res[i].Trusted = on
		}
	}

	// 兼容前端把questionInfo信息加上
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: imagesIds}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchScanImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	for i := range scs {
		if _, ok := imageMap[scs[i].ImageID]; ok && scs[i].FinishAt > 0 {
			imageMap[scs[i].ImageID].CompleteTime = scs[i].FinishAt
		}

		qus := make([]model.QuestionInfo, 0)

		if scs[i].VulnScore > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VULN})
		}

		if scs[i].SensitiveScore > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_SENSITIVE})
		}
		if scs[i].VirusScore > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VIRUS})
		}
		if scs[i].WebshellScore > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_WEB_SHELL})
		}

		if scs[i].ScanEnableCollection.EnvEnable > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_ENV})
		}

		if scs[i].ScanEnableCollection.LicenseEnable > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_LICENSE, Info: ParseLicense(scs[i].LicenseInfo)})
		}

		if scs[i].ScanEnableCollection.SoftwareEnable > 0 {
			qus = append(qus, model.QuestionInfo{ID: model.QUESTION_SOFTWARE, Info: ParseSoftWare(scs[i].Software)})
		}
		// 问题类别加上
		if v, ok := imageMap[scs[i].ImageID]; ok {
			v.Questions = qus
		}
		// 镜像评分信息加上
		if _, ok := imageMap[scs[i].ImageID]; ok {
			imageMap[scs[i].ImageID].RiskScore = scs[i].VulnScore + scs[i].SensitiveScore + math.Min(scs[i].WebshellScore+scs[i].VirusScore, 40)
		}
	}

	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImageWithScan.SearchRegistry")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}

	for i := range res {

		if res[i].PrivilegedBoot == consts.PrivilegedBootImage {
			res[i].Questions = append(res[i].Questions, model.QuestionInfo{ID: model.QUESTION_PRIORITY})
		}
		if re, ok := regMap[res[i].RegistryID]; ok {
			res[i].RegistryName = re.Name
			res[i].Library = re.Url
			res[i].RegistryDeletedAt = re.DeletedAt
		}
	}

	return res, cnt, nil
}

func (s *ConScannerSrv) filterScanStatus(ctx context.Context, status []int) ([]int64, error) {
	// 先查全部镜像数据
	inIds := make([]int64, 0)
	image, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Fields: []string{"id"}}, nil)
	if err != nil {
		return inIds, err
	}
	scanStatus, err := s.dbdal.SearchSubTasksWithScanStatus(ctx, nil, nil)
	if err != nil {
		return inIds, err
	}
	scanStatusMap := make(map[int64]model.SubTask)
	for i := range scanStatus {
		scanStatusMap[scanStatus[i].ImageID] = scanStatus[i]
	}
	hasNotScan := InIntSlice(consts.ImageNotScan, status)

	for i := range image {
		tak, ok := scanStatusMap[image[i].ID]
		if hasNotScan && !ok {
			inIds = append(inIds, image[i].ID)
		}
		if InIntSlice(int(tak.Status), status) {
			inIds = append(inIds, image[i].ID)
		}
	}
	return inIds, nil
}

func (s *ConScannerSrv) getRegistry(ctx context.Context, library string, useType int64) (registry.Registry, error) {
	// cicd集成时，首先会把公司镜像推送到我们自己搭建的仓库中(默认是docker-registry),然后拉取镜像进行扫描，
	// 通过library查registryID
	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryURL: library, UseType: useType, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("can not find the library:%s", library))
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not find the library:%s,error is %s", library, err.Error())))
	}
	if len(regs) == 0 {
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not find the library:%s", library)))
	}
	drive, err := registry.Open(RegToRegistryConf(regs[0]))
	if err != nil {
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	if err := drive.Ping(); err != nil {
		logging.GetLogger().Error().Err(err).Msg("尝试连接到仓库出错")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("尝试连接到仓库出错,请核对信息后重新提交"))
	}

	return drive, nil
}

// DetectImageForCICD CICD 检查镜像是否正确
func (s *ConScannerSrv) DetectImageForCICD(ctx context.Context, img *model.ImageList) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("CICD,start DetectImage,imageId：%d", img.ID)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msg("CICD get global policy error")
		return false, records, msgs, err
	}
	if len(globalReg) == 0 {
		logging.GetLogger().Info().Msg("CICD not find global policy")
		return true, records, msgs, nil
	}

	if !globalReg[0].CicdEnable {
		logging.GetLogger().Info().Msg("CICD global is not enable ")
		return true, records, msgs, nil
	}

	// 先查镜像是否存在  // todo 这里可以移除吗 @liuqiang
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{img.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD,find the image :%d,error", img.ID)
		return false, records, msgs, err
	}
	// 如果没有在数据库没有查到镜像，默认不安全
	if len(imgs) == 0 {
		logging.GetLogger().Info().Msgf("CICD,not find the image:%d", img.ID)
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("CICD,没有查到对应镜像:%d", img.ID))
	}

	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryURL: imgs[0].Library, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult search SearchRegistry error:%s", err.Error())
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("CICD,查询镜像仓库地址出错：%d", img.ID))
	}
	if len(regs) == 0 {
		logging.GetLogger().Info().Msgf("untrust Library imag Id:" + strconv.Itoa(int(imgs[0].ID)))
		msgZh := model.GetRejectReason(model.LangZh)[model.RejectNoLibrary]
		msgEN := model.GetRejectReason(model.LangEn)[model.RejectNoLibrary]
		msgLog := fmt.Sprintf("Image:%s/%s:%s is untrust Library", imgs[0].Library, imgs[0].FullRepoName, imgs[0].Tags)

		records = append(records, ReasonAndDetail{
			RejectReason: model.RejectNoLibrary,
			RejectDetail: msgZh,
		})

		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectNoLibrary], msgZh+"，被阻断"),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectNoLibrary], msgEN+",blocked")}})
		logging.GetLogger().Info().Msgf(" %s,has blocked", msgLog)
		// 仓库都不在本地仓库，就直接返回了
		return false, records, msgs, nil
	}

	img = &imgs[0]

	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Library: img.Library})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD library:%s get reject policy error", img.Library)
		return true, records, msgs, err
	}

	if len(policies) == 0 { // 没有策略说明不检测，默认全安全
		logging.GetLogger().Info().Msgf("CICD library:%s has no reject policy, all safe by default", img.Library)
		return true, records, msgs, nil
	}
	scanImageRes, err := s.checkScanImageExist(ctx, model.UsePatternForCICD, img, policies[0])
	if err != nil {
		logging.GetLogger().Info().Msgf("CICD search scan_image: %d, error: %s", img.ID, err.Error())
		return false, records, msgs, err
	}
	records = append(records, scanImageRes.Records...)
	msgs = append(msgs, scanImageRes.Msg...)
	if !scanImageRes.Safe {
		safe = false
	}

	if scanImageRes.ScanImag != nil {
		scanImage := *scanImageRes.ScanImag
		for _, po := range policies {
			if !po.Enable || po.IsGlobal {
				logging.GetLogger().Info().Msgf("CICD reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}

			logging.GetLogger().Info().Msgf("CICD reject policy is enable :name:%s,ID:%d,police is %+v", po.Name, po.ID, po)
			// 恶意文件
			sa1, red1, ms1 := s.checkMaliciousInfo(ctx, scanImage, img, po)
			// 敏感文件
			sa2, red2, ms2 := s.checkSensitiveFile(ctx, scanImage, img, po)
			// 漏洞评分
			sa3, red3, ms3 := s.checkVulnScore(ctx, scanImage, img, po)
			// 自定义漏洞规则
			sa4, red4, ms4 := s.checkCustomizeVulu(ctx, scanImage, img, po)
			// 漏洞评级
			sa5, red5, ms5 := s.checkVulnSeverity(ctx, scanImage, img, po)
			// webshell
			sa6, red6, ms6 := s.checkWebshell(ctx, scanImage, img, po)

			sa9, red9, ms9 := s.checkEnv(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 || !sa9 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6, red9)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6, ms9)...)
		}
	}

	// 检查基础镜像
	for _, po := range policies {
		if !po.Enable || !po.CicdEnable || po.IsGlobal {
			logging.GetLogger().Info().Msgf("CICD reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
			continue
		}
		sa6, red6, ms6 := s.checkBaseImage(ctx, img, po)
		if !sa6 {
			safe = false
		}
		records = append(records, red6...)
		msgs = append(msgs, ms6...)

		// 可信镜像
		// sa7, red7, ms7 := s.checkTrustedImage(ctx, img, po)
		// if !sa7 {
		// 	safe = false
		// }

		// records = append(records, red7...)
		// msgs = append(msgs, ms7...)

		// 特权账户
		sa8, red8, ms8 := s.checkPrivilegedBoot(ctx, img, po)
		if !sa8 {
			safe = false
		}

		records = append(records, red8...)
		msgs = append(msgs, ms8...)
	}

	// 检查白名单,要检查一下Digest,防止通过Library+FullRepoName+Tags的方式绕过检测
	// 镜像存在白名单中，只是不阻断，任然要进行扫描检测，对检测结果仍然要发事件中心
	if !safe {
		if in, _ := s.checkWhitelist(ctx, img, model.UsePatternForCICD); in {
			logging.GetLogger().Info().
				Str("library", img.Library).
				Str("fullRepoName", img.FullRepoName).
				Str("tags", img.Tags).
				Str("digest", img.Digest).
				Msg("ci/cd check image")
			safe = true
			for i := range msgs {
				msgs[i].KVHash.ZH.Value = strings.Replace(msgs[i].KVHash.ZH.Value, "被阻断", "但镜像已加入白名单中，未被阻断", 1)
				msgs[i].KVHash.EN.Value = strings.Replace(msgs[i].KVHash.EN.Value, ",blocked", ",but image has add to the whitelist,unblocked", 1)
			}
		}
	}
	return safe, records, msgs, nil
}

// DetectImageForK8sOnlineMonitor  判断该镜像是否安全
func (s *ConScannerSrv) DetectImageForK8sOnlineMonitor(ctx context.Context, image *model.ImageList) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("K8sOnlineMonitor,start DetectImage,image：%s/%s:%s", image.Library, image.FullRepoName, image.Tags)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msg("K8sOnlineMonitor get global policy error")
		return false, records, msgs, err
	}
	if len(globalReg) == 0 {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor not find global policy ")
		return true, records, msgs, nil
	}

	if !globalReg[0].OnlineMonitor {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor global policy is not enable")
		return true, records, msgs, nil
	}

	// 先查镜像是否存在
	checkImageRes := s.checkImageExist(ctx, model.UsePatternForOnline, image)
	if !checkImageRes.Safe || checkImageRes.Image == nil {
		safe = false
		msgs = append(msgs, checkImageRes.Msg...)
		// 没有查到镜像就要返回了
		return safe, records, msgs, nil
	}

	// 对于delete Pod所发的update事件，这时是没有digest
	if checkImageRes.Image != nil && image.Digest != "" && checkImageRes.Image.Digest != image.Digest {
		safe = false
		msgZh := fmt.Sprintf("镜像：%s/%s:%s是非可信镜像", checkImageRes.Image.Library, image.FullRepoName, image.Tags)
		msgEN := fmt.Sprintf("image:%s%s:%s is untrusted image", checkImageRes.Image.Library, image.FullRepoName, image.Tags)
		logging.GetLogger().Info().Msgf("untrusted image,k8s digest:%s,database:%s", image.Digest, checkImageRes.Image.Digest)

		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonDifferentImageDigest], msgZh),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonDifferentImageDigest], msgEN)}})
		return safe, records, msgs, nil
	}

	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Library: checkImageRes.Image.Library})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor library:%s get reject policy error", checkImageRes.Image.Library)
		return true, records, msgs, err
	}

	if len(policies) == 0 { // 没有策略说明不检测，默认全安全
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor library:%s has no reject policy, all safe by default", checkImageRes.Image.Library)
		return true, records, msgs, nil
	}

	img := checkImageRes.Image
	checkScanImage, err := s.checkScanImageExist(ctx, model.UsePatternForOnline, img, policies[0])
	if err != nil {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor search scan_image: %d, error: %s", checkImageRes.Image.ID, err.Error())
		return safe, records, msgs, nil
	}
	records = append(records, checkScanImage.Records...)
	msgs = append(msgs, checkScanImage.Msg...)
	if !checkScanImage.Safe {
		safe = false
	}

	if checkScanImage.ScanImag != nil {
		scanImage := *checkScanImage.ScanImag
		for _, po := range policies {
			if !po.Enable || po.IsGlobal {
				logging.GetLogger().Info().Msgf("K8sOnlineMonitor reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}
			logging.GetLogger().Info().Msgf("K8sOnlineMonitor reject policy is enable :name:%s,ID:%d,police is %+v", po.Name, po.ID, po)

			// 恶意文件
			sa1, red1, ms1 := s.checkMaliciousInfo(ctx, scanImage, img, po)
			// 敏感文件
			sa2, red2, ms2 := s.checkSensitiveFile(ctx, scanImage, img, po)
			// 漏洞评分
			sa3, red3, ms3 := s.checkVulnScore(ctx, scanImage, img, po)
			// 自定义漏洞规则
			sa4, red4, ms4 := s.checkCustomizeVulu(ctx, scanImage, img, po)
			// 漏洞评级
			sa5, red5, ms5 := s.checkVulnSeverity(ctx, scanImage, img, po)
			// webshell
			sa6, red6, ms6 := s.checkWebshell(ctx, scanImage, img, po)

			sa9, red9, ms9 := s.checkEnv(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 || !sa9 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6, red9)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6, ms9)...)
		}
	}

	// 检查基础镜像
	for _, po := range policies {
		if !po.Enable || !po.OnlineMonitor || po.IsGlobal {
			logging.GetLogger().Info().Msgf("K8sOnlineMonitor reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
			continue
		}
		sa6, red6, ms6 := s.checkBaseImage(ctx, img, po)
		if !sa6 {
			safe = false
		}
		records = append(records, red6...)
		msgs = append(msgs, ms6...)

		// 检查可信镜像
		sa7, red7, ms7 := s.checkTrustedImage(ctx, img, po)
		if !sa7 {
			safe = false
		}

		records = append(records, red7...)
		msgs = append(msgs, ms7...)

		// 特权账户
		sa8, red8, ms8 := s.checkPrivilegedBoot(ctx, img, po)
		if !sa8 {
			safe = false
		}

		records = append(records, red8...)
		msgs = append(msgs, ms8...)
	}

	if !safe {
		if in, _ := s.checkWhitelist(ctx, img, model.UsePatternForOnline); in {
			safe = true
			for i := range msgs {
				// 在线监控不可能会阻断，所以这里改一下文案
				msgs[i].KVHash.ZH.Value = strings.Replace(msgs[i].KVHash.ZH.Value, "被阻断", "按策略应该被阻断,但已加白名单", 1)
				msgs[i].KVHash.EN.Value = strings.Replace(msgs[i].KVHash.EN.Value, ",blocked", ",should be blocked by reject policy，but has in white list", 1)
			}
		} else {
			for i := range msgs {
				// 在线监控不可能会阻断，所以这里改一下文案
				msgs[i].KVHash.ZH.Value = strings.Replace(msgs[i].KVHash.ZH.Value, "被阻断", "按策略应该被阻断", 1)
				msgs[i].KVHash.EN.Value = strings.Replace(msgs[i].KVHash.EN.Value, ",blocked", ",should be blocked by reject policy", 1)
			}
		}
	}
	return safe, records, msgs, nil
}

// checkBaseImage 是否是基础镜像构建的应用
func (s *ConScannerSrv) checkBaseImage(ctx context.Context, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("start  checkBaseImage imag Id:" + strconv.Itoa(int(img.ID)))
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	images, _, err := s.ListBaseImageOfApp(ctx, img.ID, nil)
	if len(images) > 0 {
		logging.GetLogger().Info().Msgf("checkBaseImage find base image:%s/%s:%s,imagID:%d", images[0].Library, images[0].FullRepoName, images[0].Tags, images[0].ID)
		return true, records, msgs
	}

	if len(images) == 0 || err != nil {
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("checkBaseImage find base image error, imag Id:" + strconv.Itoa(int(img.ID)))
		}

		logging.GetLogger().Info().Msgf("checkBaseImage can not find base image imag Id:" + strconv.Itoa(int(img.ID)))

		msgZh := "非基础镜像构建的应用镜像"
		msgEN := "The application image is not built with a verified base image"
		msgLog := fmt.Sprintf("image:%s/%s:%s untrusted base image", img.Library, img.FullRepoName, img.Tags)

		switch po.BaseImagePolicy {
		case model.RejectPolicyReject:
			safe = false
			records = append(records, ReasonAndDetail{
				RejectReason: model.RejectReasonUntrustedBaseImage,
				RejectDetail: msgZh,
			})

			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedBaseImage], msgZh+"，被阻断"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonUntrustedBaseImage], msgEN+",blocked")}})
			logging.GetLogger().Info().Msgf(" %s,has blocked", msgLog)

		case model.RejectPolicyAlarm:
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedBaseImage], msgZh+"，未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonUntrustedBaseImage], msgEN+",unblocked,just alert")}})
			logging.GetLogger().Info().Msgf("%s,not blocked,only send messages to the event center", msgLog)
		}
	}
	return safe, records, msgs
}

// checkWebshell 检查websell的扫描结果
func (s *ConScannerSrv) checkWebshell(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msg("checkWebshell,start ")
	logging.GetLogger().Info().Msgf("CICD checkWebshell, imageid:%d,websell policy  is:%s,webshell has :%d", img.ID, po.WebShellPolicy, len(scanImage.WebshellInfo))

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	webshellFile := make([]string, 0)
	for i := range scanImage.WebshellInfo {
		if po.WebShellScore > 0 && scanImage.WebshellInfo[i].WebShellInfo.Score > po.WebShellScore {
			webshellFile = append(webshellFile, scanImage.WebshellInfo[i].WebShellInfo.FileName)
		}
	}
	if len(webshellFile) > 0 {
		msgZh := fmt.Sprintf("包含webshell文件：%s，高于阻断评分：%d", strings.Join(webshellFile, "，"), po.WebShellScore)
		msgEN := fmt.Sprintf("include websell file:%s  more than:%d", strings.Join(webshellFile, ","), po.WebShellScore)
		switch po.WebShellPolicy {
		case model.RejectPolicyAlarm:
			logging.GetLogger().Info().Msgf(fmt.Sprintf("include webshell than the config, %s, unblocked,just alert", msgEN))
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonWebshellScore], msgZh+"，未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonWebshellScore], msgEN+",unblocked,just alert")}})

		case model.RejectPolicyReject:
			safe = false
			msgLog := fmt.Sprintf("Image:%s/%s:%s  more than:%d", img.Library, img.FullRepoName, img.Tags, po.WebShellScore)
			logging.GetLogger().Info().Msgf("include webshell than the config,%s，被阻断", msgLog)
			records = append(records, ReasonAndDetail{
				RejectReason: model.RejectReasonWebshellScore,
				RejectDetail: msgZh,
				VulnScore:    po.VulnScore,
			})
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonWebshellScore], msgZh+"，被阻断"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonWebshellScore], msgEN+",blocked")}})
		}
	}

	return safe, records, msgs
}

// checkInWhitelist 检测白名单
func (s *ConScannerSrv) checkWhitelist(ctx context.Context, img *model.ImageList, usePattern string) (bool, error) {
	logging.GetLogger().Info().Msgf("checkWhitelist checking whitelist: %s%s:%s, Digest:%s", img.Library, img.FullRepoName, img.Tags, img.Digest)
	param := store.SearchImageWhitelistParam{
		Library:      img.Library,
		FullRepoName: img.FullRepoName,
		Tag:          img.Tags,
	}

	wl, _, err := s.dbdal.SearchImageWhitelist(ctx, param, nil)
	if err != nil {
		logging.GetLogger().Info().Msgf("checkWhitelist checking whitelist error:%s/%s:%s,Digest:%s", img.Library, img.FullRepoName, img.Tags, img.Digest)
		return false, err
	}

	if len(wl) > 0 {
		logging.GetLogger().Info().Msgf("checkWhitelist image：%s/%s:%s,Digest:%s， Hit the reject policy ，but the image in whitelist,not block", img.Library, img.FullRepoName, img.Tags, img.Digest)
		return true, nil
	}
	logging.GetLogger().Info().Msgf("checkWhitelist image：%s/%s:%s，Hit the reject policy，not find image in whitelist", img.Library, img.FullRepoName, img.Tags)
	return false, nil
}

// 未找到扫描结果时拼装消息和阻断记录 拼装数据
func (s *ConScannerSrv) checkScanImageExist(ctx context.Context, usePattern string, img *model.ImageList, po model.RejectPolicy) (checkSanImageRes, error) {
	res := checkSanImageRes{
		Safe:    true,
		Records: make([]ReasonAndDetail, 0),
		Msg:     make([]model.KVHashs, 0),
	}

	scanImage, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{img.ID}, Status: model.ScanStatusSucceeded}, nil)
	if err != nil {
		res.Safe = false
		logging.GetLogger().Info().Msgf("checkScanImageExist search scan_image: %d, error: %s", img.ID, err.Error())
		return res, err
	}

	if len(scanImage) > 0 {
		res.ScanImag = &scanImage[0]
		return res, nil
	}

	logging.GetLogger().Info().Msgf("checkScanImageExist not fond scan-image:%s/%s:%s", img.Library, img.FullRepoName, img.Tags)
	if usePattern == model.UsePatternForCICD {
		// msgZh := fmt.Sprintf("镜像：%s/%s:%s 扫描失败", img.Library, img.FullRepoName, img.Tags)
		msgZh := "扫描失败"
		msgLog := fmt.Sprintf("image:%s/%s:%s scan failure", img.Library, img.FullRepoName, img.Tags)
		msgEN := "scan failure"
		logging.GetLogger().Info().Msgf(msgLog)

		res.Safe = false
		res.Records = append(res.Records, ReasonAndDetail{
			RejectReason: model.RejectScanFailure,
			RejectDetail: msgZh,
		})

		res.Msg = append(res.Msg, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectScanFailure], msgZh),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectScanFailure], msgEN)}})
	} else if usePattern == model.UsePatternForK8s {
		// 其他都认为安全
		if po.Mode == model.RejectPolicySafeModel {
			msgZh := "镜像未扫描，被阻断"
			msgEN := "image not scanned blocked"
			msgLog := fmt.Sprintf("image:%s/%s:%s not scanned,blocked", img.Library, img.FullRepoName, img.Tags)
			res.Safe = false
			logging.GetLogger().Info().Msgf(msgLog)
			res.Records = append(res.Records, ReasonAndDetail{
				RejectReason: model.RejectScanNotScanned,
				RejectDetail: msgZh,
			})

			res.Msg = append(res.Msg, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectScanFailure], msgZh),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectScanFailure], msgEN)}})
		}
	}
	return res, nil
}

// 未找到镜像
func (s *ConScannerSrv) checkImageExist(ctx context.Context, usePattern string, img *model.ImageList) checkImageRes {
	res := checkImageRes{
		Safe:    true,
		Records: make([]ReasonAndDetail, 0),
		Msg:     make([]model.KVHashs, 0),
	}
	// 通过library+fullreponame+tag的方式去查询
	img1, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Libraries: []string{img.Library, "https://" + img.Library, "http://" + img.Library}, FullRepoName: img.FullRepoName, Tag: img.Tags}, nil)
	if err != nil || len(img1) == 0 {
		res.Safe = false
		if err != nil {
			logging.GetLogger().Err(err).Msgf("%s search image：%s/%s:%s", usePattern, img.Library, img.FullRepoName, img.Tags)
		}
		msgZh := "未查到对应镜像"
		msgLog := fmt.Sprintf("checkImageExist image:%s%s:%s no image found", img.Library, img.FullRepoName, img.Tags)
		msgEN := "not found image"

		logging.GetLogger().Info().Msgf(msgLog)
		res.Msg = append(res.Msg, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectScanFailure], msgZh),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectScanFailure], msgEN)}})
		return res
		// 如果需要，加阻断记录
	}
	res.Image = &img1[0]
	return res
}

func (s *ConScannerSrv) checkMaliciousInfo(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("start checkMaliciousInfo, imageid:%d malic police is %s,malic:%d", img.ID, po.MaliciousPolicy, len(scanImage.MaliciousInfo))
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	//  验证恶意文件
	if len(scanImage.MaliciousInfo) > 0 {
		logging.GetLogger().Info().Msgf("contains malicious files, imag Id:" + strconv.Itoa(int(img.ID)))

		msgZh := "存在恶意文件"
		msgEN := "contains malicious file"
		msgLog := fmt.Sprintf("image:%s%s:%s contains malicious file", img.Library, img.FullRepoName, img.Tags)

		switch po.MaliciousPolicy {
		case model.RejectPolicyReject:
			safe = false
			records = append(records, ReasonAndDetail{
				RejectReason: model.RejectReasonHasMalicious,
				RejectDetail: msgZh,
			})

			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasMalicious], msgZh+"，被阻断"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasMalicious], msgEN+",blocked")}})
			logging.GetLogger().Info().Msgf(" %s,has blocked", msgLog)

		case model.RejectPolicyAlarm:
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasMalicious], msgZh+"，未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasMalicious], msgEN+",unblocked,just alert")}})
			logging.GetLogger().Info().Msgf("%s,not blocked,only send messages to the event center", msgLog)
		}
	}

	return safe, records, msgs
}

func (s *ConScannerSrv) checkSensitiveFile(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("CICD checkSensitiveFile, imageid:%d,Sensitive policy  is:%s, custom Sensitive police is %+v, Sensitive is :%d", img.ID, po.SensitiveFilePolicy, po.SensitiveFile, len(scanImage.SensitiveFile))

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	rejectSensFile := make([]string, 0)
	alterFile := make([]string, 0)
	exist := make(map[string]bool)
	// 验证敏感文件
	// 自定义敏感文件
	for i := range scanImage.SensitiveFile {
		for j := range po.SensitiveFile {
			if MatchSuffix(scanImage.SensitiveFile[i].Name, po.SensitiveFile[j].Key) {
				exist[scanImage.SensitiveFile[i].Name] = true
				if po.SensitiveFile[j].Policy == model.RejectPolicyReject {
					safe = false
					rejectSensFile = append(rejectSensFile, scanImage.SensitiveFile[i].Name)
				} else if po.SensitiveFile[j].Policy == model.RejectPolicyAlarm {
					alterFile = append(alterFile, scanImage.SensitiveFile[i].Name)
				}
				continue
			}
		}
		if !exist[scanImage.SensitiveFile[i].Name] {
			switch po.SensitiveFilePolicy {
			case model.RejectPolicyReject:
				safe = false
				rejectSensFile = append(rejectSensFile, scanImage.SensitiveFile[i].Name)
			case model.RejectPolicyAlarm:
				alterFile = append(alterFile, scanImage.SensitiveFile[i].Name)
			}
		}
	}

	logging.GetLogger().Info().Msgf("Contains sensitive files, imag Id:" + strconv.Itoa(int(img.ID)))
	msgZh := "存在敏感文件"
	msgEN := "contain sensitive file"
	msgLog := fmt.Sprintf("Image:%s/%s:%s Contains sensitive file", img.Library, img.FullRepoName, img.Tags)

	if len(rejectSensFile) > 0 {
		msgZh = fmt.Sprintf("%s:%s", msgZh, strings.Join(rejectSensFile, ","))
		msgEN = fmt.Sprintf("%s:%s", msgEN, strings.Join(rejectSensFile, ","))

		records = append(records, ReasonAndDetail{
			RejectReason: model.RejectReasonHasSensitiveFile,
			RejectDetail: msgZh,
		})

		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile], msgZh+"，被阻断"),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasSensitiveFile], msgEN+",unblocked,just alert")}})

		logging.GetLogger().Info().Msgf("%s,has blocked", msgLog)
	}

	if len(alterFile) > 0 {
		msgZh := fmt.Sprintf("%s:%s", msgZh, strings.Join(alterFile, ","))
		msgEN := fmt.Sprintf("%s:%s", msgEN, strings.Join(alterFile, ","))
		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile], msgZh+",未阻断，只告警"),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasSensitiveFile], msgEN+",unblocked,just alert")}})
		logging.GetLogger().Info().Msgf("%s,not blocked, only send messages to the event center", msgLog)
	}

	return safe, records, msgs
}

func (s *ConScannerSrv) checkCustomizeVulu(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("CICD checkCustomizeVulu, imageid:%d,customizeVulu policy  is:%+v,vulu has :%d", img.ID, po.RejectVulns, len(scanImage.VulnInfo))

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	customizeVuluMap := make(map[string]model.RejectVuln)
	for i := range po.RejectVulns {
		customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
	}
	cusBlockVluns := make([]string, 0)
	cusAlertVluns := make([]string, 0)
	respVuln := FilterVulnsFromScanImage(scanImage.VulnInfo)
	for _, vu := range respVuln {
		// 自定义漏洞规则
		if svn, ok := customizeVuluMap[vu.CVEID]; ok {
			logging.GetLogger().Info().Msgf("Contains custom vulnerabilities, imag Id:" + strconv.Itoa(int(img.ID)))

			switch svn.RejectPolicy {
			case model.RejectPolicyReject:
				cusBlockVluns = append(cusBlockVluns, vu.CVEID)
				safe = false
			case model.RejectPolicyAlarm:
				cusAlertVluns = append(cusAlertVluns, vu.CVEID)
			}
		}
	}
	// 组装消息
	cusVuluZH, cusVuluEN := "", ""
	if len(cusBlockVluns) > 0 {
		cusVuluZH = fmt.Sprintf("包含自定义漏洞：%s，被阻断", strings.Join(cusBlockVluns, "，"))
		cusVuluEN = fmt.Sprintf("contain custom vulnerability:%s,blocked", strings.Join(cusBlockVluns, ","))
	}
	if cusVuluEN != "" && cusVuluZH != "" && len(cusAlertVluns) > 0 {
		cusVuluEN = cusVuluEN + ","
		cusVuluZH = cusVuluZH + "，"
	}

	if len(cusAlertVluns) > 0 {
		cusVuluZH = fmt.Sprintf("%s包含自定义漏洞：%s，未阻断，只告警", cusVuluZH, strings.Join(cusAlertVluns, "，"))
		cusVuluEN = fmt.Sprintf("%scontain custom vulnerability:%s,unblocked,just alert", cusVuluEN, strings.Join(cusAlertVluns, ","))
	}

	if cusVuluEN != "" && cusVuluZH != "" {
		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasCustomizeVulu], cusVuluZH),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasCustomizeVulu], cusVuluEN)}})

		records = append(records, ReasonAndDetail{
			RejectReason: model.RejectReasonHasCustomizeVulu,
			RejectDetail: cusVuluZH,
		})

		logging.GetLogger().Info().Msgf(fmt.Sprintf("has custom vulnerability, %s", cusVuluEN))
	}
	return safe, records, msgs
}

func (s *ConScannerSrv) checkVulnSeverity(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("CICD checkVulnSeverity, imageid:%d,vulu policy is:%s ,vulnSeverity is :%d ,vulu has :%d", img.ID, po.VulnPolicy, po.VulnScore, len(scanImage.VulnInfo))

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	customizeVuluMap := make(map[string]model.RejectVuln)
	for i := range po.RejectVulns {
		customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
	}
	vumMap := make(map[string][]string)
	respVuln := FilterVulnsFromScanImage(scanImage.VulnInfo)
	for _, vu := range respVuln {
		if _, ok := customizeVuluMap[vu.CVEID]; ok {
			continue
		}
		// 如果配置了漏洞评级
		if po.VulnLevel != "" && compareSeverity(vu.Trivy[0].Severity, po.VulnLevel) {
			if vumMap[vu.Trivy[0].Severity] == nil {
				vumMap[vu.Trivy[0].Severity] = make([]string, 0)
			}
			vumMap[vu.Trivy[0].Severity] = append(vumMap[vu.Trivy[0].Severity], vu.CVEID)
		}
	}
	for level, vuns := range vumMap {
		if len(vuns) > 0 {
			zh := fmt.Sprintf("包含漏洞：%s，评级：%s，高于漏洞阻断评级：%s", strings.Join(vuns, "，"), level, po.VulnLevel)
			en := fmt.Sprintf("include Vulnerability:%s Rate:%s, more than:%s", strings.Join(vuns, ","), level, po.VulnLevel)

			logging.GetLogger().Info().Msgf(fmt.Sprintf("vulnerability severity than the config, %s, blocked", en))

			switch po.VulnPolicy {
			case model.RejectPolicyAlarm:
				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.GetVuluRuleKey(level, model.LangZh), zh+"，未阻断，只告警"),
						EN: model.NewKeyValue(model.GetVuluRuleKey(level, model.LangEn), en+",unblocked,just alert")}})
			case model.RejectPolicyReject:
				safe = false
				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.GetVuluRuleKey(level, model.LangZh), zh+"，被阻断"),
						EN: model.NewKeyValue(model.GetVuluRuleKey(level, model.LangEn), en+",blocked")}})

				records = append(records, ReasonAndDetail{
					RejectReason: model.GetSeverityRejectReason(level),
					RejectDetail: zh,
					VulnLevel:    po.VulnLevel,
				})
			}
		}
	}

	return safe, records, msgs
}

func (s *ConScannerSrv) checkVulnScore(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("CICD checkVulnScore, imageid:%d,vulnScore policy  is:%s,vulnScore is :%g", img.ID, po.VulnPolicy, scanImage.VulnScore)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	customizeVuluMap := make(map[string]model.RejectVuln)
	for i := range po.RejectVulns {
		customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
	}
	//  如果配置了漏洞分数,
	ans := CalculateVulnScore(scanImage, customizeVuluMap)
	if po.VulnScore > 0 && int64(ans) < po.VulnScore {
		msgZh := fmt.Sprintf("漏洞综合评分：%d，低于阻断分数：%d", ans, po.VulnScore)
		msgEN := fmt.Sprintf("vulnerability rate %d,Lower than:%d", ans, po.VulnScore)
		msgLog := fmt.Sprintf("Image:%s/%s:%s rate %d Lower than:%d", img.Library, img.FullRepoName, img.Tags, ans, po.VulnScore)
		logging.GetLogger().Info().Msgf("vulnerability score than the config，%s，被阻断", msgLog)

		switch po.VulnPolicy {
		case model.RejectPolicyAlarm:
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonVuluScore], msgZh+"，未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonVuluScore], msgEN+",unblocked,just alert")}})
		case model.RejectPolicyReject:
			safe = false
			records = append(records, ReasonAndDetail{
				RejectReason: model.RejectReasonVuluScore,
				RejectDetail: msgZh,
				VulnScore:    po.VulnScore,
			})
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonVuluScore], msgZh+",被阻断"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonVuluScore], msgEN+",blocked")}})
		}
	}
	return safe, records, msgs
}

// DeleteCICDImage 定期删除cicd仓库的镜像
func (s *ConScannerSrv) DeleteCICDImage(ctx context.Context) {
	regs, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{UseType: model.RegistryUseTypeCICDBuff}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD find BuffRegistry error")
		return
	}
	if len(regs) == 0 {
		logging.GetLogger().Err(err).Msgf("CICD not find BuffRegistry ")
		return
	}
	logging.GetLogger().Info().Msgf("CICD find BuffRegistry registry: %s", regs[0].Url)
	drive, err := s.getRegistry(ctx, "", model.RegistryUseTypeCICDBuff)

	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD connect BuffRegistry :%s", regs[0].Url)
		return
	}
	// 先查询镜像，然后一个一个的删除
	images, err := drive.ListImages(func(image registry.Image) (*registry.ListImagesRes, error) {
		logging.GetLogger().Info().Msgf("CICD  deleteCICDImage search image in %s", image.Repository)
		return nil, nil
	}, registry.ListImagesRequest{NeedToReturnAll: true})
	if err != nil {
		logging.GetLogger().Info().Msgf("CICD asynchronously delete BuffRegistry image error: %s", err.Error())
		return
	}
	for i := range images.All {
		if err := drive.DeleteImages("", images.All[i].FullRepoName, images.All[i].Digest); err != nil {
			logging.GetLogger().Info().Msgf("CICD asynchronous delete  BuffRegistry image error: %s", err.Error())
		} else {
			logging.GetLogger().Info().Msgf("CICD asynchronous delete BuffRegistry image :%s", images.All[i].FullRepoName)
		}
	}

	// 启动GC
	logging.GetLogger().Info().Msg("deleteCICDImage start GC")
	split := strings.Split(regs[0].Url, ":")

	if len(split) <= 2 {
		logging.GetLogger().Info().Msgf("deleteCICDImage url parse error url:%s", regs[0].Url)
		return
	}
	port := os.Getenv("REGISTRY_GC_PORT") // 以环境变量的方式取值
	if port == "" {
		port = "8081"
	}

	url := fmt.Sprintf("%s:%s:%s/api/registry/gc", split[0], split[1], port)
	logging.GetLogger().Info().Msgf("deleteCICDImage NewRequest url:%s", url)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("deleteCICDImage NewRequest,url:%s", url)
		return
	}
	timeOutCtx, cancelFunc := context.WithTimeout(ctx, time.Minute*2)
	defer cancelFunc()

	resp, err := http.DefaultClient.Do(req.WithContext(timeOutCtx))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("deleteCICDImage NewRequest,url:%s", url)
		return
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode >= http.StatusMultipleChoices || resp.StatusCode < http.StatusOK {
		logging.GetLogger().Error().Err(err).Msgf("deleteCICDImage StatusCode not 200,url:%s", url)
		return
	}
	by, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("deleteCICDImage parse ")
		return
	}
	type body struct {
		Status bool `json:"status"`
	}
	bd := new(body)
	if err := json.Unmarshal(by, bd); err != nil || !bd.Status {
		logging.GetLogger().Error().Err(err).Msg("deleteCICDImage This call failed to clean up the storage")
		return
	}
	logging.GetLogger().Info().Msg("deleteCICDImage success GC")
}

func (s *ConScannerSrv) GetImageLibraryNameTag(imageName string) (*model.ImageList, error) {

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, err
	}

	repo := ref.Context()

	registryStr := repo.RegistryStr()

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()

	img := &model.ImageList{
		Tags:         tag,
		FullRepoName: repositoryName,
		Library:      registryStr,
	}
	return img, nil
}

func (s *ConScannerSrv) CreateSafeReject(ctx context.Context, ImageList model.ImageList, msgType string, reason int64, detail string, coninfo model.RejectOnlineMonitorImage) {
	defaultKvHash := model.KVHash{}
	defaultKvHash.ZH.Key = "镜像来源仓库非法"
	defaultKvHash.ZH.Value = "模式:安全模式 镜像：" + ImageList.Library + "/" + ImageList.FullRepoName + ":" + ImageList.Tags
	tmpHashs := []model.KVHashs{}
	tmpHash := model.KVHashs{}
	tmpHash.KVHash = defaultKvHash
	tmpHashs = append(tmpHashs, tmpHash)
	img := ImageList
	tmpReasonAndDetail := ReasonAndDetail{}
	tmpReasonAndDetail.RejectReason = reason
	tmpReasonAndDetail.RejectDetail = detail + " 原始信息为:" + ImageList.Library + "/" + ImageList.FullRepoName + ":" + ImageList.Tags
	tmpReasonAndDetails := []ReasonAndDetail{}
	tmpReasonAndDetails = append(tmpReasonAndDetails, tmpReasonAndDetail)
	if msgType == consts.AlertKindK8s {
		res := mergeRejectRecord(img, tmpReasonAndDetails)
		if _, err := s.dbdal.CreateRejectRecord(ctx, res); err != nil {
			logging.GetLogger().Err(err).Msgf("CICD store reject_record error %s", err.Error())
		}
	}
	if len(tmpHashs) > 0 {
		notify := model.NotifyContext{
			ServiceID: fmt.Sprintf("%s/%s:%s(image)", ImageList.Library, ImageList.FullRepoName, ImageList.Tags),
			CustomKV:  tmpHashs,
		}

		notify.PodName = coninfo.NotifyContext.PodName
		notify.PodUID = coninfo.NotifyContext.PodUID
		notify.Cluster = coninfo.NotifyContext.Cluster
		notify.Namespace = coninfo.NotifyContext.Namespace
		notify.CustomKV = append(notify.CustomKV, coninfo.NotifyContext.CustomKV...)
		notify.CustomKV = append(notify.CustomKV, model.KVHashs{KVHash: model.KVHash{
			EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
			ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
		}})

		msg := model.NewReqBody(
			model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity),
			notify,
			generateUUID(img, msgType, consts.EventIntervalUUID),
		)
		if err := sendMsgToEventCenter(ctx, msg); err != nil {
			logging.GetLogger().Err(err).Msgf("send msg to event center error:%s", err.Error())
		}
	}
}

func (s *ConScannerSrv) DetectImageForK8s(ctx context.Context, img *model.ImageList) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("K8sDeployDetect,start DetectImage,imageId：%d, policeReg: %s", img.ID, img.Library)
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	// todo @liuqiang 这块查询逻辑是否可以去除
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{img.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect,find the img :%d,error", img.ID)
		return false, records, msgs, err
	}
	// 如果没有在数据库没有查到镜像，默认不安全
	if len(imgs) == 0 {
		logging.GetLogger().Info().Msgf("K8sDeployDetect,not find the img:%d", img.ID)
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("K8sDeployDetect,没有查到对应镜像:%d", img.ID))
	}

	img = &imgs[0]

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect library:%s get global reject policy error", img.Library)
		return false, records, msgs, err
	}
	if len(globalReg) == 0 {
		logging.GetLogger().Info().Msgf("K8sDeployDetect library:%s not find global policy", img.Library)
		return true, records, msgs, nil
	}

	if !globalReg[0].K8sEnable {
		logging.GetLogger().Info().Msgf("K8sDeployDetect library:%s global reject is not enable ", img.Library)
		return true, records, msgs, nil
	}

	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Library: img.Library, Global: consts.FalseString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect library:%s get reject policy error", img.Library)
		return true, records, msgs, err
	}

	if len(policies) == 0 { // 没有策略说明不检测，默认全安全
		logging.GetLogger().Info().Msgf("K8sDeployDetect library:%s has no reject policy, all safe by default", img.Library)
		return true, records, msgs, nil
	}
	scanImageRes, err := s.checkScanImageExist(ctx, model.UsePatternForK8s, img, policies[0])
	if err != nil {
		logging.GetLogger().Info().Msgf("K8sDeployDetect search scan_image: %d, error: %s", img.ID, err.Error())
		return false, records, msgs, err
	}
	records = append(records, scanImageRes.Records...)
	msgs = append(msgs, scanImageRes.Msg...)

	if !scanImageRes.Safe {
		safe = scanImageRes.Safe
	}

	if scanImageRes.ScanImag != nil {
		scanImage := *scanImageRes.ScanImag
		for _, po := range policies {
			if !po.Enable || po.IsGlobal {
				logging.GetLogger().Info().Msgf("K8sDeployDetect reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}
			logging.GetLogger().Info().Msgf("K8sDeployDetect reject policy is enable :name:%s,ID:%d,police is %+v", po.Name, po.ID, po)

			// 恶意文件
			sa1, red1, ms1 := s.checkMaliciousInfo(ctx, scanImage, img, po)
			// 敏感文件
			sa2, red2, ms2 := s.checkSensitiveFile(ctx, scanImage, img, po)
			// 漏洞评分
			sa3, red3, ms3 := s.checkVulnScore(ctx, scanImage, img, po)
			// 自定义漏洞规则
			sa4, red4, ms4 := s.checkCustomizeVulu(ctx, scanImage, img, po)
			// 漏洞评级
			sa5, red5, ms5 := s.checkVulnSeverity(ctx, scanImage, img, po)
			// webshell
			sa6, red6, ms6 := s.checkWebshell(ctx, scanImage, img, po)

			sa9, red9, ms9 := s.checkEnv(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 || !sa9 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6, red9)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6, ms9)...)
		}
	}
	// 检查基础镜像
	for _, po := range policies {
		if !po.Enable || !po.K8sEnable || po.IsGlobal {
			logging.GetLogger().Info().Msgf("K8sDeployDetect reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
			continue
		}
		sa6, red6, ms6 := s.checkBaseImage(ctx, img, po)
		if !sa6 {
			safe = false
		}
		records = append(records, red6...)
		msgs = append(msgs, ms6...)

		// 可信镜像
		sa7, red7, ms7 := s.checkTrustedImage(ctx, img, po)
		if !sa7 {
			safe = false
		}

		records = append(records, red7...)
		msgs = append(msgs, ms7...)

		// 特权账户
		sa8, red8, ms8 := s.checkPrivilegedBoot(ctx, img, po)
		if !sa8 {
			safe = false
		}

		records = append(records, red8...)
		msgs = append(msgs, ms8...)
	}
	logging.GetLogger().Info().Msgf("K8sDeployDetect:checkBaseImage ... digest: %s, safe:%t: msg:%d,records:%d", img.Digest, safe, len(msgs), len(records))

	// 检查白名单,K8s不检查Digest
	// 镜像存在白名单中，只是不阻断，任然要进行扫描检测，对检测结果仍然要发事件中心
	if !safe {
		if in, _ := s.checkWhitelist(ctx, img, model.UsePatternForK8s); in {
			safe = true
			for i := range msgs {
				msgs[i].KVHash.ZH.Value = strings.Replace(msgs[i].KVHash.ZH.Value, "被阻断", "但镜像已加入白名单中，未被阻断", 1)
				msgs[i].KVHash.EN.Value = strings.Replace(msgs[i].KVHash.EN.Value, ",blocked", ",but img has add to the whitelist,unblocked", 1)
			}
		}
	}
	return safe, records, msgs, nil
}

func (s *ConScannerSrv) GetScanTaskList(ctx context.Context, limit, offset int64) ([]*model.Task, int64, error) {
	data, count, err := s.dbdal.GetTaskList(ctx, int(limit), int(offset))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取扫描任务记录失败, limit: %d, offset: %d", limit, offset)
		return nil, 0, err
	}

	return data, count, nil
}

func (s *ConScannerSrv) GetScanSubTaskList(ctx context.Context, taskID, limit, offset int64) ([]model.SubTask, int64, error) {

	data, count, err := s.dbdal.GetSubTaskListWithImage(ctx, taskID, int(limit), int(offset))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取扫描子任务记录失败, taskId: %d, limit: %d, offset: %d", taskID, limit, offset)
		return nil, 0, err
	}

	return data, count, nil
}

func (s *ConScannerSrv) UpdateScanTaskStatus(ctx context.Context, taskID int64, status uint8) error {
	if status < consts.Pending || status > consts.Terminate {
		logging.GetLogger().Error().
			Int64("taskId", taskID).
			Uint8("status", status).
			Msg("update task status err")
		return fmt.Errorf("invailed status enum: %d", status)
	}

	err := s.dbdal.UpdateTaskStatus(ctx, taskID, status)
	if err != nil {
		logging.GetLogger().Err(err).
			Int64("taskId", taskID).
			Uint8("status", status).
			Msg("update task status err")
		return errors.Wrapf(err, "更新任务%d的状态为%d失败", taskID, status)
	}

	if status == consts.Terminate {
		// update pending subtask to terminated status
		search := store.SearchSubTaskParam{
			TaskIds:  []int64{taskID},
			Statuses: []int{consts.ImageScanPending},
		}
		updateInfo := make(map[string]interface{})
		updateInfo["status"] = consts.ImageNotScan
		err := s.dbdal.UpdateSubTasksInfo(ctx, search, updateInfo)
		if err != nil {
			logging.GetLogger().Err(err).
				Int64("taskId", taskID).
				Uint8("status", status).
				Msg("update subtask status to terminated err")
			return errors.Wrapf(err, "更新子任务%d的状态为%d失败", taskID, consts.ImageNotScan)
		}
	}

	return nil
}

func (s *ConScannerSrv) ScanReportCreate(ctx context.Context, data *scanreport.TensorScanReportTasks) (uint, error) {
	if err := data.CheckValid(); err != nil {
		logging.GetLogger().Err(err).Msgf("创建扫描报告时，数据校验失败，name:%s", data.Name)
		return 0, err
	}

	if data.Type == scanreport.TensorScanReportTypeCustomize {
		data.SubTaskType = scanreport.SubTaskTypeOnce
	} else {
		data.SubTaskType = scanreport.SubTaskTypeCircle
	}

	id, err := s.dbdal.Create(ctx, data)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("创建扫描报告时, 插入数据失败，name:%s", data.Name)

		if strings.Contains(err.Error(), "duplicate") {
			return 0, fmt.Errorf("名字:<%s>已存在", data.Name)
		}

		return 0, errors.New("新增失败")
	}
	return id, nil
}

func (s *ConScannerSrv) ScanReportUpdate(ctx context.Context, data *scanreport.TensorScanReportTasks) error {
	if err := data.CheckValid(); err != nil {
		logging.GetLogger().Err(err).Msgf("更新扫描报告时，数据校验失败，name:%s", data.Name)
		return err
	}

	if data.Type == scanreport.TensorScanReportTypeCustomize {
		return errors.New("自定义任务无法修改")
	}
	data.SubTaskType = scanreport.SubTaskTypeCircle

	if err := s.dbdal.Update(ctx, data); err != nil {
		logging.GetLogger().Err(err).Msgf("更新扫描报告时, 更新数据失败，name:%s", data.Name)
		if strings.Contains(err.Error(), "duplicate") {
			return fmt.Errorf("名字:<%s>已存在", data.Name)
		}

		return errors.New("新增失败")
	}
	return nil
}

func (s *ConScannerSrv) ScanReportList(ctx context.Context, keyword string, limit, offset int, _type []uint8) ([]scanreport.TensorScanReportTasks, int64, error) {
	data, count, err := s.dbdal.List(ctx, keyword, limit, offset, _type)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取扫描报告列表失败，keyword:%s, limit:%d, offset:%d", keyword, limit, offset)
		return nil, 0, err
	}

	return data, count, nil
}

func (s *ConScannerSrv) ScanReportDetail(ctx context.Context, id uint) (*scanreport.TensorScanReportTasks, error) {
	data, err := s.dbdal.Detail(ctx, id)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取扫描报告详情失败，id: %d", id)
		return nil, err
	}

	return data, nil
}

func (s *ConScannerSrv) ScanReportDelete(ctx context.Context, id uint) error {
	err := s.dbdal.Delete(ctx, id)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("删除扫描报告失败，id: %d", id)
		return err
	}

	return nil
}

func (s *ConScannerSrv) ScanReportFiles(ctx context.Context, id uint, limit, offset int) ([]scanreport.TensorScanReportSubTasks, int64, error) {
	data, count, err := s.dbdal.FilesList(ctx, id, limit, offset)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取扫描报告文件列表失败，id:%d, limit:%d, offset:%d", id, limit, offset)
		return nil, 0, err
	}

	return data, count, nil
}

func (s *ConScannerSrv) ScanReportDownload(ctx context.Context, taskID, subTaskID uint) (*scanreport.ScanReportResult, error) {
	r, err := s.dbdal.Download(ctx, taskID, subTaskID)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("查询扫描报告文件失败，taskId:%d, subTask:%d", taskID, subTaskID)
		return nil, errors.Wrap(err, "查询扫描报告文件失败")
	}

	result := &scanreport.ScanReportResult{
		Data: &scanreport.ScanReportResultData{
			Images:     []*scanreport.Image{},
			ImageVulns: []*scanreport.ImageVuln{},
		},
	}

	data, err := compress.ZlipDecompress(r.File)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("解压数据失败，taskId:%d, subTask:%d", taskID, subTaskID)
		return nil, errors.Wrap(err, "解压数据失败")
	}
	err = result.Unmarshal(data)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("序列化扫描报告文件失败，taskId:%d, subTask:%d", taskID, subTaskID)
		return nil, errors.Wrap(err, "序列化扫描报告文件失败")
	}

	return result, nil
}

func (s *ConScannerSrv) ScanReportGenerate(ctx context.Context, taskID uint) (uint, error) {
	data, err := s.dbdal.Detail(ctx, taskID)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("立即生成失败，查询任务详情失败，taskId:%d", taskID)
		return 0, errors.New("查询任务详情失败")
	}

	if data.Type == scanreport.TensorScanReportTypeCustomize {
		return 0, errors.New("自定义任务不能立即生成")
	}

	data.SubTaskType = scanreport.SubTaskTypeOnce
	subtask := data.GenSubtask()
	subtask.ScanReportId = data.ID
	id, err := s.dbdal.SubTaskCreate(ctx, subtask)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("立即生成失败，生成子任务失败，taskId:%d", taskID)
		return 0, errors.New("生成子任务失败")
	}
	return id, nil
}

// 检查是否为可信镜像
func (s *ConScannerSrv) checkTrustedImage(ctx context.Context, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Debug().Msgf("checkTrustedImage, image digest: %s, PrivilegedBootPolicy: %s", img.Digest, po.PrivilegedBootPolicy)
	r, err := s.dbdal.SearchTrustedImages(ctx, store.SearchTrustedImageParam{Digests: []string{img.Digest}})
	if err == nil && len(r) > 0 && r[0].IsTrusted == 1 {
		return true, nil, nil
	}

	if err != nil {
		logging.GetLogger().Err(err).Msgf("获取digest<%s>的可信信息失败", img.Digest)
	}

	var reasonAndDetail []ReasonAndDetail
	var kv []model.KVHashs
	var safe = true

	var zhMsg = model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedImage]
	var enMsg = model.GetRejectReason(model.LangEn)[model.RejectReasonUntrustedImage]

	switch po.TrustedImagePolicy {
	case model.RejectPolicyReject:
		safe = false
		reasonAndDetail = []ReasonAndDetail{
			{
				RejectReason: model.RejectReasonUntrustedImage,
				RejectDetail: zhMsg,
			},
		}

		kv = []model.KVHashs{
			{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(zhMsg, zhMsg+"，被阻断"),
					EN: model.NewKeyValue(enMsg, enMsg+",blocked"),
				},
			},
		}

		logging.GetLogger().Info().Msgf("镜像<%s>不可信，被阻断", img.Digest)
	case model.RejectPolicyAlarm:
		kv = []model.KVHashs{
			{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(zhMsg, zhMsg+"，未阻断，只告警"),
					EN: model.NewKeyValue(enMsg, enMsg+",unblocked,just alert"),
				},
			},
		}
		logging.GetLogger().Info().Msgf("镜像<%s>不可信，告警不阻断", img.Digest)
	}

	return safe, reasonAndDetail, kv
}

// 检查是否为特权启动
func (s *ConScannerSrv) checkPrivilegedBoot(ctx context.Context, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Debug().Msgf("checkPrivilegedBoot, image digest: %s, User: %s, PrivilegedBootPolicy: %s", img.Digest, img.ConfigFile.Config.User, po.PrivilegedBootPolicy)
	// 当用户不包含root时，说明不是特权用户启动
	// 这里把User为空时也当作root用户
	if img.PrivilegedBoot == consts.NotPrivilegedBootImage {
		return true, nil, nil
	}

	var reasonAndDetail []ReasonAndDetail
	var kv []model.KVHashs
	var safe = true

	var zhMsg = model.GetRejectReason(model.LangZh)[model.RejectReasonPrivilegedBoot]
	var enMsg = model.GetRejectReason(model.LangEn)[model.RejectReasonPrivilegedBoot]

	switch po.PrivilegedBootPolicy {
	case model.RejectPolicyReject:
		safe = false
		reasonAndDetail = []ReasonAndDetail{
			{
				RejectReason: model.RejectReasonPrivilegedBoot,
				RejectDetail: zhMsg,
			},
		}

		kv = []model.KVHashs{
			{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(zhMsg, zhMsg+"，被阻断"),
					EN: model.NewKeyValue(enMsg, enMsg+",blocked"),
				},
			},
		}

		logging.GetLogger().Info().Msgf("镜像<%s>特权启动，被阻断", img.Digest)
	case model.RejectPolicyAlarm:
		kv = []model.KVHashs{
			{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonPrivilegedBoot], zhMsg+"，未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonPrivilegedBoot], enMsg+",unblocked,just alert"),
				},
			},
		}
		logging.GetLogger().Info().Msgf("镜像<%s>特权启动，告警不阻断", img.Digest)
	}

	return safe, reasonAndDetail, kv
}

func (s *ConScannerSrv) checkEnv(ctx context.Context, scanImage model.ScanImage, img *model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("CICD checkEnv, imageid:%d,envs:%+v,policy env is :%+v,env policy is :%s", img.ID, scanImage.EnvKeyValue, po.Envs, po.EnvPolicy)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	//  验证不被信任的环境变量
	rejectEnvs := make([]string, 0)
	alterEnvs := make([]string, 0)
	for i := range scanImage.EnvKeyValue {
		for j := range po.Envs {
			if scanImage.EnvKeyValue[i].Key == po.Envs[j] {
				if po.EnvPolicy == model.RejectPolicyReject {
					rejectEnvs = append(rejectEnvs, scanImage.EnvKeyValue[i].Key)
				} else if po.EnvPolicy == model.RejectPolicyAlarm {
					alterEnvs = append(alterEnvs, scanImage.EnvKeyValue[i].Key)
				}
				continue
			}
		}
	}
	if len(rejectEnvs) > 0 {
		logging.GetLogger().Info().Msgf("contains env files, imag Id:" + strconv.Itoa(int(img.ID)))

		msgZh := fmt.Sprintf("%s:%s", model.GetRejectReason(model.LangZh)[model.RejectReasonHasUntrustedEnv], strings.Join(rejectEnvs, "，"))
		msgEN := fmt.Sprintf("%s:%s", model.GetRejectReason(model.LangEn)[model.RejectReasonHasUntrustedEnv], strings.Join(rejectEnvs, "，"))
		msgLog := fmt.Sprintf("image:%s%s:%s contains env ", img.Library, img.FullRepoName, img.Tags)

		safe = false
		records = append(records, ReasonAndDetail{
			RejectReason: model.RejectReasonHasUntrustedEnv,
			RejectDetail: msgZh,
		})

		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasUntrustedEnv], msgZh+"，被阻断"),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasUntrustedEnv], msgEN+",blocked")}})
		logging.GetLogger().Info().Msgf(" %s,has blocked", msgLog)
	}

	if len(alterEnvs) > 0 {
		logging.GetLogger().Info().Msgf("contains env files, imag Id:" + strconv.Itoa(int(img.ID)))

		msgZh := fmt.Sprintf("%s:%s", model.GetRejectReason(model.LangZh)[model.RejectReasonHasUntrustedEnv], strings.Join(alterEnvs, "，"))
		msgEN := fmt.Sprintf("%s:%s", model.GetRejectReason(model.LangEn)[model.RejectReasonHasUntrustedEnv], strings.Join(alterEnvs, "，"))
		msgLog := fmt.Sprintf("image:%s%s:%s contains env ", img.Library, img.FullRepoName, img.Tags)

		msgs = append(msgs, model.KVHashs{
			KVHash: model.KVHash{
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasUntrustedEnv], msgZh+"，未阻断，只告警"),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasUntrustedEnv], msgEN+",unblocked,just alert")}})
		logging.GetLogger().Info().Msgf(" %s,has blocked", msgLog)
	}

	return safe, records, msgs
}
