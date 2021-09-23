package component

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SearchImagesParam struct {
	SearchWord      string
	Kind            string
	IsOnline        bool
	ImageType       string
	ImageId         int64
	ImageIds        []int64
	Library         string
	HasQuestionInfo bool // 是否查询scanIamge中把QuestionInfo信息加上
}

type ScannerSrv interface {
	CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error
	SearchImages(ctx context.Context, param SearchImagesParam, filter *model.Filter) ([]model.ImageList, int64, error)
	UpdateImage(ctx context.Context, where SearchImagesParam, update map[string]interface{}) error
	GetImageDetail(ctx context.Context, imgId int64) (*model.ImageList, error)
	GetImageOverView(ctx context.Context, registerUrl string) (*model.OverView, error)
	GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error)
	TickScanOne(ctx context.Context, imgId int64, fromUrl string, comefrom int) error
	ScanOneForCICD(ctx context.Context, req *model.ScanOneForCICDRequest) (*model.ScanOneCICDResultRequest, error)
	ScanOneForCICDResult(ctx context.Context, req *model.ScanOneCICDResultRequest) (*model.ScanOneForCICDResponse, error)
	ScanAllNow(ctx context.Context, fromUrl string) error
	GetScanAllStatus(ctx context.Context) harbor.ScanAllStatus
	GetVulnOverView(ctx context.Context) (model.VulnOverview, error)
	ListImgLayers(ctx context.Context, imgDigest string, filter *model.Filter) ([]model.ReportImgBackInfo, error)
	ImgLayerInfo(ctx context.Context, layerDigest string, filter *model.Filter) (*model.ScanLayer, error)
	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)
	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail

	TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) bool

	DeleteCICDImage(ctx context.Context)
	ListBaseImageOfApp(ctx context.Context, imageId int64) ([]model.ImageList, error)
	ListAppImageOfBase(ctx context.Context, baseImageId int64) ([]model.ImageList, error)
}

type ConScannerSrv struct {
	dbdal       store.ScannerDalInterface
	registryDal store.RegistryDaoInterface
	log         *logging.Logger
	redclair    *RedClairService
	virusScan   *VirusScan
	scannerDB   *store.ScannerDB
	globalCache *cache.Cache
	scannerList *ScannerList
}

func NewConScannerSrv(dbdal store.ScannerDalInterface, registryDal store.RegistryDaoInterface, redclair *RedClairService, virusScan *VirusScan, scdb *store.ScannerDB, globalCache *cache.Cache, scannerList *ScannerList) *ConScannerSrv {
	return &ConScannerSrv{
		dbdal:       dbdal,
		registryDal: registryDal,
		log:         logging.GetLogger(),
		redclair:    redclair,
		virusScan:   virusScan,
		scannerDB:   scdb,
		globalCache: globalCache,
		scannerList: scannerList,
	}
}

func (s *ConScannerSrv) ListBaseImageOfApp(ctx context.Context, imageId int64) ([]model.ImageList, error) {
	images, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imageId}, ImageType: consts.AppImage}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListBaseImageOfApp")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
	}
	if len(images) == 0 {
		return nil, response.NewHttpError(http.StatusExpectationFailed, errors.New("not find the app image"))
	}

	baseImages, _, err := s.SearchImages(ctx, SearchImagesParam{ImageType: consts.BaseImage}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListBaseImageOfApp")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取基础镜像出错"))
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
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("SearchImages.SearchRegistry:error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusGone, err)
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}
	for i := range ans {
		if re, ok := regMap[ans[i].RegistryId]; ok {
			ans[i].Registry = &re
		}
	}

	return ans, nil
}

func (s *ConScannerSrv) ListAppImageOfBase(ctx context.Context, baseImageId int64) ([]model.ImageList, error) {
	baseImages, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{baseImageId}, ImageType: consts.BaseImage, Fields: []string{"id", "layers"}}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListAppImageOfBase")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取应用镜像出错"))
	}
	if len(baseImages) == 0 {
		return nil, response.NewHttpError(http.StatusExpectationFailed, errors.New("not find the base image"))
	}
	baseLayer := getLayerString(baseImages[0])
	images, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{ImageType: consts.AppImage, LayersPrefix: baseLayer,
		Fields: []string{"id", "layers", "full_repo_name", "image_type", "library", "tags", "digest"}}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImage")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ListAppImageOfBase")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("获取应用镜像出错"))
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}
	for i := range images {
		if re, ok := regMap[images[i].RegistryId]; ok {
			images[i].Registry = &re
		}
	}

	return images, nil
}

func (s *ConScannerSrv) UpdateImage(ctx context.Context, param SearchImagesParam, update map[string]interface{}) error {
	where := make([]string, 0)
	if param.ImageType == consts.AppImage {
		where = append(where, fmt.Sprintf("image_type = %d", consts.AppImageType))
	} else if param.ImageType == consts.BaseImage {
		where = append(where, fmt.Sprintf("image_type = %d", consts.BaseImageType))
	}

	if param.ImageId > 0 {
		where = append(where, fmt.Sprintf("id = %d", param.ImageId))
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
	if len(update) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, errors.New("no update data for update"))
	}

	err := s.dbdal.UpdateImage(ctx, strings.Join(where, " AND "), update)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("updating image error")
		return response.NewHttpError(http.StatusInternalServerError, errors.New("更新镜像出错"))
	}
	return nil
}

func (s *ConScannerSrv) K8sDeployDetect(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) bool {
	resConfig := s.dbdal.GetGlobalPolicyConfig(ctx)
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
			s.CreateSafeReject(ctx, *tmpImage, msgType, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary])
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
				logging.GetLogger().Info().Msg("K8sDeployDetect not find the image and the mode is safe mode")
				s.CreateSafeReject(ctx, *tmpImage, msgType, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary])
				flag = false
			}
			continue
		}
		img := imgs[0]
		safe, records, msgs, _ := s.DetectImageForK8s(ctx, imgs[0].ID, img.Library)
		if len(msgs) > 0 {
			notify := model.NotifyContext{
				ServiceID: fmt.Sprintf("%s/%s:%s(image)", img.Library, img.FullRepoName, img.Tags),
				CustomKV:  msgs,
			}

			if containerInfo[k].NotifyContext != nil {
				notify.PodName = containerInfo[k].NotifyContext.PodName
				notify.PodUID = containerInfo[k].NotifyContext.PodUID
				notify.Cluster = containerInfo[k].NotifyContext.Cluster
				notify.Namespace = containerInfo[k].NotifyContext.Namespace
				notify.CustomKV = append(notify.CustomKV, containerInfo[k].NotifyContext.CustomKV...)
			}
			notify.CustomKV = append(notify.CustomKV, model.KVHashs{KVHash: model.KVHash{
				EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
				ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", img.Library, img.FullRepoName, img.Tags)},
			}})
			notify.ServiceID = ""

			msg := model.NewReqBody(model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity), notify, generateUUId(img, msgType, consts.EventIntervalUUID))
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

func (s *ConScannerSrv) TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) bool {

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
func (s *ConScannerSrv) K8sOnlineMonitor(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) {
	if len(containerInfo) == 0 {
		logging.GetLogger().Info().Msg("K8sOnlineMonitor containerInfo is empty")
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
			s.CreateSafeReject(ctx, *tmpImageList, consts.AlertKindOnline, model.RejectNoLibrary, model.GetRejectReason(model.LangZh)[model.RejectNoLibrary])
			continue
		}

		// 进行检测
		_, _, msgs, _ := s.DetectImageForK8sOnlineMonitor(ctx, *tmpImageList)
		// 发送消息
		if len(msgs) > 0 {
			notify := model.NotifyContext{
				CustomKV: msgs,
			}

			if containerInfo[k].NotifyContext != nil {
				notify.PodName = containerInfo[k].NotifyContext.PodName
				notify.PodUID = containerInfo[k].NotifyContext.PodUID
				notify.Cluster = containerInfo[k].NotifyContext.Cluster
				notify.Namespace = containerInfo[k].NotifyContext.Namespace
				notify.CustomKV = append(notify.CustomKV, containerInfo[k].NotifyContext.CustomKV...)
			}
			notify.CustomKV = append(notify.CustomKV, model.KVHashs{KVHash: model.KVHash{
				EN: model.KeyValue{Key: "image", Value: fmt.Sprintf("%s/%s:%s", tmpImageList.Library, tmpImageList.FullRepoName, tmpImageList.Tags)},
				ZH: model.KeyValue{Key: "镜像", Value: fmt.Sprintf("%s/%s:%s", tmpImageList.Library, tmpImageList.FullRepoName, tmpImageList.Tags)},
			}})

			msg := model.NewReqBody(model.NewEventCenterRule(consts.AlertKindOnline, consts.AlertModuleContainerSecurity, consts.ImageSecurity),
				notify, generateUUId(*tmpImageList, consts.AlertKindOnline, consts.EventIntervalUUID))
			if err := sendMsgToEventCenter(ctx, msg); err != nil {
				logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor sendMsgToEventCenter sending message to event center, msg Type: %s error:%s", consts.AlertKindOnline, err.Error())
			}
		}
	}
	// return
}

func (s *ConScannerSrv) CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error {
	regi, err := s.getRegistry(ctx, "", model.RegistryUseTypeBuff)
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

	safe, records, msgs, err := s.DetectImageForCICD(ctx, req.ImageID, req.Library)
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
			generateUUId(img[0], consts.AlertKindCICD, consts.EventIntervalUUID),
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
	if !safe {
		// 删除记录
		if err := s.dbdal.DeleteImage(ctx, store.DeleteImageParam{ImageId: req.ImageID}); err != nil {
			logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult delete tensor_image_list record error %s", err.Error())
		}
		if err := s.dbdal.DeleteScanImage(ctx, store.DeleteScanImageParam{ImageId: req.ImageID}); err != nil {
			logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult delete scan_image record error %s", err.Error())
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
	hasHttp := strings.Contains(req.Image, "http://")
	hasHttps := strings.Contains(req.Image, "https://")

	req.Image = strings.Replace(strings.Replace(req.Image, "http://", "", 1), "https://", "", 1)
	lib, repo, tag := getLibRepoTag(req.Image)
	if hasHttp {
		lib = "http://" + lib
	} else if hasHttps || (!hasHttps && !hasHttp) {
		lib = "https://" + lib
	}
	logging.GetLogger().Info().Msgf("CICD parsed the image: %s%s:%s", lib, repo, tag)
	regs, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{UseType: model.RegistryUseTypeBuff}, nil)

	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD find the BuffRegistry library error")
		return nil, response.NewHttpError(http.StatusPreconditionFailed, fmt.Errorf("can not find the RegistryUseTypeBuff library"))
	}
	if len(regs) == 0 {
		logging.GetLogger().Err(err).Msgf("CICD can not find the BuffRegistry library")
		return nil, response.NewHttpError(http.StatusPreconditionFailed, fmt.Errorf("can not find the RegistryUseTypeBuff library"))
	}
	logging.GetLogger().Info().Msgf("CICD BuffRegistry registry is :%s", regs[0].Url)
	regi, err := s.getRegistry(ctx, "", model.RegistryUseTypeBuff)
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
		Library:        regs[0].Url,
		RegistryId:     regs[0].ID,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJson:     []byte(image.ConfigJson),
		CompleteTime:   image.Created.UTC().String(),
		FromType:       model.ImageFromTypeCICD,
		ImageType:      consts.AppImageType,
	}
	img.Layers = getLayerString(img)
	// 同步镜像到数据库
	imgId, err := s.scannerDB.InsertImageList(ctx, img)
	if err != nil && !strings.Contains(err.Error(), "duplicate key") {
		logging.GetLogger().Err(err).Msgf("CICD insert image tensor_image_list error image %s/%s:%s", regs[0].Url, img.FullRepoName, tag)
		return nil, err
	}
	// 下达扫描指令,这里会去拉取镜像，所以只能存中转镜像的library
	logging.GetLogger().Info().Msgf("CICD start scan,imagId:%d,image:%s/%s:%s", imgId, regs[0].Url, image.Repository, image.Tag)
	var globerr error
	if err := s.TickScanOne(ctx, imgId, "", consts.ScanTaskComeFromCICD); err != nil {
		logging.GetLogger().Err(err).Msgf("CICD TickScanOne failure, imag Id:" + strconv.Itoa(int(imgId)))
		globerr = err
		// 这里不返回，因为后面要删除记录
	}
	// 更新library,这一步的目的是为了下面在做镜像扫描时能通过library找到相关的策略
	update := map[string]interface{}{"library": lib}

	// 先删除原来的，再更新现在的,不然就会存在更新失败的情况,因为（FullRepoName+tags+library+fromType是唯一索引）
	if err := s.dbdal.DeleteImage(ctx, store.DeleteImageParam{
		FullRepoName: img.FullRepoName,
		Tags:         img.Tags,
		Library:      lib,
		FromType:     model.ImageFromTypeCICD,
	}); err != nil {
		logging.GetLogger().Err(err).Msgf("CICD delete pre image error %s", err.Error())
		return nil, response.NewHttpError(http.StatusExpectationFailed, err)
	}

	if err := s.dbdal.UpdateImage(ctx, fmt.Sprintf("id = %d", imgId), update); err != nil {
		globerr = err
		logging.GetLogger().Err(err).Msgf("CICD update tensor_image_list library error %s", err.Error())
	}
	return &model.ScanOneCICDResultRequest{
		ImageID: imgId,
		Library: lib,
	}, globerr
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
func (s *ConScannerSrv) ImgLayerInfo(ctx context.Context, layerDigest string, filter *model.Filter) (*model.ScanLayer, error) {
	layers, _, err := s.dbdal.SearchScanLayer(ctx, store.SearchScanLayerParam{LayerDigests: []string{layerDigest}}, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ReportImgBackInfo.SearchScanLayer")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(layers) == 0 {
		logging.GetLogger().Error().Err(err).Msg("ImgLayerInfo.SearchScanLayer not fond the image layer")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return &layers[0], nil
}

// ListImgLayers List  all layers  information  with  this image. order by created time
func (s *ConScannerSrv) ListImgLayers(ctx context.Context, imgDigest string, filter *model.Filter) ([]model.ReportImgBackInfo, error) {
	// step1 get image info
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Digests: []string{imgDigest}}, nil)
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
						res[i].Vulus = append(res[i].Vulus, layers[j].VulnInfo[k].ID)
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

func (s *ConScannerSrv) GetScanAllStatus(ctx context.Context) harbor.ScanAllStatus {
	return s.dbdal.SearchScanAllStatus(ctx)
}

func (s *ConScannerSrv) ScanAllNow(ctx context.Context, fromUrl string) error {
	logging.GetLogger().Info().Msgf(fmt.Sprintf("start of full scan:%s", time.Now().Format("2006-01-02 15:04:05")))
	// 先查询当前时刻已存在的仓库列表
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("ScanAllNow.SearchRegistry ")
		return err
	}
	registryIds := make([]int64, len(registries))
	for i := range registries {
		registryIds[i] = registries[i].ID
	}

	start := time.Now().Unix()
	var lastID int64 = 0
	var bathSize int64 = 1000
	if err := s.dbdal.SetImageStatus(ctx, nil, model.ScanStatusPending); err != nil {
		logging.GetLogger().Error().Err(err).Msg("ScanAllNow.SetImageStatus")
		return err
	}
	for {
		// step1: search image_list
		imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{StartId: lastID, FromType: model.ImageFromTypeNormal, RegistryIds: registryIds}, &model.Filter{
			PageSize:  bathSize, // 批量取
			PageIndex: 1,
			SortBy:    "asc",
			SortFiled: "id",
		})
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ScanAllNow.SearchImage error:%s", err.Error())
			return err
		}
		if len(imgs) == 0 {
			return nil
		}

		lastID = imgs[len(imgs)-1].ID
		imgIds := make([]int64, 0)
		for i := range imgs {
			imgIds = append(imgIds, imgs[i].ID)
		}

		scanImages, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: imgIds, Fields: []string{"image_id", "status"}}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ScanAllNow.SearchScanImage error:%s", err.Error())
			if err := s.dbdal.SetImageStatus(ctx, nil, model.ScanStatusFailed); err != nil {
				if err != nil {
					dbfunc := ScannerDbFunc{}
					f := func() error {
						err := s.dbdal.SetImageStatus(context.Background(), nil, model.ScanStatusFailed)
						return err
					}
					dbfunc.RetryNum = 0
					dbfunc.Value = f
					s.scannerList.ReUpdataDBPush(dbfunc)
				}
				logging.GetLogger().Error().Err(err).Msg("ScanAllNow.SetImageStatus")
				return err
			}
		}
		scanImageMap := make(map[int64]*model.ScanImage)
		for i := range scanImages {
			scanImageMap[scanImages[i].ImageId] = &scanImages[i]
		}

		for i := range imgs {
			if si, ok := scanImageMap[imgs[i].ID]; ok && si.Status == model.ScanStatusInProgress {
				continue
			}
			if err := s.TickScanOne(ctx, imgs[i].ID, fromUrl, consts.ScanTaskComeFromWeb); err != nil {
				logging.GetLogger().Err(err).Msgf(fmt.Sprintf("ScanAllNow.TickScanOne error:%s", err.Error()))
				err := s.dbdal.SetImageStatus(context.Background(), []int64{imgs[i].ID}, model.ScanStatusFailed)
				if err != nil {
					dbfunc := ScannerDbFunc{}
					f := func() error {
						err := s.dbdal.SetImageStatus(context.Background(), []int64{imgs[i].ID}, model.ScanStatusFailed)
						return err
					}
					dbfunc.RetryNum = 0
					dbfunc.Value = f
					s.scannerList.ReUpdataDBPush(dbfunc)
				}
				continue
			}
		}

		if len(imgs) < int(bathSize) {
			break
		}
	}
	logging.GetLogger().Info().Msgf(fmt.Sprintf("End of full scan: %s, spend %d second", time.Now().Format("2006-01-02 15:04:05"), time.Now().Unix()-start))
	return nil
}

func (s *ConScannerSrv) TickScanOne(ctx context.Context, imgId int64, fromUrl string, comeFrom int) error {
	resTask, resVirusTask, err := s.dbdal.GetTaskFromImageList(ctx, imgId, fromUrl, "")
	if err != nil {
		return err
	}

	logging.GetLogger().Info().Msgf("TickScanOne task is :%v", resTask)
	start := time.Now()

	s.redclair.AddScanTask(resTask, comeFrom)
	s.virusScan.AddScanTask(resVirusTask, comeFrom)

	if time.Since(start) > time.Second*20 && comeFrom == consts.ScanTaskComeFromCICD {
		logging.GetLogger().Info().Msgf("time out to send task for scan,comefrom :%d", comeFrom)
		return fmt.Errorf("time out to send task")
	}
	return nil
}

func (s *ConScannerSrv) GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error) {
	scanStatus := "not_scan"
	res := model.ScanOneStatusResponse{ScanStatus: scanStatus, EndTime: time.Now().Format("2006-01-02 15:04:05")}
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imgId}, Library: fromUrl}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetScanOneStatus.SearchImage error:%s", err.Error()))
		return &res, nil
	}
	if len(imgs) == 0 {
		return &res, nil
	}
	// 查scan_image
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{imgs[0].ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetScanOneStatus.SearchScanImage error:%s", err.Error()))
		return &res, nil
	}
	if len(scs) == 0 {
		return &res, nil
	}
	// 拼装信息
	switch scs[0].Status {
	case model.ScanStatusInProgress:
		scanStatus = "inprogress"
	case model.ScanStatusFailed:
		scanStatus = "error"
	case model.ScanStatusPending:
		scanStatus = "pending"
	case model.ScanStatusSucceeded:
		scanStatus = "success"
	default:
		scanStatus = "not_scan"
	}
	res.ScanStatus = scanStatus
	if len(scs[0].MaliciousInfo) > 0 {
		res.HasMalicious = true
	}
	if len(scs[0].VulnInfo) > 0 {
		res.HasVulu = true
	}
	if len(scs[0].SensitiveFile) > 0 {
		res.HasSensitive = true
	}
	res.RiskScore = scs[0].RiskScore
	res.OverallSeverity = scs[0].OverallSeverity
	res.OverallSeverityInt = scs[0].OverallSeverityInt
	return &res, nil
}

func (s *ConScannerSrv) GetImageDetail(ctx context.Context, imgId int64) (*model.ImageList, error) {
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imgId}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("GetImageDetail.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(imgs) == 0 {
		logging.GetLogger().Err(err).Msgf("GetImageDetail.not find the image")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("not find the image"))
	}

	img := &imgs[0]
	// 查扫描结果
	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: []int64{img.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("SearchImages.SearchScanImage:error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(scs) == 0 {
		logging.GetLogger().Info().Msgf("GetImageDetail not found the scan_image,imageID:%d", imgId)
		return img, nil
	}

	// 增加漏洞和敏感文件信息
	scanTaskId, _ := primitive.ObjectIDFromHex(scs[0].ScanTaskId)
	imageScanResult := model.ImageScanSummaryResult{
		TopVulns:          scs[0].VulnInfo,
		SensitiveFiles:    scs[0].SensitiveFile,
		Repository:        img.FullRepoName,
		HarborURL:         img.Url,
		Tag:               img.Tags,
		Digest:            img.Digest,
		TaskID:            scanTaskId,
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

	return img, nil
}

func (s *ConScannerSrv) GetImageOverView(ctx context.Context, registerUrl string) (*model.OverView, error) {
	overView := new(model.OverView)
	// 查总数
	_, total, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Library: registerUrl, FromType: model.ImageFromTypeNormal}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("GetImageOverView.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	allResMap := make(map[string]map[string]*store.ImageGroup)

	for _, ty := range []string{consts.VulnType, consts.MaliciousInfoType, consts.SensitiveFileType, consts.WebsellInfoType} {
		if err := s.getOverViewHelper(ctx, ty, overView, allResMap); err != nil {
			logging.GetLogger().Error().Err(err).Msgf(fmt.Sprintf("GetImageOverView.getOverViewHelper error %s", err.Error()))
			return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
	}

	// 查在线
	onlineSql := fmt.Sprintf("select distinct a.digest, a.library  from  %s a  join %s b  on  a.digest = b.digest and a.from_type = %d", store.ImageTable, store.ImageRelateTable, model.ImageFromTypeNormal)
	if registerUrl != "" {
		onlineSql = onlineSql + fmt.Sprintf(" AND a.library = %s ; ", registerUrl)
	} else {
		onlineSql = onlineSql + " ;"
	}
	onlineRes, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSql})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetImageOverView.GetOnlineImage")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	for i := range onlineRes {
		on, ok := allResMap[fmt.Sprintf("%s_%s", onlineRes[i].Digest, onlineRes[i].Library)]
		if !ok {
			continue
		}
		if on[consts.VulnType] != nil {
			overView.Online.VULN += on[consts.VulnType].Count
		}
		if on[consts.MaliciousInfoType] != nil {
			overView.Online.VIRUS += on[consts.MaliciousInfoType].Count
		}
		if on[consts.SensitiveFileType] != nil {
			overView.Online.SENSITIVE += on[consts.SensitiveFileType].Count
		}
		if on[consts.WebsellInfoType] != nil {
			overView.Online.Webshell += on[consts.WebsellInfoType].Count
		}
	}
	overView.ImageTotal = total
	overView.OnlineTotal = int64(len(onlineRes))
	return overView, nil
}

// getOverViewHelper 连表查询tensor_image_list和scan_image表，查询各个镜像下漏洞，病毒等的数据
func (s *ConScannerSrv) getOverViewHelper(ctx context.Context, searchType string, overView *model.OverView, allResMap map[string]map[string]*store.ImageGroup) error {
	hasVuluSql := fmt.Sprintf("select count(b.image_id), b.image_id,a.digest, a.library from %s a join %s b on a.id = b.image_id where  b.%s is not null and a.from_type = %d group by b.image_id,a.digest,  a.library;", store.ImageTable, store.ImageScanTable, searchType, model.ImageFromTypeNormal)

	hasVuluRes, err := s.dbdal.GetImageOverView(ctx, store.GetImageOverViewParm{SQL: hasVuluSql})
	if err != nil {
		return response.NewHttpError(http.StatusInternalServerError, err)
	}
	for i := range hasVuluRes {
		key := fmt.Sprintf("%s_%s", hasVuluRes[i].Digest, hasVuluRes[i].Library)
		if allResMap[key] == nil {
			allResMap[key] = make(map[string]*store.ImageGroup)
		}
		allResMap[key][searchType] = &hasVuluRes[i]
		switch searchType {
		case consts.VulnType:
			overView.Sum.VULN += hasVuluRes[i].Count
		case consts.PkgType:
			overView.Sum.Pkg += hasVuluRes[i].Count
		case consts.SensitiveFileType:
			overView.Sum.SENSITIVE += hasVuluRes[i].Count
		case consts.MaliciousInfoType:
			overView.Sum.VIRUS += hasVuluRes[i].Count
		case consts.WebsellInfoType:
			overView.Sum.Webshell += hasVuluRes[i].Count
		}
	}
	return nil
}

func (s *ConScannerSrv) SearchImages(ctx context.Context, param SearchImagesParam, filter *model.Filter) ([]model.ImageList, int64, error) {

	filter = filter.SetDefault()
	filter.SortFiled = "id"
	filter.SortBy = "asc"
	daoParam := store.SearchImageParam{FromType: model.ImageFromTypeNormal, ImageType: param.ImageType, Library: param.Library}
	// 种类的搜索
	if param.Kind != "" {
		kindImageId := make([]int64, 0)
		qs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{Kind: param.Kind, NoSerialization: true, Fields: []string{"image_id"}}, nil)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchImages.SearchQuestionInfo")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range qs {
			kindImageId = append(kindImageId, qs[i].ImageId)
		}
		if len(kindImageId) == 0 {
			logging.GetLogger().Info().Msgf("SearchScanImage not fond scan image")
			return []model.ImageList{}, 0, nil
		}
		daoParam.Ids = kindImageId
	}

	if param.SearchWord != "" {
		split := strings.Split(param.SearchWord, ":")
		if len(split) > 0 {
			daoParam.FullRepoSearch = split[0]
		}
		if len(split) > 1 {
			daoParam.TagSearch = split[1]
		}
	}
	if param.IsOnline {
		onlineSql := fmt.Sprintf("select distinct a.digest, a.library  from  %s a  join %s b  on  a.digest = b.digest ;", store.ImageTable, store.ImageRelateTable)
		online, err := s.dbdal.GetOnlineImage(ctx, store.GetOnlineImageParam{SQL: onlineSql})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("SearchImages.SearchQuestionInfo")
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		onlineDigests := make([]string, 0)
		for _, im := range online {
			onlineDigests = append(onlineDigests, im.Digest)
		}
		if len(onlineDigests) == 0 {
			logging.GetLogger().Info().Msgf("GetOnlineImage not fond scan image")
			return []model.ImageList{}, 0, nil
		}
		daoParam.Digests = onlineDigests
	}

	imgs, cnt, err := s.dbdal.SearchImage(ctx, daoParam, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImages.SearchImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	if len(imgs) == 0 {
		return imgs, 0, nil
	}

	imageIds := make([]int64, 0)
	imgeMap := make(map[int64]*model.ImageList)
	for i := range imgs {
		if imgs[i].CompleteTime == "" {
			imgs[i].CompleteTime = imgs[i].CreatedAt.Format("2006-01-02 15:04:05")
		}
		imageIds = append(imageIds, imgs[i].ID)
		imgeMap[imgs[i].ID] = &imgs[i]
	}

	scs, _, err := s.dbdal.SearchScanImage(ctx, store.SearchScanImageParam{ImageIds: imageIds, NoSerialization: true}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImages.SearchScanImage")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	// 为了兼容前端把questionInfo信息加上
	if param.HasQuestionInfo {
		scMap := make(map[int64][]model.QuestionInfo)
		for _, sc := range scs {
			if im, ok := imgeMap[sc.ImageId]; ok && sc.FinishAt > 0 {
				im.CompleteTime = time.Unix(sc.FinishAt, 0).Format("2006-01-02 15:04:05")
			}
			qus := make([]model.QuestionInfo, 0)
			if len(sc.VulnInfoJSON) > 0 {
				qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VULN})
			}
			if len(sc.SensitiveFileJSON) > 0 {
				qus = append(qus, model.QuestionInfo{ID: model.QUESTION_SENSITIVE})
			}
			if len(sc.MaliciousInfoJSON) > 0 {
				qus = append(qus, model.QuestionInfo{ID: model.QUESTION_VIRUS})
			}
			if len(sc.WebshellInfoJSON) > 0 {
				qus = append(qus, model.QuestionInfo{ID: model.QUESTION_WEB_SHELL})
			}
			scMap[sc.ImageId] = qus
		}

		for i := range imgs {
			if qs, ok := scMap[imgs[i].ID]; ok {
				imgs[i].Questions = qs
			} else {
				imgs[i].Questions = make([]model.QuestionInfo, 0) // 防止null
			}
		}
	}
	// 把仓库信息加上
	registries, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("SearchImages.SearchRegistry")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	regMap := make(map[int64]model.Registry)
	for i := range registries {
		regMap[registries[i].ID] = registries[i]
	}
	// 镜像评分
	riskScoreMap := make(map[int64]model.ScanImage)
	for i := range scs {
		riskScoreMap[scs[i].ImageId] = scs[i]
	}
	for i := range imgs {
		if sc, ok := riskScoreMap[imgs[i].ID]; ok {
			imgs[i].ScanImage = &sc
		}
		if re, ok := regMap[imgs[i].RegistryId]; ok {
			imgs[i].Registry = &re
		}
	}
	return imgs, cnt, nil
}

func (s *ConScannerSrv) getRegistry(ctx context.Context, library string, useType int64) (registry.Registry, error) {
	// cicd集成时，首先会把公司镜像推送到我们自己搭建的仓库中(默认是docker-registry),然后拉取镜像进行扫描，
	// 通过library查registryID
	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryUrl: library, UseType: useType, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(fmt.Sprintf("can not find the library:%s", library))
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not find the library:%s,error is %s", library, err.Error())))
	}
	if len(regs) == 0 {
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not find the library:%s", library)))
	}
	regs[0].RegType = docker.Version // 暂时只支持docker-registry，所以这里赋值一下

	regi, err := GetRegistryFromConfig(regs[0])
	if err != nil {
		logging.GetLogger().Err(err).Msgf("can not connect harborV2")
		return nil, response.NewHttpError(http.StatusBadGateway, fmt.Errorf(fmt.Sprintf("can not connect harborV2 error is %s", err.Error())))
	}
	return regi, nil
}

// DetectImageForCICD CICD 检查镜像是否正确
func (s *ConScannerSrv) DetectImageForCICD(ctx context.Context, imageId int64, policeReg string) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("CICD,start DetectImage,imageId：%d", imageId)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	// 先查镜像是否存在
	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imageId}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD,find the image :%d,error", imageId)
		return false, records, msgs, err
	}
	// 如果没有在数据库没有查到镜像，默认不安全
	if len(imgs) == 0 {
		logging.GetLogger().Info().Msgf("CICD,not find the image:%d", imageId)
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("CICD,没有查到对应镜像:%d", imageId))
	}

	regs, _, err := s.registryDal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryUrl: imgs[0].Library, NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD ScanOneForCICDResult search SearchRegistry error:%s", err.Error())
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("CICD,查询镜像仓库地址出错：%d", imageId))
	}
	if len(regs) == 0 {
		logging.GetLogger().Info().Msgf("untrust Library imag Id:" + strconv.Itoa(int(imgs[0].ID)))
		msgZh := "来源镜像不在本地仓库"
		msgEN := "image not in config registry"
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

	img := imgs[0]
	img.Library = policeReg

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD library:%s get global reject policy error", policeReg)
		return false, records, msgs, err
	}
	if len(globalReg) == 0 || !globalReg[0].CicdEnable {
		logging.GetLogger().Info().Msgf("CICD library:%s global is not enable ", policeReg)
		return true, records, msgs, nil
	}

	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Library: policeReg})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD library:%s get reject policy error", policeReg)
		return true, records, msgs, err
	}

	if len(policies) == 0 { // 没有策略说明不检测，默认全安全
		logging.GetLogger().Info().Msgf("CICD library:%s has no reject policy, all safe by default", policeReg)
		return true, records, msgs, nil
	}
	scanImageRes, err := s.checkScanImageExist(ctx, model.UsePatternForCICD, img, policies[0])
	if err != nil {
		logging.GetLogger().Info().Msgf("CICD search scan_image: %d, error: %s", imageId, err.Error())
		return false, records, msgs, err
	}
	records = append(records, scanImageRes.Records...)
	msgs = append(msgs, scanImageRes.Msg...)

	if scanImageRes.ScanImag != nil {
		scanImage := *scanImageRes.ScanImag
		for _, po := range policies {
			if !po.Enable || !po.CicdEnable || po.IsGlobal {
				logging.GetLogger().Info().Msgf("CICD reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}
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
			sa6, red6, ms6 := s.checkWebselhl(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6)...)
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
	}

	// 检查白名单,要检查一下Digest,防止通过Library+FullRepoName+Tags的方式绕过检测
	// 镜像存在白名单中，只是不阻断，任然要进行扫描检测，对检测结果仍然要发事件中心
	if !safe {
		if in, _ := s.checkWhitelist(ctx, img, model.UsePatternForCICD); in {
			s.log.WithContext(ctx).Infof("CICD DetectImageForCICD:%s/%s:%s,Digest:%s", img.Library, img.FullRepoName, img.Tags, img.Digest)
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
func (s *ConScannerSrv) DetectImageForK8sOnlineMonitor(ctx context.Context, image model.ImageList) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("K8sOnlineMonitor,start DetectImage,image：%s/%s:%s", image.Library, image.FullRepoName, image.Tags)

	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

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
				ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedImage], msgZh),
				EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonUntrustedImage], msgEN)}})
		return safe, records, msgs, nil
	}
	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor library:%s get global reject policy error", checkImageRes.Image.Library)
		return false, records, msgs, err
	}
	if len(globalReg) == 0 || !globalReg[0].OnlineMonitor {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor library:%s global reject is not enable ", checkImageRes.Image.Library)
		return true, records, msgs, nil
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

	img := *checkImageRes.Image
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
			if !po.Enable || !po.OnlineMonitor || po.IsGlobal {
				logging.GetLogger().Info().Msgf("K8sOnlineMonitor reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}
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
			sa6, red6, ms6 := s.checkWebselhl(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6)...)
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
func (s *ConScannerSrv) checkBaseImage(ctx context.Context, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msgf("start  checkBaseImage imag Id:" + strconv.Itoa(int(img.ID)))
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	images, err := s.ListBaseImageOfApp(ctx, img.ID)
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
		msgLog := fmt.Sprintf("image:%s%s:%s untrusted base image", img.Library, img.FullRepoName, img.Tags)

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

// checkWebselhl 检查websell的扫描结果
func (s *ConScannerSrv) checkWebselhl(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	logging.GetLogger().Info().Msg("checkWebselhl,start ")
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
func (s *ConScannerSrv) checkWhitelist(ctx context.Context, img model.ImageList, usePattern string) (bool, error) {
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
func (s *ConScannerSrv) checkScanImageExist(ctx context.Context, usePattern string, img model.ImageList, po model.RejectPolicy) (checkSanImageRes, error) {
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
func (s *ConScannerSrv) checkImageExist(ctx context.Context, usePattern string, img model.ImageList) checkImageRes {
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

func (s *ConScannerSrv) checkMaliciousInfo(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
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

func (s *ConScannerSrv) checkSensitiveFile(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	// 验证敏感文件
	if len(scanImage.SensitiveFile) > 0 {
		logging.GetLogger().Info().Msgf("Contains sensitive files, imag Id:" + strconv.Itoa(int(img.ID)))
		msgZh := "存在敏感文件"
		msgEN := "contain sensitive file"
		msgLog := fmt.Sprintf("Image:%s/%s:%s Contains sensitive file", img.Library, img.FullRepoName, img.Tags)

		switch po.SensitiveFilePolicy {
		case model.RejectPolicyReject:
			safe = false
			records = append(records, ReasonAndDetail{
				RejectReason: model.RejectReasonHasSensitiveFile,
				RejectDetail: msgZh,
			})

			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile], msgZh+"，被阻断"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasSensitiveFile], msgEN+",unblocked,just alert")}})

			logging.GetLogger().Info().Msgf("%s,has blocked", msgLog)

		case model.RejectPolicyAlarm:
			msgs = append(msgs, model.KVHashs{
				KVHash: model.KVHash{
					ZH: model.NewKeyValue(model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile], msgZh+",未阻断，只告警"),
					EN: model.NewKeyValue(model.GetRejectReason(model.LangEn)[model.RejectReasonHasSensitiveFile], msgEN+",unblocked,just alert")}})
			logging.GetLogger().Info().Msgf("%s,not blocked, only send messages to the event center", msgLog)
		}
	}

	return safe, records, msgs
}

func (s *ConScannerSrv) checkCustomizeVulu(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	customizeVuluMap := make(map[string]model.RejectVuln)
	for i := range po.RejectVulns {
		customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
	}
	cusBlockVluns := make([]string, 0)
	cusAlertVluns := make([]string, 0)

	for _, vu := range scanImage.VulnInfo {
		// 自定义漏洞规则
		if svn, ok := customizeVuluMap[vu.ID]; ok {
			logging.GetLogger().Info().Msgf("Contains custom vulnerabilities, imag Id:" + strconv.Itoa(int(img.ID)))

			switch svn.RejectPolicy {
			case model.RejectPolicyReject:
				cusBlockVluns = append(cusBlockVluns, vu.ID)
				safe = false
			case model.RejectPolicyAlarm:
				cusAlertVluns = append(cusAlertVluns, vu.ID)
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

func (s *ConScannerSrv) checkVulnSeverity(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true
	customizeVuluMap := make(map[string]model.RejectVuln)
	for i := range po.RejectVulns {
		customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
	}
	vumMap := make(map[string][]string)
	for _, vu := range scanImage.VulnInfo {
		if _, ok := customizeVuluMap[vu.ID]; ok {
			continue
		}
		// 如果配置了漏洞评级
		if po.VulnLevel != "" && compareSeverity(vu.Severity, po.VulnLevel) {
			if vumMap[vu.Severity] == nil {
				vumMap[vu.Severity] = make([]string, 0)
			}
			vumMap[vu.Severity] = append(vumMap[vu.Severity], vu.ID)
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

func (s *ConScannerSrv) checkVulnScore(ctx context.Context, scanImage model.ScanImage, img model.ImageList, po model.RejectPolicy) (bool, []ReasonAndDetail, []model.KVHashs) {
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
	ticker := time.NewTicker(time.Hour * 12) // 每12个小时删除一次
	for {
		<-ticker.C
		s.deleteCICDImage(context.Background())
	}
}

// DeleteCICDImage 定期删除cicd仓库的镜像
func (s *ConScannerSrv) deleteCICDImage(ctx context.Context) {

	regs, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{UseType: model.RegistryUseTypeBuff}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD find BuffRegistry error")
		return
	}
	if len(regs) == 0 {
		logging.GetLogger().Err(err).Msgf("CICD not find BuffRegistry ")
		return
	}
	logging.GetLogger().Info().Msgf("CICD find BuffRegistry registry: %s", regs[0].Url)
	regi, err := s.getRegistry(ctx, "", model.RegistryUseTypeBuff)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CICD connect BuffRegistry :%s", regs[0].Url)
		return
	}
	// 先查询镜像，然后一个一个的删除
	images, err := regi.ListImages(func(conf registry.RegisterConfig, image registry.Image) error {
		logging.GetLogger().Info().Msgf("CICD  deleteCICDImage search image in %s", image.Repository)
		return nil
	})
	if err != nil {
		logging.GetLogger().Info().Msgf("CICD asynchronously delete BuffRegistry image error: %s", err.Error())
	}
	for i := range images {
		if err := regi.DeleteImages("", images[i].Repository, images[i].ImageDigest); err != nil {
			logging.GetLogger().Info().Msgf("CICD asynchronous delete  BuffRegistry image error: %s", err.Error())
		} else {
			logging.GetLogger().Info().Msgf("CICD asynchronous delete BuffRegistry image :%s", images[i].Repository)
		}
	}
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

func (s *ConScannerSrv) CreateSafeReject(ctx context.Context, ImageList model.ImageList, msgType string, reason int64, detail string) {
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
		msg := model.NewReqBody(
			model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity),
			model.NotifyContext{
				ServiceID: fmt.Sprintf("%s/%s:%s(image)", ImageList.Library, ImageList.FullRepoName, ImageList.Tags),
				CustomKV:  tmpHashs},
			generateUUId(img, msgType, consts.EventIntervalUUID),
		)
		if err := sendMsgToEventCenter(ctx, msg); err != nil {
			logging.GetLogger().Err(err).Msgf("send msg to event center error:%s", err.Error())
		}
	}
}

func (s *ConScannerSrv) DetectImageForK8s(ctx context.Context, imageId int64, policeReg string) (bool, []ReasonAndDetail, []model.KVHashs, error) {
	logging.GetLogger().Info().Msgf("K8sDeployDetect,start DetectImage,imageId：%d", imageId)
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)
	safe := true

	imgs, _, err := s.dbdal.SearchImage(ctx, store.SearchImageParam{Ids: []int64{imageId}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect,find the image :%d,error", imageId)
		return false, records, msgs, err
	}
	// 如果没有在数据库没有查到镜像，默认不安全
	if len(imgs) == 0 {
		logging.GetLogger().Info().Msgf("K8sDeployDetect,not find the image:%d", imageId)
		return false, records, msgs, fmt.Errorf(fmt.Sprintf("K8sDeployDetect,没有查到对应镜像:%d", imageId))
	}

	img := imgs[0]
	img.Library = policeReg

	// 检查全局策略是否开启
	globalReg, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect library:%s get global reject policy error", policeReg)
		return false, records, msgs, err
	}
	if len(globalReg) == 0 || !globalReg[0].K8sEnable {
		logging.GetLogger().Info().Msgf("K8sDeployDetect library:%s global reject is not enable ", policeReg)
		return true, records, msgs, nil
	}

	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Library: policeReg, Global: consts.FalseString})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("K8sDeployDetect library:%s get reject policy error", policeReg)
		return true, records, msgs, err
	}

	if len(policies) == 0 { // 没有策略说明不检测，默认全安全
		logging.GetLogger().Info().Msgf("K8sDeployDetect library:%s has no reject policy, all safe by default", policeReg)
		return true, records, msgs, nil
	}
	scanImageRes, err := s.checkScanImageExist(ctx, model.UsePatternForK8s, img, policies[0])
	if err != nil {
		logging.GetLogger().Info().Msgf("K8sDeployDetect search scan_image: %d, error: %s", imageId, err.Error())
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
			if !po.Enable || !po.K8sEnable || po.IsGlobal {
				logging.GetLogger().Info().Msgf("K8sDeployDetect reject policy not enable :name:%s,ID:%d", po.Name, po.ID)
				continue
			}
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
			sa6, red6, ms6 := s.checkWebselhl(ctx, scanImage, img, po)
			if !sa1 || !sa2 || !sa3 || !sa4 || !sa5 || !sa6 {
				safe = false
			}
			records = append(records, mergeRecord(red1, red2, red3, red4, red5, red6)...)
			msgs = append(msgs, mergeMsg(ms1, ms2, ms3, ms4, ms5, ms6)...)
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
	}
	logging.GetLogger().Info().Msgf("K8sDeployDetect:checkBaseImage ... safe:%t: msg:%d,records:%d", safe, len(msgs), len(records))

	// 检查白名单,K8s不检查Digest
	// 镜像存在白名单中，只是不阻断，任然要进行扫描检测，对检测结果仍然要发事件中心
	if !safe {
		if in, _ := s.checkWhitelist(ctx, img, model.UsePatternForK8s); in {
			safe = true
			for i := range msgs {
				msgs[i].KVHash.ZH.Value = strings.Replace(msgs[i].KVHash.ZH.Value, "被阻断", "但镜像已加入白名单中，未被阻断", 1)
				msgs[i].KVHash.EN.Value = strings.Replace(msgs[i].KVHash.EN.Value, ",blocked", ",but image has add to the whitelist,unblocked", 1)
			}
		}
	}
	return safe, records, msgs, nil
}
