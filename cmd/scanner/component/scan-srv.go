package component

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/harborv2"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	VulnType          = "vuln_info_json"
	PkgType           = "pkg_info_json"
	SensitiveFileType = "sensitive_file_json"
	MaliciousInfoType = "malicious_info_json"
)

type ScannerSrv interface {
	CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error
	SearchAssetsContainers(ctx context.Context, digests []string, filter *model.Filter) ([]model.AssetContainer, int64, error)
	SearchImages(ctx context.Context, searchWord, kind string, isOnline bool, filter *model.Filter) ([]model.ImageList, int64, error)
	GetImageDetail(ctx context.Context, imgId int64) (*model.ImageList, error)
	GetImageOverView(ctx context.Context, registerUrl string) (*model.OverView, error)
	GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error)
	TickScanOne(ctx context.Context, imgId int64, fromUrl string, comefrom int) error
	ScanOneForDetectImage(ctx context.Context, library, projectName, repoName, tag string, maxSecond int) (bool, error)
	ScanAllNow(ctx context.Context, fromUrl string) error
	GetScanAllStatus(ctx context.Context) harbor.ScanAllStatus
	GetVulnOverView(ctx context.Context) (model.VulnOverview, error)
	ListImgLayers(ctx context.Context, imgDigest string, filter *model.Filter) ([]model.ReportImgBackInfo, error)
	ImgLayerInfo(ctx context.Context, layerDigest string, filter *model.Filter) (*model.ScanLayer, error)
	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)
	GetRelationImage(ctx context.Context, vulnImageLists []model.VulnImageList) ([]model.VulnDetailContainer, error)
	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail
	GetPolicyConfig(ctx context.Context) (model.RejectPolicyConfigResponse, error)
	AddSinglePolicy(ctx context.Context, policy model.RejectPolicyConfigResponse) (int64, error)
	AddPolicyConfig(ctx context.Context, policyCpmfog model.RejectPolicyConfigResponse)
	TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) bool
	AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicyConfigResponse)
	ListRegistry(ctx context.Context, noPolice bool) ([]model.Registry, int64, error)
}

type ConScannerSrv struct {
	dbdal       store.ScannerDalInterface
	log         *logging.Logger
	redclair    *RedClairService
	virusScan   *VirusScan
	scannerDB   *store.ScannerDB
	globalCache *cache.Cache
}

func (s *ConScannerSrv) ListRegistry(ctx context.Context, noPolice bool) ([]model.Registry, int64, error) {
	registries, i, err := s.dbdal.SearchRegistry(store.SearchRegistryParam{}, nil)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, "ListRegistry error %s", err.Error())
		return nil, 0, response.NewHttpError(http.StatusBadRequest, err)
	}
	// 只返回还没有配置策略的仓库
	if noPolice {
		policies, err := s.dbdal.SearchRejectPolicy(store.SearchRejectPolicyParam{})
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, "查询配置策略出错")
			return registries, i, nil
		}
		exit := make(map[string]bool)
		for i := range policies {
			for j := range policies[i].Library {
				exit[policies[i].Library[j]] = true
			}
		}
		ans := make([]model.Registry, 0)
		for i := range registries {
			if !exit[registries[i].Url] {
				ans = append(ans, registries[i])
			}
		}
		return ans, int64(len(ans)), nil
	}
	return registries, i, nil
}

func (s *ConScannerSrv) AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicyConfigResponse) {
	tmpPolicy := model.RejectPolicy{}
	tmpPolicy.CicdEnable = policy.Cicd
	tmpPolicy.K8sEnable = policy.K8sDeployment
	tmpPolicy.OnlineMonitor = policy.OnlineMonitor
	tmpPolicy.IsGlobal = true
	tmpPolicy.Mode = policy.Mode
	s.dbdal.AddGlobalPolicyConfig(ctx, tmpPolicy)
}

func (s *ConScannerSrv) TickOnlineScan(ctx context.Context, containerInfo []model.RejectOnlineMoniterImage) bool {
	resConfig := s.dbdal.GetGlobalPolicyConfig(ctx)
	tmpImageLists := []model.ImageList{}
	defaultKvHash := model.KVHash{}
	defaultKvHash.ZH.Key = "镜像来源仓库非法"
	msgType := consts.AlertKindK8s
	if strings.Contains(strings.ToLower(containerInfo[0].FromType), "k8s") {
		msgType = consts.AlertKindK8s
	} else if strings.Contains(strings.ToLower(containerInfo[0].FromType), "online") {
		msgType = consts.AlertKindOnline
	}
	// 判断是否已有扫描结果
	for k := range containerInfo {
		newLibrary := s.GetImageLibrary(containerInfo[k].Image)
		tmpImage := containerInfo[k].Image
		index := strings.Index(tmpImage, "/")
		tagIndex := strings.Index(tmpImage, ":")
		if newLibrary == "" || newLibrary == "index.docker.io" {
			if resConfig[0].Mode == "safe" {
				tmpImageList := model.ImageList{}
				if index != -1 {
					tmpImageList.Library = tmpImage[:index]
					tmpImageList.FullRepoName = tmpImage[index+1 : tagIndex]
				} else {
					tmpImageList.FullRepoName = tmpImage[tagIndex+1:]
				}
				s.CreateSafeReject(ctx, tmpImageList, msgType, 11, model.RejectNoLibraryZH)
				return false
			}
		}
		tmpLibrary := tmpImage[0:index]
		if strings.Contains(tmpLibrary, "http://") == false && strings.Contains(tmpLibrary, "https://") == false {
			tmpLibrary = "https://" + tmpLibrary
		}
		tmpFullRepoName := tmpImage[index+1 : tagIndex]
		tmpTag := tmpImage[tagIndex+1:]
		tmpImageList := model.ImageList{}
		tmpImageList.Library = tmpLibrary
		tmpImageList.FullRepoName = tmpFullRepoName
		tmpImageList.Tags = tmpTag
		s.log.WithContext(ctx).Infof("收到的镜像为: %v", tmpImageList)
		isInDB := s.dbdal.IsInRegistry(ctx, tmpLibrary)
		if isInDB == false && resConfig[0].Mode == "safe" {

			s.CreateSafeReject(ctx, tmpImageList, msgType, 11, model.RejectNoLibraryZH)
			return false
		}
		//tmpImageLists = append(tmpImageLists, tmpImageList)
		//_, cnt, _ := s.dbdal.SearchImageWhitelist(store.SearchImageWhitelistParam{
		//	Library:      tmpImageList.Library,
		//	FullRepoName: tmpImageList.FullRepoName,
		//	Tag:          tmpImageList.Tags,
		//}, nil)
		//if cnt == 0 {
		tmpImageLists = append(tmpImageLists, tmpImageList)
		//}
	}
	//if len(tmpImageLists) == 0 {
	//	return true // 全在白名单内
	//	}
	resIds := s.dbdal.GetK8sRejectImageList(ctx, tmpImageLists)
	if len(resIds) == 0 && resConfig[0].Mode == "safe" { //安全模式下不在我们数据库内
		s.CreateSafeReject(ctx, tmpImageLists[0], msgType, 11, model.RejectNoLibraryZH)
		return false
	} else if len(resIds) == 0 && resConfig[0].Mode == "base" {
		return true
	}
	var flag bool
	flag = true
	for k := range resIds {
		safe, kVHashs, _ := s.DetectImage(ctx, resIds[k], consts.UsePatternForK8s)
		s.log.WithContext(ctx).Infof("检测镜像")
		if len(kVHashs) > 0 {
			s.log.WithContext(ctx).Infof("发送事件中心")
			msg := model.NewReqBody(model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity), kVHashs)
			if err := sendMsgToEventcenter(ctx, msg); err != nil {
				s.log.WithContext(ctx).Errorf(err, "发送消息到事件中心出错 error:%s", err.Error())
			}
		}
		if safe == false {
			flag = false
		}
	}
	return flag

}

func (s *ConScannerSrv) AddPolicyConfig(ctx context.Context, policy model.RejectPolicyConfigResponse) {
	// policyIds := []int64{}
	for k := range policy.Polices {
		policy.Polices[k].CicdEnable = policy.Cicd
		policy.Polices[k].K8sEnable = policy.K8sDeployment
		policy.Polices[k].OnlineMonitor = policy.OnlineMonitor
		policy.Polices[k].LibraryJSON, _ = json.Marshal(policy.Polices[k].Library)
		s.dbdal.UpdatePolicy(ctx, policy.Polices[k])
		// policyIds = append(policyIds, policy.Polices[k].ID)
	}
	// s.dbdal.DeletePolicy(ctx, policyIds)
}

func (s *ConScannerSrv) AddSinglePolicy(ctx context.Context, policy model.RejectPolicyConfigResponse) (int64, error) {
	tmpPolicy := model.RejectPolicy{}
	tmpPolicy = policy.Polices[0]
	for k := range tmpPolicy.Library {
		if strings.Contains(policy.Polices[0].Library[k], "http://") == false && strings.Contains(policy.Polices[0].Library[k], "https://") == false {
			policy.Polices[0].Library[k] = "https://" + policy.Polices[0].Library[k]
		}
	}
	tmpPolicy.Mode = policy.Mode
	tmpPolicy.CicdEnable = policy.Cicd
	tmpPolicy.K8sEnable = policy.K8sDeployment
	tmpPolicy.OnlineMonitor = policy.OnlineMonitor
	tmpPolicy.LibraryJSON, _ = json.Marshal(policy.Polices[0].Library)
	var err error
	if tmpPolicy.ID == 0 {
		tmpPolicy.ID, err = s.dbdal.AddSinglePolicy(ctx, tmpPolicy)
		resConfig := s.dbdal.GetGlobalPolicyConfig(ctx)
		if len(resConfig) == 0 {
			tmpConfig := model.RejectPolicy{}
			tmpConfig.Mode = policy.Mode
			tmpConfig.CicdEnable = policy.Cicd
			tmpConfig.K8sEnable = policy.K8sDeployment
			tmpConfig.OnlineMonitor = policy.OnlineMonitor
			tmpConfig.IsGlobal = true
			s.dbdal.AddGlobalPolicyConfig(ctx, tmpConfig)
		}
	} else {
		s.dbdal.UpdatePolicy(ctx, tmpPolicy)
	}
	return tmpPolicy.ID, err
}

func (s *ConScannerSrv) GetPolicyConfig(ctx context.Context) (model.RejectPolicyConfigResponse, error) {
	PolicyRes, err := s.dbdal.GetPolicyConfig(ctx, true)
	if err != nil {
		return model.RejectPolicyConfigResponse{}, err
	}
	res := model.RejectPolicyConfigResponse{}
	// fmt.Println(PolicyRes)
	if len(PolicyRes) > 0 {
		res.Cicd = PolicyRes[0].CicdEnable
		res.K8sDeployment = PolicyRes[0].K8sEnable
		res.OnlineMonitor = PolicyRes[0].OnlineMonitor
		res.Mode = PolicyRes[0].Mode
		res.Polices = PolicyRes
		for k := range PolicyRes {
			json.Unmarshal(PolicyRes[k].LibraryJSON, &res.Polices[k].Library)
		}
		// res.Polices = PolicyRes
	} else {
		PolicyRes = s.dbdal.GetGlobalPolicyConfig(ctx)
		if len(PolicyRes) > 0 {
			res.Cicd = PolicyRes[0].CicdEnable
			res.K8sDeployment = PolicyRes[0].K8sEnable
			res.OnlineMonitor = PolicyRes[0].OnlineMonitor
			res.Mode = PolicyRes[0].Mode
		}
	}

	return res, nil
}

func (s *ConScannerSrv) CheckProjectAndCreateIfNotExist(ctx context.Context, library, projectName string) error {
	regi, err := s.getRegistry(ctx, library)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("can not connect harborV2"))
		return response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not connect harborV2 error is %s", err.Error())))
	}
	if err := regi.CheckProject(projectName); err != nil {
		if err := regi.CreateProject(projectName, true); err != nil {
			return response.NewHttpError(http.StatusInternalServerError, errors.New(fmt.Sprintf("can not create project error is %s", err.Error())))
		}
	}
	return nil
}

func (s *ConScannerSrv) ScanOneForDetectImage(ctx context.Context, library, projectName, fullRepoName, tag string, maxSecond int) (bool, error) {
	// cicd集成时，首先会把公司镜像推送到我们自己搭建的harborV2仓库中,然后拉取镜像进行扫描，
	// 通过library查registryID
	regs, _, err := s.dbdal.SearchRegistry(store.SearchRegistryParam{LibraryUrls: []string{library}}, nil)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("can not find the library:%s", library))
		return false, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not find the library:%s,error is %s", library, err.Error())))
	}
	if len(regs) == 0 {
		return false, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not find the library:%s", library)))
	}
	regi, err := s.getRegistry(ctx, library)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("can not connect harborV2"))
		return false, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not connect harborV2 error is %s", err.Error())))
	}
	image, err := regi.GetImage(projectName, fullRepoName, tag)
	if err != nil {
		return false, err
	}
	s.log.Info().Msg("从harbor获取到image:" + image.Repository + " " + image.ImageDigest)
	img := model.ImageList{
		FullRepoName:   image.Repository,
		Tags:           image.Tag,
		Digest:         image.ImageDigest,
		Size:           int(image.Size),
		Library:        library,
		RegistryId:     regs[0].ID,
		FirstPushTime:  image.Created,
		LastPushTime:   image.LastPushTime,
		LastPullTime:   image.LastPullTime,
		ManifestV1JSON: []byte(image.ManifestV1),
		ManifestV2JSON: []byte(image.ManifestV2),
		ConfigJson:     []byte(image.ConfigJson),
		CompleteTime:   image.Created.UTC().String(),
	}
	// 同步镜像到数据库
	imgId, err := s.scannerDB.InsertImageList(img)
	if err != nil {
		return false, err
	}
	// 下达扫描指令
	s.log.Info().Msg("下达扫描指令,imagId:" + strconv.Itoa(int(imgId)))
	if err := s.TickScanOne(ctx, imgId, "", consts.ScanTaskComeFromCICD); err != nil {
		return false, err
	}
	// 轮询查看扫描结果(默认1分钟)
	maxTimes := maxSecond / 10
	if maxTimes < 6 {
		maxTimes = 6
	}
	s.log.Info().Msg("扫描完成,imagId:" + strconv.Itoa(int(imgId)))

	for i := 1; i <= maxTimes; i++ {
		scanImage, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: []int64{imgId}, Status: model.ScanStatusSucceeded}, nil)
		if err != nil {
			return false, err
		}
		if len(scanImage) > 0 {
			s.log.Info().Msg("已查询到结果")
			break
		}
		s.log.Info().Msg(fmt.Sprintf("第%d次没有查询到结果", i))
		time.Sleep(time.Second * time.Duration(10))
	}
	safe, msgs, err := s.DetectImage(ctx, imgId, consts.UsePatternForCICD)
	// 向事件中心发送消息
	if len(msgs) > 0 {
		s.log.WithContext(ctx).Infof("向事件中心发送消息")
		msg := model.NewReqBody(model.NewEventCenterRule(consts.AlertKindCICD, consts.AlertModuleContainerSecurity, consts.ImageSecurity), msgs)
		if err := sendMsgToEventcenter(ctx, msg); err != nil {
			s.log.WithContext(ctx).Errorf(err, "发送消息到事件中心出错 error:%s", err.Error())
		}
	}
	return safe, err
}

func (s *ConScannerSrv) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	res := s.dbdal.GetSimpleImageDetail(ctx, tag, digest, library, fullRepoName)
	return res
}

func (s *ConScannerSrv) GetRelationImage(ctx context.Context, vulnImageLists []model.VulnImageList) ([]model.VulnDetailContainer, error) {
	res, err := s.dbdal.GetRelationImage(ctx, vulnImageLists)
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
	layers, _, err := s.dbdal.SearchScanLayer(store.SearchScanLayerParam{LayerDigests: []string{layerDigest}}, filter)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("ReportImgBackInfo.SearchScanLayer error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusBadRequest, err)
	}
	if len(layers) == 0 {
		s.log.WithContext(ctx).Errorf(err, "ImgLayerInfo.SearchScanLayer not fond the image layer")
		return nil, response.NewHttpError(http.StatusBadRequest, errors.New("not fond the layer"))
	}
	return &layers[0], nil
}

// ListImgLayers List  all layers  information  with  this image. order by created time
func (s *ConScannerSrv) ListImgLayers(ctx context.Context, imgDigest string, filter *model.Filter) ([]model.ReportImgBackInfo, error) {
	// step1 get image info
	imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{Digests: []string{imgDigest}}, nil)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("ReportImgBackInfo.SearchImage error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusBadRequest, err)
	}
	if len(imgs) == 0 {
		s.log.WithContext(ctx).Errorf(err, "ReportImgBackInfo.SearchImage not fond the image")
		return nil, response.NewHttpError(http.StatusBadRequest, errors.New("not fond thd image"))
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
		layers, _, err := s.dbdal.SearchScanLayer(store.SearchScanLayerParam{LayerDigests: layerDigests}, filter)
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("ReportImgBackInfo.SearchScanLayer error:%s", err.Error()))
			return nil, response.NewHttpError(http.StatusBadRequest, err)
		}
		// We don't have much data, so we just loop through two levels
		for i := range res {
			for j := range layers {
				if res[i].ImageDigest == layers[j].LayerDigest {
					// 软件包信息，恶意文件信息
					for k := range layers[j].VulnInfo {
						res[i].Vulus = append(res[i].Vulus, layers[j].VulnInfo[k].ID)
					}
					for k := range layers[j].SensitiveFile {
						res[i].SensitiveFiles = append(res[i].SensitiveFiles, layers[j].SensitiveFile[k].Name)
					}
					for k := range layers[j].MaliciousInfo {
						res[i].Malicious = append(res[i].Malicious, layers[j].MaliciousInfo[k].VirusInfo.VirusName)
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
	s.log.Info().Msg(fmt.Sprintf("全量扫描开始:%s", time.Now().Format("2006-01-02 15:04:05")))
	err := s.dbdal.SetAllImagePending(ctx)
	if err != nil {
		return err
	}
	start := time.Now().Unix()
	var lastID int64 = 0
	var bathSize int64 = 1000
	for {
		// step1: search image_list
		imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{BiggerID: lastID}, &model.Filter{
			PageSize:  bathSize, // 批量取
			PageIndex: 1,
			SortBy:    "asc",
			SortFiled: "id",
		})
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, "ScanAllNow.SearchImage error:%s", err.Error())
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
		scanImages, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: imgIds}, nil)
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, "ScanAllNow.SearchScanImage error:%s", err.Error())
			continue
		}
		scanImageMap := make(map[int64]*model.ScanImage)
		for _, si := range scanImages {
			scanImageMap[si.ImageId] = &si
		}

		for i := range imgs {
			if si, ok := scanImageMap[imgs[i].ID]; ok && si.Status == model.ScanStatusInProgress {
				continue
			}
			if err := s.TickScanOne(ctx, imgs[i].ID, fromUrl, consts.ScanTaskComeFromWeb); err != nil {
				s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("ScanAllNow.TickScanOne error:%s", err.Error()))
				continue
			}
		}

		if len(imgs) < int(bathSize) {
			break
		}
	}
	s.log.Info().Msg(fmt.Sprintf("全量扫描结束:%s,一共用时：%d 秒", time.Now().Format("2006-01-02 15:04:05"), time.Now().Unix()-start))
	return nil
}

func (s *ConScannerSrv) TickScanOne(ctx context.Context, imgId int64, fromUrl string, comeFrom int) error {
	resTask, resVirusTask, err := s.dbdal.GetTaskFromImageList(ctx, imgId, fromUrl, "")
	if err != nil {
		return err
	}
	s.log.Info().Msgf("task is :%v", resTask)
	s.redclair.AddScanTask(resTask, comeFrom)
	s.virusScan.AddScanTask(resVirusTask, comeFrom)
	return nil
}

func (s *ConScannerSrv) GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error) {
	scanStatus := "not_scan"
	res := model.ScanOneStatusResponse{ScanStatus: scanStatus, EndTime: time.Now().Format("2006-01-02 15:04:05")}
	imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{Ids: []int64{imgId}, Library: fromUrl}, nil)
	if err != nil {
		s.log.Error().Msg(fmt.Sprintf("GetScanOneStatus.SearchImage error:%s", err.Error()))
		return &res, nil
	}
	if len(imgs) == 0 {
		return &res, nil
	}
	// 查scan_image
	scs, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: []int64{imgs[0].ID}}, nil)
	if err != nil {
		s.log.Error().Msg(fmt.Sprintf("GetScanOneStatus.SearchScanImage error:%s", err.Error()))
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

func (s *ConScannerSrv) SearchAssetsContainers(ctx context.Context, digests []string, filter *model.Filter) ([]model.AssetContainer, int64, error) {
	cts, i, err := s.dbdal.SearchAssetsContainers(store.SearchAssetsContainersParam{Digests: digests, NotDeleted: store.TrueString}, filter)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("SearchAssetsContainers.SearchAssetsContainers error:%s", err.Error()))
		return nil, 0, response.NewHttpError(http.StatusBadRequest, err)
	}
	return cts, i, nil
}

func (s *ConScannerSrv) GetImageDetail(ctx context.Context, imgId int64) (*model.ImageList, error) {
	imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{Ids: []int64{imgId}}, nil)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("GetImageDetail.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	if len(imgs) == 0 {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("GetImageDetail.not find the image"))
		return nil, response.NewHttpError(http.StatusInternalServerError, errors.New("not find the image"))
	}

	img := &imgs[0]
	// 增加关联镜像的信息
	cts, _, err := s.dbdal.SearchAssetsContainers(store.SearchAssetsContainersParam{Digests: []string{img.Digest}, NotDeleted: store.TrueString}, nil)
	if err != nil {
		s.log.Error().Msg(fmt.Sprintf("SearchImages.SearchAssetsContainers:error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusGone, err)
	}
	img.Container = append(img.Container, cts...)

	// 查扫描结果
	scs, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: []int64{img.ID}}, nil)
	if err != nil {
		s.log.Error().Msg(fmt.Sprintf("SearchImages.SearchScanImage:error:%s", err.Error()))
		return nil, response.NewHttpError(http.StatusGone, err)
	}
	if len(scs) == 0 {
		s.log.Info().Msg("未找查到镜像扫描结果")
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
	}
	img.ImageScanVuln = imageScanResult
	// 增加病毒信息
	for i := range scs[0].MaliciousInfo {
		img.ImageScanVirus = append(img.ImageScanVirus,
			model.VirusFileInfo{Filename: scs[0].MaliciousInfo[i].VirusInfo.FileName,
				Filepath:  scs[0].MaliciousInfo[i].VirusInfo.FilePath,
				Virusname: scs[0].MaliciousInfo[i].VirusInfo.VirusName})
	}

	return img, nil
}

func (s *ConScannerSrv) GetImageOverView(ctx context.Context, registerUrl string) (*model.OverView, error) {
	overView := new(model.OverView)
	// 查总数
	_, total, err := s.dbdal.SearchImage(store.SearchImageParam{Library: registerUrl}, model.EmptyFilterForTheTotalQuery())
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("GetImageOverView.SearchImage error %s", err.Error()))
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}
	allResMap := make(map[string]map[string]*store.ImageGroup)

	for _, ty := range []string{VulnType, MaliciousInfoType, SensitiveFileType} {
		if err := s.getOverViewHelper(ctx, ty, overView, allResMap); err != nil {
			return nil, err
		}
	}

	// 查在线
	onlineSql := fmt.Sprintf("select distinct a.digest, a.library  from  %s a  join %s b  on  a.digest = b.digest ", store.ImageTable, store.ImageRelateTable)
	if registerUrl != "" {
		onlineSql = onlineSql + fmt.Sprintf(" AND a.library = %s ; ", registerUrl)
	} else {
		onlineSql = onlineSql + " ;"
	}
	onlineRes, err := s.dbdal.GetOnlineImage(store.GetOnlineImageParam{SQL: onlineSql})
	if err != nil {
		return nil, response.NewHttpError(http.StatusInternalServerError, err)
	}

	for i := range onlineRes {
		on, ok := allResMap[fmt.Sprintf("%s_%s", onlineRes[i].Digest, onlineRes[i].Library)]
		if !ok {
			continue
		}
		if on[VulnType] != nil {
			overView.Online.VULN += on[VulnType].Count
		}
		if on[MaliciousInfoType] != nil {
			overView.Online.VIRUS += on[MaliciousInfoType].Count
		}
		if on[SensitiveFileType] != nil {
			overView.Online.SENSITIVE += on[SensitiveFileType].Count
		}
	}
	overView.ImageTotal = total
	overView.OnlineTotal = int64(len(onlineRes))
	return overView, nil
}

// getOverViewHelper 连表查询tensor_image_list和scan_image表，查询各个镜像下漏洞，病毒等的数据
func (s *ConScannerSrv) getOverViewHelper(ctx context.Context, searchType string, overView *model.OverView, allResMap map[string]map[string]*store.ImageGroup) error {
	hasVuluSql := fmt.Sprintf("select count(b.image_id), b.image_id,a.digest, a.library from %s a join %s b on a.id = b.image_id where  b.%s is not null group by b.image_id,a.digest,  a.library;", store.ImageTable, store.ImageScanTable, searchType)

	hasVuluRes, err := s.dbdal.GetImageOverView(store.GetImageOverViewParm{SQL: hasVuluSql})
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
		case VulnType:
			overView.Sum.VULN += hasVuluRes[i].Count
		case PkgType:
			overView.Sum.Pkg += hasVuluRes[i].Count
		case SensitiveFileType:
			overView.Sum.SENSITIVE += hasVuluRes[i].Count
		case MaliciousInfoType:
			overView.Sum.VIRUS += hasVuluRes[i].Count
		}
	}
	return nil
}

func (s *ConScannerSrv) SearchImages(ctx context.Context, searchWord, kind string, isOnline bool, filter *model.Filter) ([]model.ImageList, int64, error) {

	filter = filter.SetDefault()
	filter.SortFiled = "id"
	filter.SortBy = "asc"
	param := store.SearchImageParam{}
	// 种类的搜索
	if kind != "" {
		kindImageId := make([]int64, 0)
		qs, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{Kind: kind, NoSerialization: true}, nil)
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, "SearchQuestionInfo error:%s", err.Error())
			return nil, 0, response.NewHttpError(http.StatusGone, err)
		}
		for i := range qs {
			kindImageId = append(kindImageId, qs[i].ImageId)
		}
		if len(kindImageId) == 0 {
			s.log.Info().Msg("SearchScanImage not fond scan image")
			return []model.ImageList{}, 0, nil
		}
		param.Ids = kindImageId
	}

	if searchWord != "" {
		split := strings.Split(searchWord, ":")
		if len(split) > 0 {
			param.FullRepoSearch = split[0]
		}
		if len(split) > 1 {
			param.TagSearch = split[1]
		}
	}
	if isOnline {
		onlineSql := fmt.Sprintf("select distinct a.digest, a.library  from  %s a  join %s b  on  a.digest = b.digest ;", store.ImageTable, store.ImageRelateTable)
		online, err := s.dbdal.GetOnlineImage(store.GetOnlineImageParam{SQL: onlineSql})
		if err != nil {
			return nil, 0, response.NewHttpError(http.StatusInternalServerError, err)
		}
		onlineDigests := make([]string, 0)
		for _, im := range online {
			onlineDigests = append(onlineDigests, im.Digest)
		}
		if len(onlineDigests) == 0 {
			s.log.Info().Msg("GetOnlineImage not fond scan image")
			return []model.ImageList{}, 0, nil
		}
		param.Digests = onlineDigests
	}

	imgs, cnt, err := s.dbdal.SearchImage(param, filter)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, "SearchImages.SearchImage error :%s", err.Error())
		return nil, 0, response.NewHttpError(http.StatusGone, err)
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

	// 为了兼容前端把questionInfo信息加上
	scs, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: imageIds, NoSerialization: true}, nil)
	if err != nil {
		s.log.Error().Msg(fmt.Sprintf("SearchImages.SearchScanImage:error:%s", err.Error()))
		return nil, 0, response.NewHttpError(http.StatusGone, err)
	}

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
		scMap[sc.ImageId] = qus
	}

	for i := range imgs {
		if qs, ok := scMap[imgs[i].ID]; ok {
			imgs[i].Questions = qs
		} else {
			imgs[i].Questions = make([]model.QuestionInfo, 0) // 防止null
		}
	}
	return imgs, cnt, nil
}

func (s *ConScannerSrv) getRegistry(ctx context.Context, library string) (registry.Registry, error) {
	// cicd集成时，首先会把公司镜像推送到我们自己搭建的harborV2仓库中,然后拉取镜像进行扫描，
	// 通过library查registryID
	regs, _, err := s.dbdal.SearchRegistry(store.SearchRegistryParam{LibraryUrls: []string{library}}, nil)
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("can not find the library:%s", library))
		return nil, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not find the library:%s,error is %s", library, err.Error())))
	}
	if len(regs) == 0 {
		return nil, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not find the library:%s", library)))
	}
	decryPass, err := util.DesDecrypt(regs[0].Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		return nil, errors.New("decrypt error:%s" + err.Error())
	}

	regi, err := registry.Open(registry.RegistrableComponentConfig{
		Type: harborv2.HarborVersion,
		Options: map[string]interface{}{
			"url":           regs[0].Url,
			"password":      string(decryPass),
			"username":      regs[0].Username,
			"skiptlsverify": true,
		},
	})
	if err != nil {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("can not connect harborV2"))
		return nil, response.NewHttpError(http.StatusBadGateway, errors.New(fmt.Sprintf("can not connect harborV2 error is %s", err.Error())))
	}
	return regi, nil
}

// DetectImage  判断该镜像是否安全
func (s *ConScannerSrv) DetectImage(ctx context.Context, imageId int64, usePattern string) (bool, []model.KVHashs, error) {
	imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{Ids: []int64{imageId}}, nil)
	// 如果没有在数据库没有查到镜像，默认安全
	if err != nil || len(imgs) == 0 {
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("没有查到镜像"))
		return true, nil, nil
	}
	img := imgs[0]
	policies, err := s.dbdal.SearchRejectPolicy(store.SearchRejectPolicyParam{Library: img.Library})
	if err != nil || len(policies) == 0 { // 没有策略说明不检测，默认全安全
		s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("没有查到策略:Library:%s", img.Library))
		return true, nil, nil
	}

	scanImage, _, err := s.dbdal.SearchScanImage(store.SearchScanImageParam{ImageIds: []int64{imageId}, Status: model.ScanStatusSucceeded}, nil)
	if err != nil {
		return false, nil, err
	}
	// 安全模式只针对k8s部署，对于cicd是要全检测
	if len(scanImage) == 0 {
		if usePattern == consts.UsePatternForK8s {
			// 检测模式是全局的，所以取第一个既可
			switch policies[0].Mode {
			case model.RejectPolicyBaseModel:
				return true, nil, nil
			case model.RejectPolicySafeModel:
				return false, nil, errors.New("not scanned")
			default:
				return true, nil, nil
			}
		}
		if usePattern == consts.UsePatternForCICD {
			return false, nil, nil
		}
	}
	scanRes := scanImage[0]
	// 逐个验证
	safe := true
	records := make([]ReasonAndDetail, 0)
	msgs := make([]model.KVHashs, 0)

	for _, po := range policies {
		if !po.Enable || (usePattern == consts.UsePatternForCICD && !po.CicdEnable) || (usePattern == consts.UsePatternForK8s && !po.K8sEnable) || po.IsGlobal {
			continue
		}
		//  验证恶意文件
		if len(scanRes.MaliciousInfo) > 0 {
			s.log.WithContext(ctx).Infof("包含恶意文件,imagId:" + strconv.Itoa(int(img.ID)))

			msgZh := fmt.Sprintf("镜像:%s:%s 存在恶意文件", img.FullRepoName, img.Tags)
			msgEN := fmt.Sprintf("image:%s:%s Exist malicious file", img.FullRepoName, img.Tags)

			switch po.MaliciousPolicy {

			case model.RejectPolicyReject:
				safe = false
				records = append(records, ReasonAndDetail{
					RejectReason: model.RejectReasonHasMalicious,
					RejectDetail: msgZh,
				})

				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.RejectReasonHasMaliciousZH, msgZh),
						EN: model.NewKeyValue(model.RejectReasonHasMaliciousEN, msgEN)}})

			case model.RejectPolicyAlarm:
				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.RejectReasonHasSensitiveFileZH, msgZh),
						EN: model.NewKeyValue(model.RejectReasonHasSensitiveFileEN, msgEN)}})

			}
		}
		// 验证敏感文件
		if len(scanRes.SensitiveFile) > 0 {
			msgZh := fmt.Sprintf("镜像:%s:%s 存在敏感文件", img.FullRepoName, img.Tags)
			msgEN := fmt.Sprintf("Image:%s:%s Exist sensitive file", img.FullRepoName, img.Tags)
			s.log.WithContext(ctx).Infof("包含敏感文件,imagId:" + strconv.Itoa(int(img.ID)))
			switch po.SensitiveFilePolicy {
			case model.RejectPolicyReject:
				safe = false
				records = append(records, ReasonAndDetail{
					RejectReason: model.RejectReasonHasSensitiveFile,
					RejectDetail: msgZh,
				})

				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.RejectReasonHasSensitiveFileZH, msgZh),
						EN: model.NewKeyValue(model.RejectReasonHasSensitiveFileEN, msgEN)}})
			case model.RejectPolicyAlarm:
				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.RejectReasonHasSensitiveFileZH, msgZh),
						EN: model.NewKeyValue(model.RejectReasonHasSensitiveFileEN, msgEN)}})
			}
		}

		// 检查漏洞
		// 1.先检查自定义漏洞
		customizeVuluMap := make(map[string]model.RejectVuln)
		for i := range po.RejectVulns {
			customizeVuluMap[po.RejectVulns[i].Name] = po.RejectVulns[i]
		}

		for _, vu := range scanRes.VulnInfo {
			// 先检查自定义漏洞规则
			if svn, ok := customizeVuluMap[vu.ID]; ok {
				s.log.WithContext(ctx).Infof("包含自定义漏洞,imagId:" + strconv.Itoa(int(img.ID)))
				msgZh := fmt.Sprintf("镜像:%s:%s 存在自定义漏洞：%s", img.FullRepoName, img.Tags, vu.ID)
				msgEN := fmt.Sprintf("Image:%s:%s Exist custom vulnerability：%s", img.FullRepoName, img.Tags, vu.ID)
				switch svn.RejectPolicy {
				case model.RejectPolicyReject:
					safe = false
					records = append(records, ReasonAndDetail{
						RejectReason: model.RejectReasonHasCustomizeVuln,
						RejectDetail: msgZh,
					})

					msgs = append(msgs, model.KVHashs{
						KVHash: model.KVHash{
							ZH: model.NewKeyValue(model.RejectReasonHasCustomizeVulnZH, msgZh),
							EN: model.NewKeyValue(model.RejectReasonHasCustomizeVulnEN, msgEN)}})
				case model.RejectPolicyAlarm:
					msgs = append(msgs, model.KVHashs{
						KVHash: model.KVHash{
							ZH: model.NewKeyValue(model.RejectReasonHasCustomizeVulnZH, msgZh),
							EN: model.NewKeyValue(model.RejectReasonHasCustomizeVulnEN, msgEN)}})
				case model.RejectPolicyIgnore:
					// 如果自定义了忽略就不再检查评分和评级
					continue
				}
			}
			//  如果配置了漏洞分数,
			if po.VulnScore > 0 && CalculateVulnScore(vu.Severity) < po.VulnScore {
				safe = false
				msgZh := fmt.Sprintf("漏洞:%s 扫描后评分:%d 低于漏洞阻断分数：%d", vu.ID, CalculateVulnScore(vu.Severity), po.VulnScore)
				msgEN := fmt.Sprintf("Vulnerability:%s rate %d Lower than : %d", vu.ID, CalculateVulnScore(vu.Severity), po.VulnScore)
				s.log.WithContext(ctx).Infof("配置了漏洞分数," + msgZh)

				records = append(records, ReasonAndDetail{
					RejectReason: model.RejectReasonScore,
					RejectDetail: msgZh,
					VulnScore:    po.VulnScore,
				})
				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.RejectReasonScoreZH, msgZh),
						EN: model.NewKeyValue(model.RejectReasonScoreEN, msgEN)}})
			}
			// 如果配置了漏洞评级
			if po.VulnLevel != "" && compareSeverity(vu.Severity, po.VulnLevel) {
				safe = false
				msgZh := fmt.Sprintf("漏洞:%s扫描后被评级:%s 高于漏洞阻断评级：%s", vu.ID, vu.Severity, po.VulnLevel)
				msgEN := fmt.Sprintf("Vulnerability:%s Rate %s more than %s", vu.ID, vu.Severity, po.VulnLevel)
				s.log.WithContext(ctx).Infof("配置了漏洞评级," + msgZh)

				records = append(records, ReasonAndDetail{
					RejectReason: getSeverityRejectReason(vu.Severity),
					RejectDetail: msgZh,
					VulnLevel:    po.VulnLevel,
				})

				msgs = append(msgs, model.KVHashs{
					KVHash: model.KVHash{
						ZH: model.NewKeyValue(model.GetVuluRuleKey(vu.Severity, model.LangCh), msgZh),
						EN: model.NewKeyValue(model.GetVuluRuleKey(vu.Severity, model.LangEn), msgEN)}})
			}
		}
	}

	// 检查白名单,要检查一下Digest,防止通过Library+FullRepoName+Tags的方式绕过检测
	// 镜像存在白名单中，只是不阻断，任然要进行扫描检测，对检测结果仍然要发事件中心
	if !safe {
		wl, _, err := s.dbdal.SearchImageWhitelist(store.SearchImageWhitelistParam{
			Library:      img.Library,
			FullRepoName: img.FullRepoName,
			Tag:          img.Tags,
			Digest:       img.Digest,
		}, nil)
		if err != nil || len(wl) > 0 {
			return true, msgs, nil
		}
	}

	if len(records) > 0 {
		res := mergeRejectRecord(img, records)
		if _, err := s.dbdal.CreateRejectRecord(res); err != nil {
			s.log.WithContext(ctx).Errorf(err, "存储阻断记录出错 error %s", err.Error())
		}
	}

	return safe, msgs, nil
}

func NewConScannerSrv(dbdal store.ScannerDalInterface,
	redclair *RedClairService,
	virusScan *VirusScan,
	scdb *store.ScannerDB,
	globalCache *cache.Cache,
) *ConScannerSrv {

	return &ConScannerSrv{
		dbdal:       dbdal,
		log:         logging.GetLogger(),
		redclair:    redclair,
		virusScan:   virusScan,
		scannerDB:   scdb,
		globalCache: globalCache,
	}
}

func CalculateVulnScore(severity string) int64 {
	// 就先写魔法数字吧，恶心是恶心了点
	subScore := map[string]int64{
		"Critical":   25,
		"High":       20,
		"Medium":     15,
		"Low":        10,
		"Negligible": 5,
		"Unknown":    5,
	}
	return 50 - subScore[severity]
}

func compareSeverity(s1, s2 string) bool {
	subScore := map[string]int64{
		"Critical":   6,
		"High":       5,
		"Medium":     4,
		"Low":        3,
		"Negligible": 2,
		"Unknown":    1,
	}
	return subScore[s1] >= subScore[s2]
}

func getSeverityRejectReason(severity string) int64 {
	subScore := map[string]int64{
		"Critical":   model.RejectReasonHasCriticalVuln,
		"High":       model.RejectReasonHasHighVuln,
		"Medium":     model.RejectReasonHasMediumVuln,
		"Low":        model.RejectReasonHasLowVuln,
		"Negligible": model.RejectReasonHasNegligibleVuln,
		"Unknown":    model.RejectReasonHasUnknownVuln,
	}
	return subScore[severity]
}

// 发送消息到事件中心
func sendMsgToEventcenter(ctx context.Context, reqBody model.ReqBody) error {
	caCert, err := ioutil.ReadFile(consts.GRPC_CA_PATH)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("打开/auth/ca/tls.crt出错")
		return err
	}

	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(caCert) {
		return err
	}

	cert, err := tls.LoadX509KeyPair(consts.HTTPS_CLIENT_CERT_PATH, consts.HTTPS_CLIENT_PRIVATE_KEY)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("LoadX509KeyPair/eventcenter-config/tls.crt出错")
		return err
	}

	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      clientCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	JSONBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	logging.GetLogger().Info().Msg(fmt.Sprintf("CICD消息内容：%s", string(JSONBytes)))

	host := consts.TENSORSEC_EVENTCENTER_SERVICE_HOST
	port := os.Getenv("TENSORSEC_EVENTCENTER_SERVICE_PORT_EVENTCENTER_HTTP")
	if port == "" {
		port = consts.TENSORSEC_EVENTCENTER_SERVICE_PORT_EVENTCENTER_HTTP
	}

	uri := fmt.Sprintf("%s:%s%s", host, port, consts.EventcenterURI)

	logging.GetLogger().WithContext(ctx).Infof("请求事件中心的URI:%s", uri)

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(JSONBytes))
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("请求事件中心 http.NewRequest error :%s", err.Error())
		return err
	}

	rsp, err := cli.Do(req)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Infof("请求事件中心 cli.Do(req) error :%s", err.Error())
		return err
	}
	defer rsp.Body.Close()
	body, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode >= http.StatusMultipleChoices || rsp.StatusCode < http.StatusOK {
		logging.GetLogger().WithContext(ctx).Infof(fmt.Sprintf("CICD镜像阻断发送到事件中心出错,出错信息:%s", string(body)))
		return errors.New(string(body))
	}
	return nil
}

func mergeRejectRecord(img model.ImageList, record []ReasonAndDetail) model.RejectRecord {
	res := model.RejectRecord{
		Library:      img.Library,
		FullRepoName: img.FullRepoName,
		Tag:          img.Tags,
		RejectAt:     time.Now().UTC(),
	}

	reasonMap := make(map[int64]int64)
	reasonDetailMap := make(map[string]int64)
	reasons := make([]int64, 0)
	reasonDetails := make([]string, 0)

	for i := range record {
		if reasonMap[record[i].RejectReason] < 1 {
			reasons = append(reasons, record[i].RejectReason)
			reasonMap[record[i].RejectReason]++
		}

		if reasonDetailMap[record[i].RejectDetail] < 1 {
			reasonDetails = append(reasonDetails, record[i].RejectDetail)
			reasonDetailMap[record[i].RejectDetail]++
		}
		// 对同一个仓库来说，只会设置一个阻断评分和阻断级别,所以这里可以直接在循环中更新值
		if record[i].VulnScore > 0 {
			res.VulnScore = record[i].VulnScore
		}
		if record[i].VulnLevel != "" {
			res.VulnLevel = record[i].VulnLevel
		}
	}
	reasonsDuplication := make(map[string]string)
	for _, r := range reasons {
		reasonsDuplication[strconv.Itoa(int(r))] = strconv.Itoa(int(r))
	}
	if bys, err := json.Marshal(reasonsDuplication); err == nil {
		res.RejectReasonJson = bys
	}
	res.RejectDetail = strings.Join(reasonDetails, "|")
	return res
}

func (s *ConScannerSrv) GetImageLibrary(imageName string) string {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		fmt.Println("parse image name err", err)
		return ""
	}

	repo := ref.Context()

	registryStr := repo.RegistryStr()
	return registryStr
}

func (s *ConScannerSrv) CreateSafeReject(ctx context.Context, ImageList model.ImageList, msgType string, reason int64, detail string) {
	defaultKvHash := model.KVHash{}
	defaultKvHash.ZH.Key = "镜像来源仓库非法"
	defaultKvHash.ZH.Value = "模式:安全模式 镜像:" + ImageList.Library + "/" + ImageList.FullRepoName + ":" + ImageList.Tags
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
	res := mergeRejectRecord(img, tmpReasonAndDetails)
	if _, err := s.dbdal.CreateRejectRecord(res); err != nil {
		s.log.WithContext(ctx).Errorf(err, "存储阻断记录出错 error %s", err.Error())
	}
	msg := model.NewReqBody(model.NewEventCenterRule(msgType, consts.AlertModuleContainerSecurity, consts.ImageSecurity), tmpHashs)
	if err := sendMsgToEventcenter(ctx, msg); err != nil {
		s.log.WithContext(ctx).Errorf(err, "发送消息到事件中心出错 error:%s", err.Error())
	}
}

type ReasonAndDetail struct {
	RejectReason int64
	RejectDetail string
	VulnScore    int64
	VulnLevel    string
}
