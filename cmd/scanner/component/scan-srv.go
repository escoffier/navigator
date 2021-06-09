package component

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	topVulnsNumber = 5
)
const (
	VulnType          = "vuln_info_json"
	PkgType           = "pkg_info_json"
	SensitiveFileType = "sensitive_file_json"
	MaliciousInfoType = "malicious_info_json"
)

type ScannerSrv interface {
	SearchAssetsContainers(ctx context.Context, digests []string, filter *model.Filter) ([]model.AssetContainer, int64, error)
	SearchImages(ctx context.Context, searchWord, kind string, isOnline bool, filter *model.Filter) ([]model.ImageList, int64, error)
	GetImageDetail(ctx context.Context, imgId int64) (*model.ImageList, error)
	GetImageOverView(ctx context.Context, registerUrl string) (*model.OverView, error)
	GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error)
	TickScanOne(ctx context.Context, imgId int64, fromUrl string) error
	ScanAllNow(ctx context.Context, fromUrl string) error
	GetScanAllStatus(ctx context.Context) harbor.ScanAllStatus
	GetVulnOverView(ctx context.Context) (model.VulnOverview, error)
	ListImgLayers(ctx context.Context, imgDigest string, filter *model.Filter) ([]model.ReportImgBackInfo, error)
	ImgLayerInfo(ctx context.Context, layerDigest string, filter *model.Filter) (*model.ScanLayer, error)
	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)
	GetRelationImage(ctx context.Context, vulnImageLists []model.VulnImageList) ([]model.VulnDetailContainer, error)
	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail
}

type ConScannerSrv struct {
	dbdal     store.ScannerDalInterface
	log       *logging.Logger
	redclair  *RedClairService
	virusScan *VirusScan
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

			resTask, resVirusTask, err := s.dbdal.GetTaskFromImageList(ctx, imgs[i].ID, fromUrl)
			if err != nil {
				s.log.WithContext(ctx).Errorf(err, fmt.Sprintf("ScanAllNow.GetTaskFromImageList error:%s", err.Error()))
				continue
			}
			s.redclair.AddScanTask(resTask)
			s.virusScan.AddScanTask(resVirusTask)
		}

		if len(imgs) < int(bathSize) {
			break
		}
	}
	s.log.Info().Msg(fmt.Sprintf("全量扫描结束:%s,一共用时：%d 秒", time.Now().Format("2006-01-02 15:04:05"), time.Now().Unix()-start))
	return nil
}

func (s *ConScannerSrv) TickScanOne(ctx context.Context, imgId int64, fromUrl string) error {
	resTask, resVirusTask, err := s.dbdal.GetTaskFromImageList(ctx, imgId, fromUrl)
	if err != nil {
		return err

	}
	s.redclair.AddScanTask(resTask)
	s.virusScan.AddScanTask(resVirusTask)
	return nil
}

func (s *ConScannerSrv) GetScanOneStatus(ctx context.Context, imgId int64, fromUrl string) (*model.ScanOneStatusResponse, error) {
	scanStatus := "not_scan"
	res := model.ScanOneStatusResponse{ScanStatus: scanStatus, EndTime: time.Now().Format("2006-01-02 15:04:05")}
	imgs, _, err := s.dbdal.SearchImage(store.SearchImageParam{
		Ids:     []int64{imgId},
		Library: fromUrl,
	}, nil)
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

func NewConScannerSrv(dbdal store.ScannerDalInterface,
	redclair *RedClairService,
	virusScan *VirusScan,
) *ConScannerSrv {
	return &ConScannerSrv{
		dbdal:     dbdal,
		log:       logging.GetLogger(),
		redclair:  redclair,
		virusScan: virusScan,
	}
}
