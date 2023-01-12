package html

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像列表搜索的安全报告
type ExportImageHtmlSrv struct {
	ImageSrv      common.ImageInterface
	VulnDal       store.VulnDalInterface
	ExportTaskDal store.ExportTaskDal
	UpdateTask    common.UpdateExportTask
	KoaAddr       string // 生成html的内部服务接口
	FileDir       string // 文件存放的绝对路径
}

func NewExportImageHtmlSrv(
	imageSrv common.ImageInterface,
	vulnDal store.VulnDalInterface,
	exportTaskDal store.ExportTaskDal,
	updateTask common.UpdateExportTask,
	fileDir string,
) *ExportImageHtmlSrv {
	return &ExportImageHtmlSrv{
		ImageSrv:      imageSrv,
		VulnDal:       vulnDal,
		ExportTaskDal: exportTaskDal,
		UpdateTask:    updateTask,
		FileDir:       fileDir,
		KoaAddr:       consts.KoaAddr,
	}
}

const (
	MaxVulnImages = 5000
	DefaultLimit  = 1000
	MaxImages     = 500
)

// 获取镜像ID和Name用于生成目录
func (s *ExportImageHtmlSrv) GetImageIdNames(ctx context.Context, taskID int64) (*ImageIDNameWithTask, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetImageIdNames start")
	images := make([]ImageIDName, 0)
	var lastImageID int64

	// 分批获取镜像
	for {
		filter := &model.Filter{Limit: consts.DefaultExportBathSize, SortFiled: "image_id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: lastImageID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetImageIdNames.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Int("image-id-length", len(images)).Msg("ExportImageHtmlSrv GetImageIdNames finished")
			break
		}
		lastImageID = taskImages[len(taskImages)-1].ImageID

		for i := range taskImages {
			images = append(images, ImageIDName{
				ImageID:   taskImages[i].ImageID,
				ImageName: taskImages[i].ImageName,
			})
		}
	}

	logging.Get().Info().Int64("taskID", taskID).Int("image-length", len(images)).Msg("ExportImageHtmlSrv.GetImageIdNames finished")
	return &ImageIDNameWithTask{TaskId: taskID, Images: images}, nil
}

// 镜像信息列表
func (s *ExportImageHtmlSrv) GetImages(ctx context.Context, taskID int64, starID int64) (*ImageResponse, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Msg("ExportImageHtmlSrv.GetImages")

	res := &ImageResponse{
		Images: make([]Image, 0),
	}
	// 分批获取镜像
	for {
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: starID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("startID", starID).Msg("GetImages.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetImages finished")
			res.End = true
			break
		}
		starID = taskImages[len(taskImages)-1].ID
		res.StartID = starID
		imageIds := make([]int64, 0)

		param := model.GetImageAssociateDataParam{
			VulnEnable:      true,
			VirusEnable:     true,
			SensitiveEnable: true,
			WebshellEnable:  true,
		}
		for i := range taskImages {
			param.ImageId = taskImages[i].ImageID
			image, err := s.ImageSrv.GetImageCorrelateData(ctx, param)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("startID", starID).Msg("ExportImageHtmlSrv GetImages.ListImageWithScanInfo")
				return nil, err
			}
			baseImage := image.ToImageBaseResponse()

			im := Image{
				ImageID:       baseImage.ID,
				ImageName:     baseImage.GetImageName(),
				FixedVuln:     VulnSeverityCount{},
				UnFixedVuln:   VulnSeverityCount{},
				Malicious:     int64(len(image.Virus)),
				RiskScore:     baseImage.RiskScore,
				NotMaintained: util.ExistBit1(baseImage.Flag, model.FlagImageNotMaintained),
				Flag:          baseImage.Flag,
			}
			im.AddVulnSeverityCount(image.Vuln)
			res.Images = append(res.Images, im)

			imageIds = append(imageIds, taskImages[i].ImageID)
		}

		if len(res.Images) > MaxImages {
			logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).Msg("ExportImageHtmlSrv.GetImages partially completed")
			break
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).Msg("ExportImageHtmlSrv.GetImages")
	return res, nil
}

// 风险总览
func (s *ExportImageHtmlSrv) GetRiskOverView(ctx context.Context, taskID int64) (*RiskOverView, error) {
	overView, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, model.ExportHtmlPrepareRiskOver)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetRiskOverView")
		return nil, fmt.Errorf("GetRiskOverView %d error :%s", taskID, err.Error())
	}
	if len(overView) == 0 {
		return nil, fmt.Errorf("not GetRiskOverView taskID: %d", taskID)
	}
	risk := &RiskOverView{}

	if err := json.Unmarshal([]byte(overView[0].Data), risk); err != nil {
		return nil, fmt.Errorf("GetRiskOverView:%d error: %s", taskID, err.Error())
	}

	return risk, nil
}

// 病毒列表
func (s *ExportImageHtmlSrv) GetVirus(ctx context.Context, taskID int64) ([]VirusInfo, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetVirus start")
	var startID int64
	res := make([]VirusInfo, 0)

	virusMap := make(map[int64]*model.ImageVirus)
	virusToImage := make(map[int64][]string)
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: startID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetVirus.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetVirus finished")
			break
		}
		startID = taskImages[len(taskImages)-1].ID

		for i := range taskImages {
			image, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{ImageId: taskImages[i].ImageID, VirusEnable: true})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", taskImages[i].ImageID).Msg("ExportImageHtmlSrv GetVirus")
				return nil, err
			}
			for k := range image.Virus {

				vir := image.Virus[k]
				virusMap[vir.ID] = vir
				if virusToImage[vir.ID] == nil {
					virusToImage[vir.ID] = make([]string, 0)
				}
				virusToImage[vir.ID] = append(virusToImage[vir.ID], image.ImageBaseResponse.GetImageName())
			}
		}
	}
	// 拼装数据
	for v, ima := range virusMap {
		vi := VirusInfo{
			FilePath:  ima.Filepath,
			VirusName: ima.Name,
			Images:    virusToImage[v],
		}
		if vi.Images == nil {
			vi.Images = make([]string, 0)
		}
		res = append(res, vi)
	}

	logging.Get().Info().Int64("taskID", taskID).Int("virus-length", len(res)).Msg("ExportImageHtmlSrv.GetVirus finished")

	return res, nil
}

// 按层取漏洞信息 canFixed:"true"，取可修复的，"false"取不可修复的，""表示取全部
func (s *ExportImageHtmlSrv) GetExportVulns(ctx context.Context, taskID int64, severity int, canFixed string, starID, limit int64) (*VulnWithImageResponse, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	logging.Get().Info().Int64("taskID", taskID).Int("severity", severity).Str("canFixed", canFixed).Int64("startID", starID).Msg("ExportImageHtmlSrv.GetExportVulns start")

	res := &VulnWithImageResponse{
		Vulns: make([]VulnWithImage, 0),
	}
	uniqueVulns := make([]uint64, 0)
	// 分批获取漏洞
	filter := &model.Filter{Limit: limit, SortFiled: "id", SortBy: consts.SortByAsc}
	vulnImages, err := s.ExportTaskDal.SearchHtmlVulnImage(ctx, store.SearchHtmlVulnImageParam{
		TaskID: taskID, StartID: starID, Severity: severity, CanFixed: canFixed}, filter)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetExportVulns SearchExportTaskImage")
		return nil, err
	}
	if len(vulnImages) < int(limit) {
		res.End = true
	}
	for i := range vulnImages {
		res.StartID = vulnImages[i].ID
		uniqueVulns = append(uniqueVulns, vulnImages[i].UniqueVuln)
		res.Vulns = append(res.Vulns, VulnWithImage{
			Images:     vulnImages[i].Images,
			UniqueVuln: vulnImages[i].UniqueVuln,
		})
	}

	// 查漏洞详情
	if len(uniqueVulns) > 0 {
		vulns, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{
			UniqueVulns:    uniqueVulns,
			ClassType:      []string{report.ClassOSPkg, report.ClassConfig},
			NotReturnCount: true,
		}, nil)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetExportVulns SearchExportTaskImage")
			return nil, err
		}
		vulnMap := make(map[uint64]*model.Vuln)
		for i := range vulns {
			vulnMap[vulns[i].UniqueVuln] = vulns[i]
		}
		for i := range res.Vulns {
			res.Vulns[i].VulnDetail = ModelToVulnDetail(vulnMap[res.Vulns[i].UniqueVuln])
		}
	}

	logging.Get().Info().Int64("taskID", taskID).Int("severity", severity).Str("canFixed", canFixed).Int("vulns", len(res.Vulns)).
		Int64("startID", starID).Bool("isEnd", res.End).Msg("ExportImageHtmlSrv.GetExportVulns finished")
	return res, nil
}

// 按层级获取镜像的漏洞信息
func (s *ExportImageHtmlSrv) GetImageVulns(ctx context.Context, taskID, imageID int64, severity int, startID int64) (*VulnWithImageResponse, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Int("severity", severity).Msg("ExportImageHtmlSrv.GetImageVulns start")
	res := &VulnWithImageResponse{
		ImageID: imageID,
		Vulns:   make([]VulnWithImage, 0),
	}
	count := 0
	// 获取镜像的漏洞统计信息信息
	vulns, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{StartID: startID,
		ClassType:      []string{report.ClassOSPkg, report.ClassConfig},
		NotReturnCount: true,
		ImageIds:       []int64{imageID}, SeverityInt: []int64{int64(severity)}},
		&model.Filter{SortFiled: "id", SortBy: consts.SortByAsc})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImageVulns SearchVuln")
		return nil, err
	}
	if len(vulns) == 0 {
		res.End = true
	}
	// 整理漏洞
	uniqueVulns := make([]uint64, 0)
	vulnMap := make(map[uint64]*model.Vuln) // 单个镜像的漏洞，不致于OOM

	for j := range vulns {
		vuln := vulns[j]
		res.StartID = vuln.ID
		vulnMap[vuln.UniqueVuln] = vuln
		uniqueVulns = append(uniqueVulns, vuln.UniqueVuln)
		if (j >= len(vulns)-1 && len(uniqueVulns) > 0) || len(uniqueVulns) >= consts.DefaultLimit {
			vulnImage, err := s.ExportTaskDal.SearchHtmlVulnImage(ctx, store.SearchHtmlVulnImageParam{TaskID: taskID, UniqueVulns: uniqueVulns}, nil)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("ExportImageHtmlSrv GetImageVulns SearchHtmlVulnImage")
				return nil, err
			}
			for k := range vulnImage {
				res.Vulns = append(res.Vulns, VulnWithImage{Images: vulnImage[k].Images, VulnDetail: ModelToVulnDetail(vulnMap[vulnImage[k].UniqueVuln])})
				count += len(vulnImage[k].Images)
			}
			uniqueVulns = make([]uint64, 0)
		}

		if count > MaxVulnImages {
			logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Int("severity", severity).Msg("ExportImageHtmlSrv.GetImageVulns partially completed")
			break
		}
	}

	logging.Get().Info().Int64("taskID", taskID).Int("severity", severity).Int64("startID", startID).Msg("ExportImageHtmlSrv.GetImageVulns finished")
	return res, nil
}

// 单个镜像风险报告
func (s *ExportImageHtmlSrv) GetImageRisk(ctx context.Context, taskID, imageID int64) (*ImageRiskOverView, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportImageHtmlSrv.GetImageRisk start")

	// 查漏洞和敏感文件，生成处置建议
	param := model.GetImageAssociateDataParam{
		ImageId:               imageID,
		VulnEnable:            true,
		SensitiveEnable:       true,
		ScanResultSearchParam: model.ScanResultSearchParam{OmitFields: model.GetVulnDefaultOmitFields()},
	}
	data, err := s.ImageSrv.GetImageCorrelateData(ctx, param)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportImageHtmlSrv GetImageRisk SearchScanImage")
		return nil, err
	}

	res := &ImageRiskOverView{
		ImageID:           data.ImageBaseResponse.ID,
		ImageName:         data.ImageBaseResponse.GetImageName(),
		VulnSeverityCount: StatisticsVulnSeverity(data.Vuln),
		FixSuggestion:     make([]string, 0),
	}
	res.FixSuggestion = append(res.FixSuggestion, data.GenVulnSuggest()...)
	res.FixSuggestion = append(res.FixSuggestion, data.GenSensitiveFileSuggest()...)

	_ = s.UpdateTask.IncrRedisFinished(ctx, model.ExportTensorTask{TaskType: model.ExportHtml, ID: taskID})
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportImageHtmlSrv.GetImageRisk finished")
	return res, nil
}

// 风险总览,获取这部分数据很耗时，需要提前做好
func (s *ExportImageHtmlSrv) createRiskOverView(ctx context.Context, task model.ExportTensorTask) error {
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv.createRiskOverView start")
	// 先查一下，是否存在
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, task.ID, model.ExportHtmlPrepareRiskOver)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		return nil
	}
	var startID int64
	res := &RiskOverView{}
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &model.Filter{Limit: 10, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: task.ID, StartID: startID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView.SearchExportTaskImage")
			return err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView finished")
			break
		}
		taskImageIds := make([]int64, 0)
		for i := range taskImages {
			taskImageIds = append(taskImageIds, taskImages[i].ImageID)
		}

		param := model.ImageListParam{ImageIds: taskImageIds}
		images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, param, nil)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Interface("param", param).Msg("ExportImageHtmlSrv createRiskOverView.ListImageWithScanInfo")
			return err
		}
		// 风险统计
		res.StatisticsImageAttr(images)
		startID = taskImages[len(taskImages)-1].ID
		logging.Get().Info().Int64("taskID", task.ID).Ints64("ImageIds", taskImageIds).Msg("ExportImageHtmlSrv createRiskOverView.ListImageWithScanInfo")
	}
	// 统计漏洞信息
	startID = 0
	for {
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		imageVulns, err := s.ExportTaskDal.SearchHtmlVulnImage(ctx, store.SearchHtmlVulnImageParam{
			TaskID:  task.ID,
			Fields:  []string{"id", "severity"},
			StartID: startID,
		}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView ListImageWithScanInfo")
			return err
		}
		for i := range imageVulns {
			res.StatisticsVulnSeverity(imageVulns[i])
		}
		if len(imageVulns) == 0 {
			break
		}
		startID = imageVulns[len(imageVulns)-1].ID

		logging.Get().Info().Int64("taskID", task.ID).Int64("startID", startID).Msg("ExportImageHtmlSrv createRiskOverView.SearchHtmlVulnImage")
	}
	res.Serializer()
	bys, err := json.Marshal(res)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv Marshal getRiskOverView")
		return err
	}

	if err := s.ExportTaskDal.CreateOrUpdateHtmlPrepare(ctx, &model.ExportHtmlPrepare{TaskID: task.ID, Data: string(bys), DataType: model.ExportHtmlPrepareRiskOver}); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createRiskOverView")
		return err
	}

	_ = s.UpdateTask.SetRedisAll(ctx, task, res.ImageCount)
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView finished")
	return nil
}

// 查询当前导出服务的状态
func (s *ExportImageHtmlSrv) getKoaStatus(ctx context.Context, taskID int64) (*KoaResponse, error) {

	url := fmt.Sprintf("%s/api/v1/middle/statusHtml?taskID=%d", s.KoaAddr, taskID)
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportImageHtmlSrv.getKoaStatus start")

	rsp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rsp.Body.Close()
	}()

	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code in updatenodes: %d", rsp.StatusCode)
	}
	response := &KoaResponse{}
	if err := json.NewDecoder(rsp.Body).Decode(response); err != nil {
		return nil, err
	}
	// filePath是一个路径，统一增加最后的斜杠
	if response.Data.FilePath != "" {
		if !strings.HasSuffix(response.Data.FilePath, "/") {
			response.Data.FilePath = response.Data.FilePath + "/"
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportImageHtmlSrv.getKoaStatus finished")
	return response, nil
}

// 新建导出任务
func (s *ExportImageHtmlSrv) createExportHtml(ctx context.Context, task model.ExportTensorTask) error {
	url := s.KoaAddr + "/api/v1/middle/startCreateHtml"

	type body struct {
		TaskID   int64  `json:"taskID"`
		FilePath string `json:"filePath"`
	}
	postData := body{
		TaskID:   task.ID,
		FilePath: s.genFilePath(ctx, task),
	}

	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).Msg("ExportImageHtmlSrv.createExportHtml start")

	data, err := json.Marshal(postData)
	if err != nil {
		return err
	}
	var rsp *http.Response
	retry := 0
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	// pod刚启动时exporter服务可能还没有启动起来，加一个重试机制
	for {
		rsp1, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			if retry >= 100 {
				return err
			}
			<-ticker.C
			retry++
		} else {
			rsp = rsp1
			break
		}
	}

	defer func() {
		_ = rsp.Body.Close()
	}()

	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code in updatenodes: %d", rsp.StatusCode)
	}

	response := KoaResponse{}

	if err := json.NewDecoder(rsp.Body).Decode(&response); err != nil {
		return err
	}
	if response.Code != consts.KoaCodeSuccess {
		return fmt.Errorf("export html task create failed:%s,taskID:%d", response.Msg, task.ID)
	}
	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).Msg("ExportImageHtmlSrv.createExportHtml finished")
	return nil
}

func (s *ExportImageHtmlSrv) genFilePath(ctx context.Context, task model.ExportTensorTask) string {
	return s.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}

// 查询出当前导出任务所有的漏洞信息，写入备用
func (s *ExportImageHtmlSrv) createVulnImage(ctx context.Context, taskID int64) error {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv prepareVuln start")
	// 如果Pod重启过，就不必从头开始
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, model.ExportHtmlPrepareVulnLastImage)
	if err != nil {
		return err
	}
	var startID int64
	if len(data) > 0 {
		if b, err := strconv.ParseInt(data[0].Data, 10, 64); err == nil {
			startID = b
		}
	}

	for {
		// 分批获取镜像
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		exportImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: startID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv prepareVuln SearchExportTaskImage")
			return err
		}
		if len(exportImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv createVulnImage finished")
			break
		}
		startID = exportImages[len(exportImages)-1].ID
		for i := range exportImages {
			// 获取该镜像的所有漏洞
			vulns, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{
				ClassType:      []string{report.ClassOSPkg, report.ClassConfig},
				OmitFields:     new(model.Vuln).DefaultOmitField(),
				NotReturnCount: true,
				ImageIds:       []int64{exportImages[i].ImageID}}, nil)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).
					Int64("imageID", exportImages[i].ImageID).Msg("ExportImageHtmlSrv prepareVuln SearchVuln")
				return err
			}

			uniques := make([]uint64, 0)
			for j := range vulns {
				uniques = append(uniques, vulns[j].UniqueVuln)
			}
			if len(uniques) == 0 {
				continue
			}

			//  正确的去重方式是向数据库写入，利用数据库的唯一索引，但是这种方式效率很低，在大数据导出时会超时
			//  所以采用查询的方式，这种方式在当前的情况下，暂时不会出错：1，任务没有并发，2，mysql没有主从延迟
			duplicates, err := s.ExportTaskDal.SearchHtmlVulnImage(ctx, store.SearchHtmlVulnImageParam{
				TaskID:      taskID,
				Fields:      []string{"id", "task_id", "unique_vuln"},
				UniqueVulns: uniques,
			}, nil)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).Msg("ExportImageHtmlSrv prepareVuln SearchHtmlVulnImage")
				return err
			}
			// 整理漏洞
			duplicatedVuln := InANotInB(vulns, duplicates)
			if len(duplicatedVuln) == 0 {
				continue
			}
			vulnImages := make([]*model.ExportVulnImage, 0)
			for j := range duplicatedVuln {
				vuln := duplicatedVuln[j]
				// 获取这个漏洞所关联的镜像
				taskImages, err := s.ExportTaskDal.GetExportImageRelatedVuln(ctx, vuln.UniqueVuln, taskID)
				if err != nil {
					logging.Get().Err(err).Int64("taskID", taskID).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("ExportImageHtmlSrv prepareVuln GetExportImageRelatedVuln")
					return err
				}

				taskImageNames := make([]string, 0)
				for k := range taskImages {
					taskImageNames = append(taskImageNames, taskImages[k].ImageName)
				}
				vulnImage := &model.ExportVulnImage{
					TaskID:     taskID,
					UniqueVuln: vuln.UniqueVuln,
					Images:     taskImageNames,
					CanFixed:   vuln.FixedBy != "",
					Severity:   vuln.SeverityInt,
				}
				vulnImages = append(vulnImages, vulnImage)
			}

			if err := s.ExportTaskDal.CreateHtmlVulnImage(ctx, vulnImages); err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int("vulnImage", len(vulnImages)).Msg("ExportImageHtmlSrv prepareVuln CreateHtmlVulnImage")
				continue
			}
			logging.Get().Info().Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).Int("vulnImage", len(vulnImages)).Msg("ExportImageHtmlSrv prepareVuln CreateHtmlVulnImage")
		}
		// pod重启后不用再重新计算。
		if err := s.ExportTaskDal.CreateOrUpdateHtmlPrepare(ctx, &model.ExportHtmlPrepare{
			TaskID:   taskID,
			DataType: model.ExportHtmlPrepareVulnLastImage,
			Data:     fmt.Sprintf("%d", startID),
		}); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("lastImageID", startID).Msg("ExportImageHtmlSrv prepareVuln CreateOrUpdateHtmlPrepare")
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.prepareVuln finished")
	return nil
}

func (s *ExportImageHtmlSrv) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		TaskType:        model.ExportHtml,
		ExecuteType:     []string{consts.ExportScanResult, consts.ExportImageSearch, consts.ExportSingleImage},
		Finished:        consts.FalseString,
		Failure:         consts.FalseString,
		ExportHtmlReady: consts.TrueString,
	}, &model.Filter{Limit: 1})
	if err != nil {
		logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv SearchExportTensorTask")
		return
	}
	if len(tasks) == 0 {
		return
	}
	task := tasks[0]
	// 支持横向扩展
	created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, task.ID)
	if err != nil {
		logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv CreateExportIdempotent")
		return
	}
	if !created {
		logging.Get().Info().Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv task running other pod ")
		return
	}

	// 把漏洞统计好,pod可能会重启
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv start createVulnImage")
	if err := s.createVulnImage(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createVulnImage")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv finish createVulnImage")

	// 把风险概览信息准备好,pod重启后可能会重复写入
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv start createRiskOverView")
	if err := s.createRiskOverView(ctx, task); err != nil && !strings.Contains(err.Error(), consts.DuplicateKey) {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createRiskOverView")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}

	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv finish createRiskOverView")

	if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportImageHtmlSrv export html Start")
		return
	}

	// 新建目录
	filePath := s.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Err(err).Str("filePath", filePath).Msg("ExportImageHtmlSrv export html MkdirIfNotExist")
		return
	}
	// 导出完成时删除目录
	defer func(filePath string) {
		if err := os.RemoveAll(filePath); err != nil {
			logging.Get().Err(err).Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv defer remove path ")
			return
		}
		logging.Get().Info().Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv defer remove path ")
	}(filePath)

	if err = s.createExportHtml(ctx, task); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportImageHtmlSrv export html task create failure")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv.createExportHtml success")

	// 如果创建成功，就一直轮询状态
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	// 服务可能会出错，所以这里提供一个重试机制
	statusRetry := 1
	for {
		<-ticker.C
		status, err := s.getKoaStatus(ctx, task.ID)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv export html getKoaStatus failure")
			statusRetry++
			if statusRetry < 100 {
				continue
			}
			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask Failure")
			}
			break
		}
		logging.Get().Info().Int64("taskID", task.ID).Str("filePath", task.FilePath).Interface("status", status).Msg("ExportImageHtmlSrv.getKoaStatus success")

		if status.Data.Status == consts.KoaStatusSuccess {
			// 调用用命令进行压缩
			zipFilename := s.FileDir + "/" + task.FilePath
			logging.Get().Info().Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ExportImageHtmlSrv ZipAndSave use zip start zip")
			command := fmt.Sprintf("cd %s;zip -r %s %s", s.FileDir, task.FilePath, strings.ReplaceAll(task.FilePath, ".zip", ""))

			logging.Get().Info().Str("command", command).Msg("ExportImageHtmlSrv command")
			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", task.FilePath).Msg("ExportImageHtmlSrv ZipAndSave use zip")
				if err := s.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
					logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
				}
			}
			logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", status.Data.FilePath).Msg("ExportImageHtmlSrv ZipAndSave use zip success")

			// 成功之后更新任务
			if err := s.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv Success export html task success update task")
			}
			break
		} else if status.Data.Status == consts.KoaStatusFailed || status.Data.Status == "" {
			// 保存状态
			logging.Get().Info().Int64("taskID", task.ID).Msg("export html execute failure")
			if len(status.Data.FailedMsg) == 0 {
				if status.Msg != "" {
					status.Data.FailedMsg = []FailedMsg{{Message: status.Msg}}
				}
				status.Data.FailedMsg = []FailedMsg{{Message: "未知错误"}}
			}
			errMsg := status.Data.FailedMsg[len(status.Data.FailedMsg)-1].Message

			if err := s.UpdateTask.Failure(ctx, task.ID, errMsg); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
			}
			break
		} else {
			logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv export html executing ")
		}
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv export html execute complete")
	_ = s.UpdateTask.DeleteRedisData(ctx, task)

	return
}

func InANotInB(a []*model.Vuln, b []model.ExportVulnImage) []*model.Vuln {
	if len(a) == 0 || len(b) == 0 {
		return a
	}
	mapB := make(map[uint64]struct{})
	for i := range b {
		mapB[b[i].UniqueVuln] = struct{}{}
	}
	ans := make([]*model.Vuln, 0)
	for k := range a {
		if _, ok := mapB[a[k].UniqueVuln]; !ok {
			ans = append(ans, a[k])
		}
	}
	return ans
}
