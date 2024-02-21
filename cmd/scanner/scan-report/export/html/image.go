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

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	types2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像列表搜索的安全报告
type ExportImageHtmlSrv struct {
	ImageSrv       types2.ImageSrvInterface
	ExportTaskDal  imagesecStore.ExportTaskDal
	UpdateTask     types2.UpdateExportTask
	VulnSrv        types2.VulnService
	KoaAddr        string // 生成html的内部服务接口
	FileDir        string // 文件存放的绝对路径
	VulnClassType  []string
	NeedKernelVuln string
	Log            *scannerUtils.LogEvent
}

func NewExportImageHtmlSrv(
	imageSrv types2.ImageSrvInterface,
	exportTaskDal imagesecStore.ExportTaskDal,
	updateTask types2.UpdateExportTask,
	vulnSrv types2.VulnService,
	fileDir string,
	vulnClassType []string,
) *ExportImageHtmlSrv {
	return &ExportImageHtmlSrv{
		ImageSrv:       imageSrv,
		ExportTaskDal:  exportTaskDal,
		UpdateTask:     updateTask,
		FileDir:        fileDir,
		KoaAddr:        consts.KoaAddr,
		VulnClassType:  vulnClassType,
		NeedKernelVuln: os.Getenv("IDENTITY_KERNEL_VULN"),
		VulnSrv:        vulnSrv,
		Log:            scannerUtils.NewLogEvent(scannerUtils.WithModule("HtmlExportImage")),
	}
}

// 获取镜像ID和Name用于生成目录
func (s *ExportImageHtmlSrv) GetImageIdNames(ctx context.Context, taskID int64) (*types2.ImageIDNameWithTask, error) {
	s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetImageIdNames start")
	images := make([]types2.ImageIDName, 0)
	var lastImageID int64

	// 分批获取镜像
	for {
		filter := &imagesecModel.Filter{Limit: consts.DefaultExportBathSize, SortFiled: "image_id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, imagesecModel.SearchExportTaskImageParam{TaskID: taskID, StartID: lastImageID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetImageIdNames.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			s.Log.Info().Int64("taskID", taskID).Int("image-id-length", len(images)).
				Msg("ExportImageHtmlSrv GetImageIdNames finished")
			break
		}
		lastImageID = taskImages[len(taskImages)-1].ImageID

		for i := range taskImages {
			images = append(images, types2.ImageIDName{
				ImageID:   taskImages[i].ImageID,
				ImageName: taskImages[i].ImageName,
			})
		}
	}

	s.Log.Info().Int64("taskID", taskID).Int("image-length", len(images)).
		Msg("ExportImageHtmlSrv.GetImageIdNames finished")
	return &types2.ImageIDNameWithTask{TaskId: taskID, Images: images}, nil
}

// 镜像信息列表
func (s *ExportImageHtmlSrv) GetImages(ctx context.Context, taskID int64, starID int64) (*types2.ImageResponse, error) {
	s.Log.Info().Int64("taskID", taskID).Int64("startId", starID).Msg("ExportImageHtmlSrv.GetImages")

	res := &types2.ImageResponse{
		Images: make([]types2.Image, 0),
	}
	// 分批获取镜像
	for {
		filter := &imagesecModel.Filter{Limit: consts.DefaultMaxLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, imagesecModel.SearchExportTaskImageParam{TaskID: taskID, StartID: starID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Int64("startID", starID).Msg("GetImages.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetImages finished")
			res.End = true
			break
		}
		starID = taskImages[len(taskImages)-1].ID
		res.StartID = starID
		imageIds := make([]int64, 0)

		param := imagesecModel.ImageAssociateParam{
			VulnEnable:      true,
			MalwareEnable:   true,
			SensitiveEnable: true,
			WebshellEnable:  true,
			SearchVulnParam: imagesecModel.ApiSearchVulnParam{
				OmitFields: imagesecModel.GetVulnDefaultOmitFields(),
				ClassType:  s.VulnClassType,
				NeedKernel: []string{s.NeedKernelVuln},
			},
		}

		for i := range taskImages {
			param.ImageId = taskImages[i].ImageID

			imageData, err := s.ImageSrv.GetImageCorrelateData(ctx, param)
			if err != nil {
				s.Log.Err(err).Int64("taskID", taskID).Int64("startID", starID).
					Msg("ExportImageHtmlSrv GetImages.ListImageWithScanInfo")
				return nil, err
			}

			baseImage := imageData.ToImageBaseResponse()

			im := types2.Image{
				ImageID:       baseImage.ID,
				ImageName:     baseImage.GetImageName(),
				FixedVuln:     types2.VulnSeverityCount{},
				UnFixedVuln:   types2.VulnSeverityCount{},
				Malicious:     imageData.MalwareCnt,
				RiskScore:     baseImage.RiskScore,
				NotMaintained: util.ExistBit1(baseImage.Flag, imagesecModel.FlagImageNotMaintained),
				Flag:          baseImage.Flag,
			}

			im.AddVulnSeverityCount(imageData.Vuln)
			res.Images = append(res.Images, im)

			imageIds = append(imageIds, taskImages[i].ImageID)
		}

		if len(res.Images) > MaxImages {
			s.Log.Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).
				Msg("ExportImageHtmlSrv.GetImages partially completed")
			break
		}
	}
	s.Log.Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).
		Msg("ExportImageHtmlSrv.GetImages")
	return res, nil
}

// 风险总览
func (s *ExportImageHtmlSrv) GetRiskOverView(ctx context.Context, taskID int64) (*types2.RiskOverView, error) {
	overView, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesecModel.ExportHtmlPrepareRiskOver)
	if err != nil {
		s.Log.Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetRiskOverView")
		return nil, fmt.Errorf("GetRiskOverView %d error :%s", taskID, err.Error())
	}
	if len(overView) == 0 {
		return nil, fmt.Errorf("not GetRiskOverView taskID: %d", taskID)
	}
	risk := &types2.RiskOverView{}

	if err := json.Unmarshal([]byte(overView[0].Data), risk); err != nil {
		return nil, fmt.Errorf("GetRiskOverView:%d error: %s", taskID, err.Error())
	}

	return risk, nil
}

// 病毒列表
func (s *ExportImageHtmlSrv) GetVirus(ctx context.Context, taskID int64) ([]types2.VirusInfo, error) {
	s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.GetVirus start")
	var startID int64
	res := make([]types2.VirusInfo, 0)

	virusMap := make(map[int64]*imagesecModel.Malware)
	virusToImage := make(map[int64][]string)
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &imagesecModel.Filter{Limit: consts.DefaultMaxLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, imagesecModel.SearchExportTaskImageParam{TaskID: taskID, StartID: startID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetVirus.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv GetVirus finished")
			break
		}
		startID = taskImages[len(taskImages)-1].ID

		for i := range taskImages {
			image, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{ImageId: taskImages[i].ImageID, MalwareEnable: true})
			if err != nil {
				s.Log.Err(err).Int64("taskID", taskID).Int64("imageID", taskImages[i].ImageID).Msg("ExportImageHtmlSrv GetVirus")
				return nil, err
			}
			for k := range image.Malware {

				vir := image.Malware[k]
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
		vi := types2.VirusInfo{
			FilePath:  ima.Filepath,
			VirusName: ima.Name,
			Images:    virusToImage[v],
		}
		if vi.Images == nil {
			vi.Images = make([]string, 0)
		}
		res = append(res, vi)
	}

	s.Log.Info().Int64("taskID", taskID).Int("virus-length", len(res)).Msg("ExportImageHtmlSrv.GetVirus finished")

	return res, nil
}

// 按层取漏洞信息 canFixed:"true"，取可修复的，"false"取不可修复的，""表示取全部
// 首页信息，所有漏洞
func (s *ExportImageHtmlSrv) GetExportVuln(ctx context.Context, param types2.GetExportVulnParam) (*types2.VulnWithImageResponse, error) {
	if param.Limit <= 0 {
		param.Limit = DefaultLimit
	}
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}
	s.Log.Info().Int64("taskID", param.TaskID).Str("severity", param.Severity).
		Str("canFixed", param.CanFixed).Int64("startID", param.StartID).Msg("ExportImageHtmlSrv.GetExportVuln start")

	res := &types2.VulnWithImageResponse{
		Vulns: make([]types2.VulnWithImage, 0),
	}
	uniqueVulns := make([]uint64, 0)
	// 分批获取漏洞
	filter := &imagesecModel.Filter{Limit: param.Limit, SortFiled: "id", SortBy: consts.SortByAsc}
	vulnParam := imagesecModel.SearchHtmlVulnImageParam{
		TaskID:   param.TaskID,
		StartID:  param.StartID,
		Severity: param.Severity,
		CanFixed: param.CanFixed,
		Filter:   filter,
	}

	vulnImages, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, vulnParam)
	if err != nil {
		s.Log.Err(err).Int64("taskID", param.TaskID).Msg("ExportImageHtmlSrv GetExportVuln SearchExportTaskImage")
		return nil, err
	}
	if len(vulnImages) < int(param.Limit) {
		res.End = true
	}
	for i := range vulnImages {
		res.StartID = vulnImages[i].ID
		uniqueVulns = append(uniqueVulns, vulnImages[i].UniqueVuln)
		res.Vulns = append(res.Vulns, types2.VulnWithImage{
			Images:     vulnImages[i].Images,
			UniqueVuln: vulnImages[i].UniqueVuln,
		})
	}

	// 查漏洞详情
	if len(uniqueVulns) > 0 {
		vulnsView, _, err := s.VulnSrv.SearchVuln(ctx, imagesecModel.ApiSearchVulnParam{
			VulnUniqueIds:  uniqueVulns,
			NotReturnCount: true,
		})
		if err != nil {
			s.Log.Err(err).Int64("taskID", param.TaskID).Msg("ExportImageHtmlSrv GetExportVuln SearchExportTaskImage")
			return nil, err
		}

		vulnMap := make(map[uint64]*imagesecModel.VulnView)
		for i := range vulnsView {
			vulnMap[vulnsView[i].UniqueID] = vulnsView[i]
		}
		for i := range res.Vulns {
			res.Vulns[i].VulnDetail = types2.ModelToVulnDetail(vulnMap[res.Vulns[i].UniqueVuln])
		}
	}

	s.Log.Info().Int64("taskID", param.TaskID).Str("severity", param.Severity).
		Str("canFixed", param.CanFixed).Int("vulns", len(res.Vulns)).
		Int64("startID", param.StartID).Bool("isEnd", res.End).Msg("ExportImageHtmlSrv.GetExportVuln finished")
	return res, nil
}

// 按层级获取镜像的漏洞信息
// 单个镜像
func (s *ExportImageHtmlSrv) GetImageVuln(ctx context.Context, param types2.GetExportVulnParam) (*types2.VulnWithImageResponse, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}
	if param.ImageID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get imageID:%d", param.ImageID)
	}
	s.Log.Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Str("severity", param.Severity).
		Msg("ExportImageHtmlSrv.GetImageVuln start")
	res := &types2.VulnWithImageResponse{
		ImageID: param.ImageID,
		Vulns:   make([]types2.VulnWithImage, 0),
	}
	count := 0

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageId:    param.ImageID,
		VulnEnable: true,
		SearchVulnParam: imagesecModel.ApiSearchVulnParam{
			SeverityStr: []string{param.Severity},
			NeedKernel:  []string{s.NeedKernelVuln},
			ClassType:   s.VulnClassType,
			StartID:     param.StartID,
			Filter:      imagesecModel.EmptyFilter().SetSortFiledByID().SetSortAsc(),
		},
	})
	if err != nil {
		s.Log.Err(err).Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).
			Msg("GetImageVuln GetImageCorrelateData")
		return nil, err
	}
	if len(data.Vuln) == 0 {
		res.End = true
	}

	// 整理漏洞
	uniqueVulns := make([]uint64, 0)
	vulnMap := make(map[uint64]*imagesecModel.VulnView) // 单个镜像的漏洞，不致于OOM
	vulns := data.Vuln

	for j := range vulns {
		vuln := vulns[j]
		res.StartID = vuln.ID
		vulnMap[vuln.UniqueID] = vuln
		uniqueVulns = append(uniqueVulns, vuln.UniqueID)
		if (j >= len(vulns)-1 && len(uniqueVulns) > 0) || len(uniqueVulns) >= consts.DefaultMaxLimit {
			vulnParam := imagesecModel.SearchHtmlVulnImageParam{TaskID: param.TaskID, UniqueVulns: uniqueVulns}
			vulnImage, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, vulnParam)
			if err != nil {
				s.Log.Err(err).Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Uint64("UniqueID", vuln.UniqueID).
					Msg("ExportImageHtmlSrv GetImageVuln SearchHtmlVulnImage")
				return nil, err
			}
			for k := range vulnImage {
				res.Vulns = append(res.Vulns, types2.VulnWithImage{Images: vulnImage[k].Images, VulnDetail: types2.ModelToVulnDetail(vulnMap[vulnImage[k].UniqueVuln])})
				count += len(vulnImage[k].Images)
			}
			uniqueVulns = make([]uint64, 0)
		}

		if count > MaxVulnImages {
			s.Log.Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Str("severity", param.Severity).
				Msg("ExportImageHtmlSrv.GetImageVuln partially completed")
			break
		}
	}

	s.Log.Info().Int64("taskID", param.TaskID).Str("severity", param.Severity).Int64("startID", param.StartID).
		Msg("ExportImageHtmlSrv.GetImageVuln finished")
	return res, nil
}

// 单个镜像风险报告
func (s *ExportImageHtmlSrv) GetImageRisk(ctx context.Context, taskID, imageID int64) (*types2.ImageRiskOverView, error) {
	s.Log.Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportImageHtmlSrv.GetImageRisk start")

	task, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesecModel.SearchExportTaskParam{ID: taskID})
	if err != nil {
		s.Log.Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTask")
		return nil, err
	}
	if len(task) == 0 {
		s.Log.Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTask not get task")
		return nil, err
	}

	// 查漏洞和敏感文件，生成处置建议
	param := imagesecModel.ImageAssociateParam{
		ImageId:               imageID,
		VulnEnable:            true, // 漏洞单独查询
		MalwareEnable:         true,
		SensitiveEnable:       true,
		WebshellEnable:        true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{},
		SearchVulnParam: imagesecModel.ApiSearchVulnParam{
			OmitFields: imagesecModel.GetVulnDefaultOmitFields(),
			NeedKernel: []string{s.NeedKernelVuln},
			ClassType:  s.VulnClassType,
			Filter:     imagesecModel.EmptyFilterForTotalQuery(),
		},
	}

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, param)
	if err != nil {
		s.Log.Err(err).Int64("taskID", taskID).Int64("imageID", imageID).
			Msg("ExportImageHtmlSrv GetImageRisk SearchScanImage")
		return nil, err
	}
	res := &types2.ImageRiskOverView{
		ImageID:           data.ImageBaseResponse.ID,
		ImageName:         data.ImageBaseResponse.GetImageName(),
		VulnSeverityCount: types2.StatisticsVulnSeverity(data.Vuln),
	}

	ctx = context.WithValue(ctx, imagesecModel.AcceptLanguage, task[0].Lang)
	im := data.ToImageBaseResponse()
	im.AdaptI18(ctx)
	res.Suggests = im.Suggests

	_ = s.UpdateTask.IncrRedisFinished(ctx, taskID)
	s.Log.Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportImageHtmlSrv.GetImageRisk finished")
	return res, nil
}

// 风险总览,获取这部分数据很耗时，需要提前做好
func (s *ExportImageHtmlSrv) createRiskOverView(ctx context.Context, task imagesecModel.ExportTensorTask) error {
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv.createRiskOverView start")
	// 先查一下，是否存在
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, task.ID, imagesecModel.ExportHtmlPrepareRiskOver)
	if err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView.SearchHtmlPrepare")
		return err
	}
	if len(data) > 0 {
		s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView.SearchHtmlPrepare find data")
		return nil
	}
	var startID int64
	res := &types2.RiskOverView{}
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &imagesecModel.Filter{Limit: 10, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, imagesecModel.SearchExportTaskImageParam{TaskID: task.ID, StartID: startID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView.SearchExportTaskImage")
			return err
		}
		if len(taskImages) == 0 {
			s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView finished")
			break
		}
		for i := range taskImages {
			param := imagesecModel.ImageAssociateParam{
				ImageId: taskImages[i].ImageID,
				// VulnEnable: true,
				// SearchVulnParam: imagesecModel.ApiSearchVulnParam{
				// 	Fields:     []string{"id", "unique_id"},
				// 	NeedKernel: []string{s.NeedKernelVuln},
				// 	ClassType:  s.VulnClassType,
				// 	Filter:     imagesecModel.EmptyFilterForTotalQuery(),
				// },
			}

			imageData, err := s.ImageSrv.GetImageCorrelateData(ctx, param)
			if err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).
					Int64("imageID", taskImages[i].ImageID).Msg("ExportImageHtmlSrv createRiskOverView.ListImageWithScanInfo")
				return err
			}
			// n 风险统计
			baseImageData := imageData.ToImageBaseResponse()
			res.StatisticsImageAttr([]*imagesecModel.ImageBaseResponse{&baseImageData})
		}
		startID = taskImages[len(taskImages)-1].ID
	}
	// 统计漏洞信息
	startID = 0
	for {
		filter := &imagesecModel.Filter{Limit: consts.DefaultMaxLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		imageVulns, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, imagesecModel.SearchHtmlVulnImageParam{
			TaskID:  task.ID,
			Fields:  []string{"id", "severity"},
			StartID: startID,
			Filter:  filter,
		})
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView ListImageWithScanInfo")
			return err
		}
		for i := range imageVulns {
			res.StatisticsVulnSeverity(imageVulns[i])
		}
		if len(imageVulns) == 0 {
			break
		}
		startID = imageVulns[len(imageVulns)-1].ID

		s.Log.Info().Int64("taskID", task.ID).Int64("startID", startID).
			Msg("ExportImageHtmlSrv createRiskOverView.SearchHtmlVulnImage")
	}
	res.Serializer()

	bys, err := json.Marshal(res)
	if err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv Marshal getRiskOverView")
		return err
	}

	if err := s.ExportTaskDal.CreateOrUpdateHTMLPrepare(ctx, &imagesecModel.ExportHtmlPrepare{TaskID: task.ID, Data: string(bys),
		DataType: imagesecModel.ExportHtmlPrepareRiskOver}); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createRiskOverView")
		return err
	}

	_ = s.UpdateTask.SetRedisAll(ctx, task.ID, res.ImageCount)
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv createRiskOverView finished")
	return nil
}

// 查询当前导出服务的状态
func (s *ExportImageHtmlSrv) getKoaStatus(ctx context.Context, taskID int64) (*types2.KoaResponse, error) {

	url := fmt.Sprintf("%s/api/v1/middle/statusHtml?taskID=%d", s.KoaAddr, taskID)
	s.Log.Info().Int64("taskID", taskID).Str("url", url).Msg("ExportImageHtmlSrv.getKoaStatus start")

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
	response := &types2.KoaResponse{}
	if err := json.NewDecoder(rsp.Body).Decode(response); err != nil {
		return nil, err
	}
	// filePath是一个路径，统一增加最后的斜杠
	if response.Data.FilePath != "" {
		if !strings.HasSuffix(response.Data.FilePath, "/") {
			response.Data.FilePath = response.Data.FilePath + "/"
		}
	}
	s.Log.Info().Int64("taskID", taskID).Str("url", url).Msg("ExportImageHtmlSrv.getKoaStatus finished")
	return response, nil
}

// 新建导出任务
func (s *ExportImageHtmlSrv) createExportHtml(ctx context.Context, task imagesecModel.ExportTensorTask) error {
	url := s.KoaAddr + "/api/v1/middle/startCreateHtml"

	type body struct {
		TaskID   int64  `json:"taskID"`
		FilePath string `json:"filePath"`
		Lang     string `json:"lang"`
	}
	postData := body{
		TaskID:   task.ID,
		Lang:     task.Lang,
		FilePath: s.genFilePath(ctx, task),
	}

	s.Log.Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).
		Msg("ExportImageHtmlSrv.createExportHtml start")

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

	response := types2.KoaResponse{}

	if err := json.NewDecoder(rsp.Body).Decode(&response); err != nil {
		return err
	}
	if response.Code != consts.KoaCodeSuccess {
		return fmt.Errorf("export html task create failed:%s,taskID:%d", response.Msg, task.ID)
	}
	s.Log.Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).
		Msg("ExportImageHtmlSrv.createExportHtml finished")
	return nil
}

func (s *ExportImageHtmlSrv) genFilePath(ctx context.Context, task imagesecModel.ExportTensorTask) string {
	return s.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}

// 查询出当前导出任务所有的漏洞信息，写入备用
func (s *ExportImageHtmlSrv) createVulnImage(ctx context.Context, taskID int64) error {
	s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv prepareVuln start")
	// 如果Pod重启过，就不必从头开始
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesecModel.ExportHtmlPrepareVulnLastImage)
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
		filter := &imagesecModel.Filter{Limit: consts.DefaultMaxLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		exportImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, imagesecModel.SearchExportTaskImageParam{TaskID: taskID, StartID: startID, Filter: filter})
		if err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Msg("ExportImageHtmlSrv prepareVuln SearchExportTaskImage")
			return err
		}
		if len(exportImages) == 0 {
			s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv createVulnImage finished")
			break
		}
		startID = exportImages[len(exportImages)-1].ID
		for i := range exportImages {
			// 获取该镜像的所有漏洞
			param := imagesecModel.ImageAssociateParam{
				ImageId:    exportImages[i].ImageID,
				VulnEnable: true,
				SearchVulnParam: imagesecModel.ApiSearchVulnParam{
					Fields:     []string{"id", "unique_id", "severity", "fixed_version"},
					ClassType:  s.VulnClassType,
					NeedKernel: []string{s.NeedKernelVuln},
				},
			}
			imageData, err := s.ImageSrv.GetImageCorrelateData(ctx, param)

			if err != nil {
				s.Log.Err(err).Int64("taskID", taskID).
					Int64("ImageID", exportImages[i].ImageID).Msg("ExportImageHtmlSrv prepareVuln SearchVuln")
				return err
			}

			uniques := make([]uint64, 0)
			vulns := imageData.Vuln
			for j := range vulns {
				vu := vulns[j]
				uniques = append(uniques, vu.UniqueID)
			}
			if len(uniques) == 0 {
				continue
			}

			//  正确的去重方式是向数据库写入，利用数据库的唯一索引，但是这种方式效率很低，在大数据导出时会超时
			//  所以采用查询的方式，这种方式在当前的情况下，暂时不会出错：1，任务没有并发，2，mysql没有主从延迟
			duplicates, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, imagesecModel.SearchHtmlVulnImageParam{
				TaskID:      taskID,
				Fields:      []string{"id", "task_id", "unique_vuln"},
				UniqueVulns: uniques,
			})
			if err != nil {
				s.Log.Err(err).Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).
					Msg("ExportImageHtmlSrv prepareVuln SearchHtmlVulnImage")
				return err
			}
			// 整理漏洞
			duplicatedVuln := InANotInB2(vulns, duplicates)
			if len(duplicatedVuln) == 0 {
				continue
			}
			vulnImages := make([]*imagesecModel.ExportVulnImage, 0)
			for j := range duplicatedVuln {
				vuln := duplicatedVuln[j]
				// 获取这个漏洞所关联的镜像
				taskImages, err := s.ExportTaskDal.SearchImageRelatedVuln(ctx, vuln.UniqueID, taskID)
				if err != nil {
					s.Log.Err(err).Int64("taskID", taskID).Uint64("UniqueID", vuln.UniqueID).
						Msg("ExportImageHtmlSrv prepareVuln SearchImageRelatedVuln")
					return err
				}

				taskImageNames := make([]string, 0)
				for k := range taskImages {
					taskImageNames = append(taskImageNames, taskImages[k].ImageName)
				}
				vulnImage := &imagesecModel.ExportVulnImage{
					TaskID:     taskID,
					UniqueVuln: vuln.UniqueID,
					Images:     taskImageNames,
					CanFixed:   vuln.FixedVersion != "",
					Severity:   vuln.SeverityInt,
				}
				vulnImages = append(vulnImages, vulnImage)
			}

			if err := s.ExportTaskDal.CreateHTMLVulnImage(ctx, vulnImages); err != nil {
				s.Log.Err(err).Int64("taskID", taskID).Int("vulnImage", len(vulnImages)).
					Msg("ExportImageHtmlSrv prepareVuln CreateHtmlVulnImage")
				continue
			}
			s.Log.Info().Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).
				Int("vulnImage", len(vulnImages)).Msg("ExportImageHtmlSrv prepareVuln CreateHtmlVulnImage")
		}
		// pod重启后不用再重新计算。
		if err := s.ExportTaskDal.CreateOrUpdateHTMLPrepare(ctx, &imagesecModel.ExportHtmlPrepare{
			TaskID:   taskID,
			DataType: imagesecModel.ExportHtmlPrepareVulnLastImage,
			Data:     fmt.Sprintf("%d", startID),
		}); err != nil {
			s.Log.Err(err).Int64("taskID", taskID).Int64("lastImageID", startID).
				Msg("ExportImageHtmlSrv prepareVuln CreateOrUpdateHtmlPrepare")
		}
	}
	s.Log.Info().Int64("taskID", taskID).Msg("ExportImageHtmlSrv.prepareVuln finished")
	return nil
}

func InANotInB2(a []*imagesecModel.VulnView, b []imagesecModel.ExportVulnImage) []*imagesecModel.VulnView {
	if len(a) == 0 || len(b) == 0 {
		return a
	}
	mapB := make(map[uint64]struct{})
	for i := range b {
		mapB[b[i].UniqueVuln] = struct{}{}
	}
	ans := make([]*imagesecModel.VulnView, 0)
	for k := range a {
		if _, ok := mapB[a[k].UniqueID]; !ok {
			ans = append(ans, a[k])
		}
	}
	return ans
}

func (s *ExportImageHtmlSrv) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesecModel.SearchExportTaskParam{
		TaskType:        imagesecModel.ExportHtml,
		ExecuteType:     []string{consts.ExportImageSearch, consts.ExportScanTask},
		Finished:        consts.FalseString,
		ExportHtmlReady: consts.TrueString,
		Filter: &imagesecModel.Filter{
			SortBy:    consts.SortByDesc,
			SortFiled: "id",
			Limit:     1,
		},
	})
	if err != nil {
		s.Log.Err(err).Str("TaskType", imagesecModel.ExportHtml).Msg("ExportImageHtmlSrv SearchExportTask")
		return
	}
	if len(tasks) == 0 {
		time.Sleep(time.Second * 30)
		return
	}
	task := tasks[0]
	// 支持横向扩展
	// created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, task.ID)
	// if err != nil {
	// 	s.Log.Err(err).Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv CreateExportIdempotent")
	// 	return
	// }
	// if !created {
	// 	s.Log.Info().Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv task running other pod ")
	// 	return
	// }

	// 把漏洞统计好,pod可能会重启
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv start createVulnImage")
	if err := s.createVulnImage(ctx, task.ID); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createVulnImage")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv finish createVulnImage")

	// 把风险概览信息准备好,pod重启后可能会重复写入
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv start createRiskOverView")
	if err := s.createRiskOverView(ctx, task); err != nil && !strings.Contains(err.Error(), consts.DuplicateKey) {
		s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv pre createRiskOverView")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}

	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv finish createRiskOverView")

	if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportImageHtmlSrv export html Start")
		return
	}

	// 新建目录
	filePath := s.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		s.Log.Err(err).Str("filePath", filePath).Msg("ExportImageHtmlSrv export html MkdirIfNotExist")
		return
	}
	// 导出完成时删除目录
	defer func(filePath string) {
		if err := os.RemoveAll(filePath); err != nil {
			s.Log.Err(err).Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv defer remove path ")
			return
		}
		s.Log.Info().Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv defer remove path ")
	}(filePath)

	if err = s.createExportHtml(ctx, task); err != nil {
		s.Log.Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportImageHtmlSrv export html task create failure")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv.createExportHtml success")

	// 如果创建成功，就一直轮询状态
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	// 服务可能会出错，所以这里提供一个重试机制
	statusRetry := 1
	for {
		<-ticker.C
		status, err := s.getKoaStatus(ctx, task.ID)
		if err != nil {
			s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv export html getKoaStatus failure")
			statusRetry++
			if statusRetry < 30 {
				continue
			}
			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask Failure")
			}
			break
		}
		s.Log.Info().Int64("taskID", task.ID).Str("filePath", task.FilePath).Interface("status", status).
			Msg("ExportImageHtmlSrv.getKoaStatus success")

		statusM := status.Data.Status
		switch statusM {

		case consts.KoaStatusSuccess:
			// 调用用命令进行压缩
			zipFilename := s.FileDir + "/" + task.FilePath
			s.Log.Info().Str("zipFilename", zipFilename).Str("filePath", filePath).
				Msg("ExportImageHtmlSrv ZipAndSave use zip start zip")
			command := fmt.Sprintf("cd %s;zip -r %s %s", s.FileDir, task.FilePath, strings.ReplaceAll(task.FilePath, ".zip", ""))

			s.Log.Info().Str("command", command).Msg("ExportImageHtmlSrv command")
			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				s.Log.Err(err).Str("zipFilename", zipFilename).Str("filePath", task.FilePath).
					Msg("ExportImageHtmlSrv ZipAndSave use zip")
				if err := s.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
					s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
				}
			}
			s.Log.Err(err).Str("zipFilename", zipFilename).Str("filePath", status.Data.FilePath).
				Msg("ExportImageHtmlSrv ZipAndSave use zip success")

			// 成功之后更新任务
			if err := s.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv Success export html task success update task")
			}

		case consts.KoaStatusInprogress:
			s.Log.Info().Int64("taskID", task.ID).Str("filePath", task.FilePath).Interface("status", status).
				Msg("ExportImageHtmlSrv.getKoaStatus")

		default:
			if status.Data.FailedMsg.Message == "" {
				status.Data.FailedMsg.Message = "unknown error"
			}
			// 保存状态
			s.Log.Info().Int64("taskID", task.ID).Interface("status", status).Msg("export html execute failure")

			if err := s.UpdateTask.Failure(ctx, task.ID, status.Data.FailedMsg.Message); err != nil {
				s.Log.Err(err).Int64("taskID", task.ID).Msg("ExportImageHtmlSrv UpdateExportTask Failure")
			}
		}

		if statusM != consts.KoaStatusInprogress {
			break
		}
	}
	s.Log.Info().Int64("taskID", task.ID).Msg("ExportImageHtmlSrv export html execute complete")
	_ = s.UpdateTask.DeleteRedisData(ctx, task.ID)

	return
}

const (
	MaxVulnImages = 5000
	DefaultLimit  = 1000
	MaxImages     = 500
)
