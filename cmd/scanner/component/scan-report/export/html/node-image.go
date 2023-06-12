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

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像列表搜索的安全报告
type ExportNodeImageHtmlSrv struct {
	NodeImageSrv   types.ImageSrvInterface
	ExportTaskDal  store.ExportTaskDal
	UpdateTask     types.UpdateExportTask
	VulnSrv        types.VulnService
	KoaAddr        string // 生成html的内部服务接口
	FileDir        string // 文件存放的绝对路径
	VulnClassType  []string
	NeedKernelVuln string
}

func NewExportNodeImageHtmlSrv(
	nodeImageSrv types.ImageSrvInterface,
	exportTaskDal store.ExportTaskDal,
	updateTask types.UpdateExportTask,
	vulnSrv types.VulnService,
	fileDir string,
	vulnClassType []string,
) *ExportNodeImageHtmlSrv {
	return &ExportNodeImageHtmlSrv{
		NodeImageSrv:   nodeImageSrv,
		ExportTaskDal:  exportTaskDal,
		UpdateTask:     updateTask,
		FileDir:        fileDir,
		KoaAddr:        consts.KoaAddr,
		VulnClassType:  vulnClassType,
		NeedKernelVuln: os.Getenv("IDENTITY_KERNEL_VULN"),
		VulnSrv:        vulnSrv,
	}
}

// 获取镜像ID和Name用于生成目录
func (s *ExportNodeImageHtmlSrv) GetImageIdNames(ctx context.Context, taskID int64) (*types.ImageIDNameWithTask, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv.GetImageIdNames start")
	images := make([]types.ImageIDName, 0)
	var lastImageID int64

	// 分批获取镜像
	for {
		filter := &model.Filter{Limit: consts.DefaultExportBathSize, SortFiled: "image_id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: lastImageID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv GetImageIdNames.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Int("image-id-length", len(images)).
				Msg("ExportNodeImageHtmlSrv GetImageIdNames finished")
			break
		}
		lastImageID = taskImages[len(taskImages)-1].ImageID

		for i := range taskImages {
			images = append(images, types.ImageIDName{
				ImageID:   taskImages[i].ImageID,
				ImageName: taskImages[i].ImageName,
			})
		}
	}

	logging.Get().Info().Int64("taskID", taskID).Int("image-length", len(images)).
		Msg("ExportNodeImageHtmlSrv.GetImageIdNames finished")
	return &types.ImageIDNameWithTask{TaskId: taskID, Images: images}, nil
}

// 镜像信息列表
func (s *ExportNodeImageHtmlSrv) GetImages(ctx context.Context, taskID int64, starID int64) (*types.ImageResponse, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Msg("ExportNodeImageHtmlSrv.GetImages")

	res := &types.ImageResponse{
		Images: make([]types.Image, 0),
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
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv GetImages finished")
			res.End = true
			break
		}
		starID = taskImages[len(taskImages)-1].ID
		res.StartID = starID
		imageIds := make([]int64, 0)

		param := imagesecModel.GetImageAssociateDataParam{
			ImageFromType:   imagesecModel.ImageFromNode,
			VulnEnable:      true,
			MalwareEnable:   true,
			SensitiveEnable: true,
			WebshellEnable:  true,
			SearchVulnParam: imagesecModel.ApiSearchVulnParam{
				ClassType:  s.VulnClassType,
				NeedKernel: s.NeedKernelVuln,
			},
		}

		for i := range taskImages {
			param.ImageId = taskImages[i].ImageID

			imageData, err := s.NodeImageSrv.GetImageCorrelateData(ctx, param)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("startID", starID).
					Msg("ExportNodeImageHtmlSrv GetImages.ListImageWithScanInfo")
				return nil, err
			}

			baseImage := imageData.ToImageBaseResponse()

			im := types.Image{
				ImageID:       baseImage.ID,
				ImageName:     baseImage.GetImageName(),
				FixedVuln:     types.VulnSeverityCount{},
				UnFixedVuln:   types.VulnSeverityCount{},
				Malicious:     imageData.MalwareCnt,
				RiskScore:     baseImage.RiskScore,
				NotMaintained: util.ExistBit1(baseImage.Flag, model.FlagImageNotMaintained),
				Flag:          baseImage.Flag,
			}

			im.AddVulnSeverityCount(imageData.Vuln)
			res.Images = append(res.Images, im)

			imageIds = append(imageIds, taskImages[i].ImageID)
		}

		if len(res.Images) > MaxImages {
			logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).
				Msg("ExportNodeImageHtmlSrv.GetImages partially completed")
			break
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Int("image-length", len(res.Images)).
		Msg("ExportNodeImageHtmlSrv.GetImages")
	return res, nil
}

// 风险总览
func (s *ExportNodeImageHtmlSrv) GetRiskOverView(ctx context.Context, taskID int64) (*types.RiskOverView, error) {
	overView, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, model.ExportHtmlPrepareRiskOver)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv.GetRiskOverView")
		return nil, fmt.Errorf("GetRiskOverView %d error :%s", taskID, err.Error())
	}
	if len(overView) == 0 {
		return nil, fmt.Errorf("not GetRiskOverView taskID: %d", taskID)
	}
	risk := &types.RiskOverView{}

	if err := json.Unmarshal([]byte(overView[0].Data), risk); err != nil {
		return nil, fmt.Errorf("GetRiskOverView:%d error: %s", taskID, err.Error())
	}

	return risk, nil
}

// 病毒列表
func (s *ExportNodeImageHtmlSrv) GetVirus(ctx context.Context, taskID int64) ([]types.VirusInfo, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv.GetVirus start")
	var startID int64
	res := make([]types.VirusInfo, 0)

	virusMap := make(map[int64]*imagesecModel.Malware)
	virusToImage := make(map[int64][]string)
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: taskID, StartID: startID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv GetVirus.SearchExportTaskImage")
			return nil, err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv GetVirus finished")
			break
		}
		startID = taskImages[len(taskImages)-1].ID

		for i := range taskImages {
			image, err := s.NodeImageSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{ImageId: taskImages[i].ImageID, MalwareEnable: true})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", taskImages[i].ImageID).Msg("ExportNodeImageHtmlSrv GetVirus")
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
		vi := types.VirusInfo{
			FilePath:  ima.Filepath,
			VirusName: ima.Name,
			Images:    virusToImage[v],
		}
		if vi.Images == nil {
			vi.Images = make([]string, 0)
		}
		res = append(res, vi)
	}

	logging.Get().Info().Int64("taskID", taskID).Int("virus-length", len(res)).Msg("ExportNodeImageHtmlSrv.GetVirus finished")

	return res, nil
}

// 按层取漏洞信息 canFixed:"true"，取可修复的，"false"取不可修复的，""表示取全部
// 首页信息，所有漏洞
func (s *ExportNodeImageHtmlSrv) GetExportVuln(ctx context.Context, param types.GetExportVulnParam) (*types.VulnWithImageResponse, error) {
	if param.Limit <= 0 {
		param.Limit = DefaultLimit
	}
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}
	logging.Get().Info().Int64("taskID", param.TaskID).Int64("severity", param.Severity).
		Str("canFixed", param.CanFixed).Int64("startID", param.StartID).Msg("ExportNodeImageHtmlSrv.GetExportVuln start")

	res := &types.VulnWithImageResponse{
		Vulns: make([]types.VulnWithImage, 0),
	}
	uniqueVulns := make([]uint64, 0)
	// 分批获取漏洞
	filter := &model.Filter{Limit: param.Limit, SortFiled: "id", SortBy: consts.SortByAsc}
	vulnImages, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, store.SearchHtmlVulnImageParam{
		TaskID: param.TaskID, StartID: param.StartID, Severity: param.Severity, CanFixed: param.CanFixed}, filter)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("ExportNodeImageHtmlSrv GetExportVuln SearchExportTaskImage")
		return nil, err
	}
	if len(vulnImages) < int(param.Limit) {
		res.End = true
	}
	for i := range vulnImages {
		res.StartID = vulnImages[i].ID
		uniqueVulns = append(uniqueVulns, vulnImages[i].UniqueVuln)
		res.Vulns = append(res.Vulns, types.VulnWithImage{
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
			logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("ExportNodeImageHtmlSrv GetExportVuln SearchExportTaskImage")
			return nil, err
		}

		vulnMap := make(map[uint64]*imagesecModel.VulnView)
		for i := range vulnsView {
			vulnMap[vulnsView[i].UniqueID] = vulnsView[i]
		}
		for i := range res.Vulns {
			res.Vulns[i].VulnDetail = types.ModelToVulnDetail(vulnMap[res.Vulns[i].UniqueVuln])
		}
	}

	logging.Get().Info().Int64("taskID", param.TaskID).Int64("severity", param.Severity).
		Str("canFixed", param.CanFixed).Int("vulns", len(res.Vulns)).
		Int64("startID", param.StartID).Bool("isEnd", res.End).Msg("ExportNodeImageHtmlSrv.GetExportVuln finished")
	return res, nil
}

// 按层级获取镜像的漏洞信息
// 单个镜像
func (s *ExportNodeImageHtmlSrv) GetImageVuln(ctx context.Context, param types.GetExportVulnParam) (*types.VulnWithImageResponse, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}
	if param.ImageID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get imageID:%d", param.ImageID)
	}
	logging.Get().Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Int64("severity", param.Severity).
		Msg("ExportNodeImageHtmlSrv.GetImageVuln start")
	res := &types.VulnWithImageResponse{
		ImageID: param.ImageID,
		Vulns:   make([]types.VulnWithImage, 0),
	}
	count := 0

	data, err := s.NodeImageSrv.GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType: imagesecModel.ImageFromNode,
		ImageId:       param.ImageID,
		VulnEnable:    true,
		SearchVulnParam: imagesecModel.ApiSearchVulnParam{
			ImageFromType: imagesecModel.ImageFromNode,
			SeverityInt:   []int64{param.Severity},
			NeedKernel:    s.NeedKernelVuln,
			ClassType:     s.VulnClassType,
			StartID:       param.StartID,
			Filter:        model.EmptyFilter().SetSortFiledByID().SetSortAsc(),
		},
	})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Msg("GetImageVuln GetImageCorrelateData")
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
		if (j >= len(vulns)-1 && len(uniqueVulns) > 0) || len(uniqueVulns) >= consts.DefaultLimit {
			vulnImage, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, store.SearchHtmlVulnImageParam{TaskID: param.TaskID, UniqueVulns: uniqueVulns}, nil)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Uint64("UniqueID", vuln.UniqueID).
					Msg("ExportNodeImageHtmlSrv GetImageVuln SearchHtmlVulnImage")
				return nil, err
			}
			for k := range vulnImage {
				res.Vulns = append(res.Vulns, types.VulnWithImage{Images: vulnImage[k].Images, VulnDetail: types.ModelToVulnDetail(vulnMap[vulnImage[k].UniqueVuln])})
				count += len(vulnImage[k].Images)
			}
			uniqueVulns = make([]uint64, 0)
		}

		if count > MaxVulnImages {
			logging.Get().Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Int64("severity", param.Severity).
				Msg("ExportNodeImageHtmlSrv.GetImageVuln partially completed")
			break
		}
	}

	logging.Get().Info().Int64("taskID", param.TaskID).Int64("severity", param.Severity).Int64("startID", param.StartID).
		Msg("ExportNodeImageHtmlSrv.GetImageVuln finished")
	return res, nil
}

// 单个镜像风险报告
func (s *ExportNodeImageHtmlSrv) GetImageRisk(ctx context.Context, taskID, imageID int64) (*types.ImageRiskOverView, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportNodeImageHtmlSrv.GetImageRisk start")

	task, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ID: taskID}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTensorTask")
		return nil, err
	}
	if len(task) == 0 {
		logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTensorTask not get task")
		return nil, err
	}

	// 查漏洞和敏感文件，生成处置建议
	param := imagesecModel.GetImageAssociateDataParam{
		ImageFromType:         imagesecModel.ImageFromNode,
		ImageId:               imageID,
		VulnEnable:            true, // 漏洞单独查询
		MalwareEnable:         true,
		SensitiveEnable:       true,
		WebshellEnable:        true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{OmitFields: model.GetVulnDefaultOmitFields()},
		SearchVulnParam: imagesecModel.ApiSearchVulnParam{
			ImageFromType: imagesecModel.ImageFromNode,
			NeedKernel:    s.NeedKernelVuln,
			ClassType:     s.VulnClassType,
			Filter:        model.EmptyFilterForTotalQuery(),
		},
		Filter: nil,
	}
	data, err := s.NodeImageSrv.GetImageCorrelateData(ctx, param)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).
			Msg("ExportNodeImageHtmlSrv GetImageRisk SearchScanImage")
		return nil, err
	}
	res := &types.ImageRiskOverView{
		ImageID:           data.ImageBaseResponse.ID,
		ImageName:         data.ImageBaseResponse.GetImageName(),
		VulnSeverityCount: types.StatisticsVulnSeverity(data.Vuln),
	}

	ctx = context.WithValue(ctx, imagesecModel.AcceptLanguage, task[0].Lang)
	im := data.ToImageBaseResponse()
	im.AdaptI18(ctx)
	res.Suggests = im.Suggests

	_ = s.UpdateTask.IncrRedisFinished(ctx, taskID)
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportNodeImageHtmlSrv.GetImageRisk finished")
	return res, nil
}

// 风险总览,获取这部分数据很耗时，需要提前做好
func (s *ExportNodeImageHtmlSrv) createRiskOverView(ctx context.Context, task model.ExportTensorTask) error {
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv.createRiskOverView start")
	// 先查一下，是否存在
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, task.ID, model.ExportHtmlPrepareRiskOver)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView.SearchHtmlPrepare")
		return err
	}
	if len(data) > 0 {
		logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView.SearchHtmlPrepare find data")
		return nil
	}
	var startID int64
	res := &types.RiskOverView{}
	// 查镜像信息 批量查询
	for {
		// 分批获取镜像
		filter := &model.Filter{Limit: 10, SortFiled: "id", SortBy: consts.SortByAsc}
		taskImages, err := s.ExportTaskDal.SearchExportTaskImage(ctx, store.SearchExportTaskImageParam{TaskID: task.ID, StartID: startID}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView.SearchExportTaskImage")
			return err
		}
		if len(taskImages) == 0 {
			logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView finished")
			break
		}
		for i := range taskImages {
			param := imagesecModel.GetImageAssociateDataParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ImageUniqueID: taskImages[i].ImageUniqueID,
				ImageId:       taskImages[i].ImageID,
				VulnEnable:    true,
				SearchVulnParam: imagesecModel.ApiSearchVulnParam{
					ImageFromType: imagesecModel.ImageFromNode,
					NeedKernel:    s.NeedKernelVuln,
					ClassType:     s.VulnClassType,
					Filter:        model.EmptyFilterForTotalQuery(),
				},
			}

			imageData, err := s.NodeImageSrv.GetImageCorrelateData(ctx, param)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Uint64("mageUniqueID", taskImages[i].ImageUniqueID).
					Int64("imageID", taskImages[i].ImageID).Msg("ExportNodeImageHtmlSrv createRiskOverView.ListImageWithScanInfo")
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
		filter := &model.Filter{Limit: consts.DefaultLimit, SortFiled: "id", SortBy: consts.SortByAsc}
		imageVulns, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, store.SearchHtmlVulnImageParam{
			TaskID:  task.ID,
			Fields:  []string{"id", "severity"},
			StartID: startID,
		}, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView ListImageWithScanInfo")
			return err
		}
		for i := range imageVulns {
			res.StatisticsVulnSeverity(imageVulns[i])
		}
		if len(imageVulns) == 0 {
			break
		}
		startID = imageVulns[len(imageVulns)-1].ID

		logging.Get().Info().Int64("taskID", task.ID).Int64("startID", startID).
			Msg("ExportNodeImageHtmlSrv createRiskOverView.SearchHtmlVulnImage")
	}
	res.Serializer()

	bys, err := json.Marshal(res)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv Marshal getRiskOverView")
		return err
	}

	if err := s.ExportTaskDal.CreateOrUpdateHTMLPrepare(ctx, &model.ExportHtmlPrepare{TaskID: task.ID, Data: string(bys),
		DataType: model.ExportHtmlPrepareRiskOver}); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv pre createRiskOverView")
		return err
	}

	_ = s.UpdateTask.SetRedisAll(ctx, task.ID, res.ImageCount)
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv createRiskOverView finished")
	return nil
}

// 查询当前导出服务的状态
func (s *ExportNodeImageHtmlSrv) getKoaStatus(ctx context.Context, taskID int64) (*types.KoaResponse, error) {

	url := fmt.Sprintf("%s/api/v1/middle/statusHtml?taskID=%d", s.KoaAddr, taskID)
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportNodeImageHtmlSrv.getKoaStatus start")

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
	response := &types.KoaResponse{}
	if err := json.NewDecoder(rsp.Body).Decode(response); err != nil {
		return nil, err
	}
	// filePath是一个路径，统一增加最后的斜杠
	if response.Data.FilePath != "" {
		if !strings.HasSuffix(response.Data.FilePath, "/") {
			response.Data.FilePath = response.Data.FilePath + "/"
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportNodeImageHtmlSrv.getKoaStatus finished")
	return response, nil
}

// 新建导出任务
func (s *ExportNodeImageHtmlSrv) createExportHtml(ctx context.Context, task model.ExportTensorTask) error {
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

	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).
		Msg("ExportNodeImageHtmlSrv.createExportHtml start")

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

	response := types.KoaResponse{}

	if err := json.NewDecoder(rsp.Body).Decode(&response); err != nil {
		return err
	}
	if response.Code != consts.KoaCodeSuccess {
		return fmt.Errorf("export html task create failed:%s,taskID:%d", response.Msg, task.ID)
	}
	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).
		Msg("ExportNodeImageHtmlSrv.createExportHtml finished")
	return nil
}

func (s *ExportNodeImageHtmlSrv) genFilePath(ctx context.Context, task model.ExportTensorTask) string {
	return s.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}

// 查询出当前导出任务所有的漏洞信息，写入备用
func (s *ExportNodeImageHtmlSrv) createVulnImage(ctx context.Context, taskID int64) error {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv prepareVuln start")
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
			logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv prepareVuln SearchExportTaskImage")
			return err
		}
		if len(exportImages) == 0 {
			logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv createVulnImage finished")
			break
		}
		startID = exportImages[len(exportImages)-1].ID
		for i := range exportImages {
			// 获取该镜像的所有漏洞
			param := imagesecModel.GetImageAssociateDataParam{
				ImageFromType: imagesecModel.ImageFromNode,
				ImageUniqueID: exportImages[i].ImageUniqueID,
				VulnEnable:    true,
				SearchVulnParam: imagesecModel.ApiSearchVulnParam{
					ClassType:  s.VulnClassType,
					NeedKernel: s.NeedKernelVuln,
				},
			}
			imageData, err := s.NodeImageSrv.GetImageCorrelateData(ctx, param)

			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).
					Uint64("ImageUniqueID", exportImages[i].ImageUniqueID).Msg("ExportNodeImageHtmlSrv prepareVuln SearchVuln")
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
			duplicates, err := s.ExportTaskDal.SearchHTMLVulnImage(ctx, store.SearchHtmlVulnImageParam{
				TaskID:      taskID,
				Fields:      []string{"id", "task_id", "unique_vuln"},
				UniqueVulns: uniques,
			}, nil)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).
					Msg("ExportNodeImageHtmlSrv prepareVuln SearchHtmlVulnImage")
				return err
			}
			// 整理漏洞
			duplicatedVuln := InANotInB2(vulns, duplicates)
			if len(duplicatedVuln) == 0 {
				continue
			}
			vulnImages := make([]*model.ExportVulnImage, 0)
			for j := range duplicatedVuln {
				vuln := duplicatedVuln[j]
				// 获取这个漏洞所关联的镜像
				taskImages, err := s.ExportTaskDal.GetExportNodeImageRelatedVuln(ctx, vuln.UniqueID, taskID)
				if err != nil {
					logging.Get().Err(err).Int64("taskID", taskID).Uint64("UniqueID", vuln.UniqueID).
						Msg("ExportNodeImageHtmlSrv prepareVuln GetExportImageRelatedVuln")
					return err
				}

				taskImageNames := make([]string, 0)
				for k := range taskImages {
					taskImageNames = append(taskImageNames, taskImages[k].ImageName)
				}
				vulnImage := &model.ExportVulnImage{
					TaskID:     taskID,
					UniqueVuln: vuln.UniqueID,
					Images:     taskImageNames,
					CanFixed:   vuln.FixedVersion != "",
					Severity:   vuln.SeverityInt,
				}
				vulnImages = append(vulnImages, vulnImage)
			}

			if err := s.ExportTaskDal.CreateHTMLVulnImage(ctx, vulnImages); err != nil {
				logging.Get().Err(err).Int64("taskID", taskID).Int("vulnImage", len(vulnImages)).
					Msg("ExportNodeImageHtmlSrv prepareVuln CreateHtmlVulnImage")
				continue
			}
			logging.Get().Info().Int64("taskID", taskID).Int64("imageID", exportImages[i].ImageID).
				Int("vulnImage", len(vulnImages)).Msg("ExportNodeImageHtmlSrv prepareVuln CreateHtmlVulnImage")
		}
		// pod重启后不用再重新计算。
		if err := s.ExportTaskDal.CreateOrUpdateHTMLPrepare(ctx, &model.ExportHtmlPrepare{
			TaskID:   taskID,
			DataType: model.ExportHtmlPrepareVulnLastImage,
			Data:     fmt.Sprintf("%d", startID),
		}); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("lastImageID", startID).
				Msg("ExportNodeImageHtmlSrv prepareVuln CreateOrUpdateHtmlPrepare")
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportNodeImageHtmlSrv.prepareVuln finished")
	return nil
}

func InANotInB2(a []*imagesecModel.VulnView, b []model.ExportVulnImage) []*imagesecModel.VulnView {
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

func (s *ExportNodeImageHtmlSrv) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		TaskType:        model.ExportHtml,
		ExecuteType:     []string{consts.ExportNodeImageSearch},
		Finished:        consts.FalseString,
		ExportHtmlReady: consts.TrueString,
	}, &model.Filter{
		SortBy:    consts.SortByDesc,
		SortFiled: "id",
		Limit:     1,
	})
	if err != nil {
		logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportNodeImageHtmlSrv SearchExportTensorTask")
		return
	}
	if len(tasks) == 0 {
		return
	}
	task := tasks[0]
	// 支持横向扩展
	// created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, task.ID)
	// if err != nil {
	// 	logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportNodeImageHtmlSrv CreateExportIdempotent")
	// 	return
	// }
	// if !created {
	// 	logging.Get().Info().Str("TaskType", model.ExportHtml).Msg("ExportNodeImageHtmlSrv task running other pod ")
	// 	return
	// }

	// 把漏洞统计好,pod可能会重启
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv start createVulnImage")
	if err := s.createVulnImage(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv pre createVulnImage")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv finish createVulnImage")

	// 把风险概览信息准备好,pod重启后可能会重复写入
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv start createRiskOverView")
	if err := s.createRiskOverView(ctx, task); err != nil && !strings.Contains(err.Error(), consts.DuplicateKey) {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv pre createRiskOverView")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}

	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv finish createRiskOverView")

	if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportNodeImageHtmlSrv export html Start")
		return
	}

	// 新建目录
	filePath := s.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Err(err).Str("filePath", filePath).Msg("ExportNodeImageHtmlSrv export html MkdirIfNotExist")
		return
	}
	// 导出完成时删除目录
	defer func(filePath string) {
		if err := os.RemoveAll(filePath); err != nil {
			logging.Get().Err(err).Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv defer remove path ")
			return
		}
		logging.Get().Info().Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv defer remove path ")
	}(filePath)

	if err = s.createExportHtml(ctx, task); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportNodeImageHtmlSrv export html task create failure")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv.createExportHtml success")

	// 如果创建成功，就一直轮询状态
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	// 服务可能会出错，所以这里提供一个重试机制
	statusRetry := 1
	for {
		<-ticker.C
		status, err := s.getKoaStatus(ctx, task.ID)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv export html getKoaStatus failure")
			statusRetry++
			if statusRetry < 100 {
				continue
			}
			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask Failure")
			}
			break
		}
		logging.Get().Info().Int64("taskID", task.ID).Str("filePath", task.FilePath).Interface("status", status).
			Msg("ExportNodeImageHtmlSrv.getKoaStatus success")

		if status.Data.Status == consts.KoaStatusSuccess {
			// 调用用命令进行压缩
			zipFilename := s.FileDir + "/" + task.FilePath
			logging.Get().Info().Str("zipFilename", zipFilename).Str("filePath", filePath).
				Msg("ExportNodeImageHtmlSrv ZipAndSave use zip start zip")
			command := fmt.Sprintf("cd %s;zip -r %s %s", s.FileDir, task.FilePath, strings.ReplaceAll(task.FilePath, ".zip", ""))

			logging.Get().Info().Str("command", command).Msg("ExportNodeImageHtmlSrv command")
			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", task.FilePath).
					Msg("ExportNodeImageHtmlSrv ZipAndSave use zip")
				if err := s.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
					logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv UpdateExportTask Failure")
				}
			}
			logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", status.Data.FilePath).
				Msg("ExportNodeImageHtmlSrv ZipAndSave use zip success")

			// 成功之后更新任务
			if err := s.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv Success export html task success update task")
			}
			break
		} else if status.Data.Status == consts.KoaStatusFailed || status.Data.Status == "" {
			// 保存状态
			logging.Get().Info().Int64("taskID", task.ID).Msg("export html execute failure")
			if len(status.Data.FailedMsg) == 0 {
				if status.Msg != "" {
					status.Data.FailedMsg = []types.FailedMsg{{Message: status.Msg}}
				}
				status.Data.FailedMsg = []types.FailedMsg{{Message: "未知错误"}}
			}
			errMsg := status.Data.FailedMsg[len(status.Data.FailedMsg)-1].Message

			if err := s.UpdateTask.Failure(ctx, task.ID, errMsg); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv UpdateExportTask Failure")
			}
			break
		} else {
			logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv export html executing ")
		}
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportNodeImageHtmlSrv export html execute complete")
	_ = s.UpdateTask.DeleteRedisData(ctx, task.ID)

	return
}
