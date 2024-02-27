package html

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	types2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	imagesec2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像列表搜索的安全报告
type ExportCiImageHtmlSrv struct {
	ExportTaskDal imagesec2.ExportTaskDal
	UpdateTask    types2.UpdateExportTask
	KoaAddr       string // 生成html的内部服务接口
	FileDir       string // 文件存放的绝对路径
}

func NewExportCiImageHtmlSrv(
	exportTaskDal imagesec2.ExportTaskDal,
	updateTask types2.UpdateExportTask,
	fileDir string,
) *ExportCiImageHtmlSrv {
	return &ExportCiImageHtmlSrv{
		ExportTaskDal: exportTaskDal,
		UpdateTask:    updateTask,
		FileDir:       fileDir,
		KoaAddr:       consts.KoaAddr,
	}
}

// 获取镜像ID和Name用于生成目录
func (s *ExportCiImageHtmlSrv) GetImageIdNames(ctx context.Context, taskID int64) (*types2.ImageIDNameWithTask, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv.GetImageIdNames start")
	res := &types2.ImageIDNameWithTask{TaskId: taskID, Images: make([]types2.ImageIDName, 0)}

	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("GetImages.SearchHtmlPrepare")
		return res, err
	}
	if len(data) == 0 {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("GetImages.SearchHtmlPrepare not find data")
		return res, err
	}
	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("GetImages.SearchExportTaskImage")
		return nil, err
	}

	for i := range taskImages {
		res.Images = append(res.Images, types2.ImageIDName{ImageID: taskImages[i].ImageBaseResponse.ID,
			ImageName: taskImages[i].ImageBaseResponse.GetImageName()})
	}

	logging.Get().Info().Int64("taskID", taskID).Int("image-length", len(res.Images)).Msg("ExportCiImageHtmlSrv.GetImageIdNames finished")
	return res, nil
}

// 镜像信息列表,cicd一次扫描任务的镜像不会太多，不用分批取
func (s *ExportCiImageHtmlSrv) GetImages(ctx context.Context, taskID int64, starID int64) (*types2.ImageResponse, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).Msg("ExportCiImageHtmlSrv.GetImages")

	res := &types2.ImageResponse{
		Images: make([]types2.Image, 0),
		End:    true,
	}

	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("startID", starID).Msg("GetImages.SearchHtmlPrepare")
		return nil, err
	}
	if len(data) == 0 {
		logging.Get().Info().Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv not find image info")
		return res, nil
	}

	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("startID", starID).Msg("GetImages.SearchExportTaskImage")
		return nil, err
	}

	for i := range taskImages {
		baseImage := taskImages[i].ImageBaseResponse
		im := types2.Image{
			ImageID:     baseImage.ID,
			ImageName:   baseImage.GetImageName(),
			FixedVuln:   types2.VulnSeverityCount{},
			UnFixedVuln: types2.VulnSeverityCount{},
			RiskScore:   baseImage.RiskScore,
			Flag:        baseImage.Flag,
		}

		im.AddVulnSeverityCount(taskImages[i].Vuln)
		res.Images = append(res.Images, im)
	}

	logging.Get().Info().Int64("taskID", taskID).Int64("startId", starID).
		Int("image-length", len(res.Images)).Msg("ExportCiImageHtmlSrv.GetImages")
	return res, nil
}

// 风险总览
func (s *ExportCiImageHtmlSrv) GetRiskOverView(ctx context.Context, taskID int64) (*types2.RiskOverView, error) {
	risk := &types2.RiskOverView{}
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv.GetRiskOverView.SearchHtmlPrepare")
		return nil, err
	}
	if len(data) == 0 {
		logging.Get().Info().Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv.GetRiskOverView not find image info")
		return risk, nil
	}

	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv.GetRiskOverView.SearchExportTaskImage")
		return nil, err
	}

	images := make([]*imagesec.ImageBaseResponse, 0)
	imageNames := make([]string, 0)
	for i := range taskImages {
		images = append(images, &(taskImages[i].ImageBaseResponse))
		imageNames = append(imageNames, taskImages[i].ImageBaseResponse.GetImageName())
	}

	risk.StatisticsImageAttr(images)

	for i := range taskImages {
		for j := range taskImages[i].Vuln {
			vu := taskImages[i].Vuln[j]
			risk.StatisticsVulnSeverity(imagesec.ExportVulnImage{
				TaskID:   taskID,
				Severity: vu.SeverityInt,
				CanFixed: vu.FixedVersion != "",
				Images:   imageNames,
			})
		}
	}

	return risk, nil
}

// 病毒列表
func (s *ExportCiImageHtmlSrv) GetVirus(ctx context.Context, taskID int64) ([]types2.VirusInfo, error) {
	logging.Get().Info().Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv.GetVirus start")
	res := make([]types2.VirusInfo, 0)
	return res, nil
}

// 按层取漏洞信息 canFixed:"true"，取可修复的，"false"取不可修复的，""表示取全部
// 首页信息，所有漏洞
func (s *ExportCiImageHtmlSrv) GetExportVuln(ctx context.Context, param types2.GetExportVulnParam) (
	*types2.VulnWithImageResponse, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}

	logging.Get().Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Str("severity", param.Severity).
		Msg("ExportCiImageHtmlSrv.GetImageVuln start")

	res := &types2.VulnWithImageResponse{
		Vulns: make([]types2.VulnWithImage, 0),
		End:   true,
	}

	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, param.TaskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("GetImages.SearchHtmlPrepare")
		return nil, err
	}

	if len(data) == 0 {
		logging.Get().Info().Int64("taskID", param.TaskID).Msg("ExportCiImageHtmlSrv not find image info")
		return res, nil
	}

	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("GetImages.SearchExportTaskImage")
		return nil, err
	}

	imageNames := make([]string, 0)
	for i := range taskImages {
		imageNames = append(imageNames, taskImages[i].ImageBaseResponse.GetImageName())
	}

	for i := range taskImages {
		for j := range taskImages[i].Vuln {
			vu := taskImages[i].Vuln[j]
			// 只取当前层级的漏洞
			if vu.Severity != param.Severity {
				continue
			}
			if (param.CanFixed == consts.TrueString && vu.FixedVersion == "") || (param.CanFixed == consts.FalseString && vu.FixedVersion != "") {
				continue
			}
			res.Vulns = append(res.Vulns, types2.VulnWithImage{
				Images:     imageNames,
				VulnDetail: types2.ModelToVulnDetail(taskImages[i].Vuln[j]),
			})
		}
	}

	logging.Get().Info().Int64("taskID", param.TaskID).Str("severity", param.Severity).Str("canFixed", param.CanFixed).
		Int("vulns", len(res.Vulns)).Bool("isEnd", res.End).Msg("ExportCiImageHtmlSrv.GetExportVuln finished")
	return res, nil
}

// 按层级获取镜像的漏洞信息
// 单个镜像
func (s *ExportCiImageHtmlSrv) GetImageVuln(ctx context.Context, param types2.GetExportVulnParam) (
	*types2.VulnWithImageResponse, error) {
	if param.TaskID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get taskID:%d", param.TaskID)
	}
	if param.ImageID <= 0 {
		return nil, fmt.Errorf("GetExportVuln not get imageID:%d", param.ImageID)
	}
	logging.Get().Info().Int64("taskID", param.TaskID).Int64("imageID", param.ImageID).Str("severity", param.Severity).
		Msg("ExportLibImageHtmlSrv.GetImageVuln start")

	res := &types2.VulnWithImageResponse{
		Vulns: make([]types2.VulnWithImage, 0),
		End:   true,
	}

	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, param.TaskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("GetImages.SearchHtmlPrepare")
		return nil, err
	}
	if len(data) == 0 {
		logging.Get().Info().Int64("taskID", param.TaskID).Msg("ExportCiImageHtmlSrv not find image info")
		return res, nil
	}

	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", param.TaskID).Msg("GetImages.SearchExportTaskImage")
		return nil, err
	}

	imageNames := make([]string, 0)
	for i := range taskImages {
		imageNames = append(imageNames, taskImages[i].ImageBaseResponse.GetImageName())
	}

	for i := range taskImages {
		if taskImages[i].ImageBaseResponse.ID != param.ImageID {
			continue
		}
		for j := range taskImages[i].Vuln {
			vu := taskImages[i].Vuln[j]
			// 只取当前层级的漏洞
			if vu.Severity != param.Severity {
				continue
			}
			res.Vulns = append(res.Vulns, types2.VulnWithImage{
				Images:     imageNames,
				VulnDetail: types2.ModelToVulnDetail(taskImages[i].Vuln[j]),
			})
		}
	}

	logging.Get().Info().Int64("taskID", param.TaskID).Str("severity", param.Severity).Int64("imageID", param.ImageID).
		Int("vulnCnt", len(res.Vulns)).Msg("ExportCiImageHtmlSrv.GetImageVuln finished")
	return res, nil
}

// 单个镜像风险报告
func (s *ExportCiImageHtmlSrv) GetImageRisk(ctx context.Context, taskID, imageID int64) (*types2.ImageRiskOverView, error) {
	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportCiImageHtmlSrv.GetImageRisk start")

	task, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesec.SearchExportTaskParam{ID: taskID})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTask")
		return nil, err
	}
	if len(task) == 0 {
		logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTask not get task")
		return nil, err
	}

	res := &types2.ImageRiskOverView{
		ImageID:           imageID,
		ImageName:         "",
		VulnSeverityCount: types2.VulnSeverityCount{},
	}
	data, err := s.ExportTaskDal.SearchHtmlPrepare(ctx, taskID, imagesec.ExportHtmlPrepareCicdImageDetail)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchHtmlPrepare")
		return nil, err
	}
	if len(data) == 0 {
		logging.Get().Info().Int64("taskID", taskID).Msg("ExportCiImageHtmlSrv not find image info")
		return res, nil
	}

	taskImages := make([]imagesec.ImageWithCorrelateData2, 0)

	if err := json.Unmarshal([]byte(data[0].Data), &taskImages); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Int64("imageID", imageID).Msg("GetImages.SearchExportTaskImage")
		return nil, err
	}

	ctx = context.WithValue(ctx, model.AcceptLanguage, task[0].Lang)

	for i := range taskImages {
		im := taskImages[i].ToImageBaseResponse()
		im.AdaptI18(ctx)

		if im.ID == imageID {
			res.ImageName = im.GetImageName()
			res.Suggests = im.Suggests
			res.VulnSeverityCount = types2.StatisticsVulnSeverity(taskImages[i].Vuln)
		}
	}

	logging.Get().Info().Int64("taskID", taskID).Int64("imageID", imageID).Msg("ExportCiImageHtmlSrv.GetImageRisk finished")
	return res, nil
}

// 查询当前导出服务的状态
func (s *ExportCiImageHtmlSrv) getKoaStatus(ctx context.Context, taskID int64) (*types2.KoaResponse, error) {

	url := fmt.Sprintf("%s/api/v1/middle/statusHtml?taskID=%d", s.KoaAddr, taskID)
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportCiImageHtmlSrv.getKoaStatus start")

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
	logging.Get().Info().Int64("taskID", taskID).Str("url", url).Msg("ExportCiImageHtmlSrv.getKoaStatus finished")
	return response, nil
}

// 新建导出任务
func (s *ExportCiImageHtmlSrv) createExportHtml(ctx context.Context, task imagesec.ExportTensorTask) error {
	url := s.KoaAddr + "/api/v1/middle/startCreateHtml"

	type body struct {
		TaskID   int64  `json:"taskID"`
		FilePath string `json:"filePath"`
		Lang     string `json:"lang"`
	}
	postData := body{
		TaskID:   task.ID,
		FilePath: s.genFilePath(ctx, task),
		Lang:     task.Lang,
	}

	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).Msg("ExportCiImageHtmlSrv.createExportHtml start")

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

	defer func() { _ = rsp.Body.Close() }()

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
	logging.Get().Info().Int64("taskID", task.ID).Str("url", url).Str("filePath", postData.FilePath).
		Msg("ExportCiImageHtmlSrv.createExportHtml finished")
	return nil
}

func (s *ExportCiImageHtmlSrv) genFilePath(ctx context.Context, task imagesec.ExportTensorTask) string {
	return s.FileDir + "/" + strings.ReplaceAll(task.FilePath, ".zip", "") + "/"
}

func (s *ExportCiImageHtmlSrv) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesec.SearchExportTaskParam{
		TaskType:        imagesec.ExportHtml,
		ExecuteType:     []string{consts.ExportCIReport},
		Finished:        consts.FalseString,
		Failure:         consts.FalseString,
		ExportHtmlReady: consts.TrueString,
		Filter: &imagesec.Filter{
			SortBy:    consts.SortByDesc,
			SortFiled: "id",
			Limit:     1,
		},
	})
	if err != nil {
		logging.Get().Err(err).Str("TaskType", imagesec.ExportHtml).Msg("ExportCiImageHtmlSrv SearchExportTask")
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
	// 	logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportCiImageHtmlSrv CreateExportIdempotent")
	// 	return
	// }
	// if !created {
	// 	logging.Get().Info().Str("TaskType", model.ExportHtml).Msg("ExportCiImageHtmlSrv task running other pod ")
	// 	return
	// }

	if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportCiImageHtmlSrv export html Start")
		return
	}

	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv  Start")
	// 新建目录
	filePath := s.genFilePath(ctx, task)
	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Err(err).Str("filePath", filePath).Msg("ExportCiImageHtmlSrv export html MkdirIfNotExist")
		return
	}
	// 导出完成时删除目录
	defer func(filePath string) {
		if err := os.RemoveAll(filePath); err != nil {
			logging.Get().Err(err).Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv defer remove path ")
			return
		}
		logging.Get().Info().Str("filePath", filePath).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv defer remove path ")
	}(filePath)

	if err = s.createExportHtml(ctx, task); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("filePath", task.FilePath).Msg("ExportCiImageHtmlSrv export html task create failure")
		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv UpdateExportTask Failure")
		}
		return
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv.createExportHtml success")

	// 如果创建成功，就一直轮询状态
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	// 服务可能会出错，所以这里提供一个重试机制
	statusRetry := 1
	for {
		<-ticker.C
		status, err := s.getKoaStatus(ctx, task.ID)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv export html getKoaStatus failure")
			statusRetry++
			if statusRetry < 100 {
				continue
			}
			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateExportTask Failure")
			}
			break
		}
		logging.Get().Info().Int64("taskID", task.ID).Str("filePath", task.FilePath).Interface("status", status).Msg("ExportCiImageHtmlSrv.getKoaStatus success")

		if status.Data.Status == consts.KoaStatusSuccess {
			// 调用用命令进行压缩
			zipFilename := s.FileDir + "/" + task.FilePath
			logging.Get().Info().Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ExportCiImageHtmlSrv ZipAndSave use zip start zip")
			command := fmt.Sprintf("cd %s;zip -r %s %s", s.FileDir, task.FilePath, strings.ReplaceAll(task.FilePath, ".zip", ""))

			logging.Get().Info().Str("command", command).Msg("ExportCiImageHtmlSrv command")
			cmd := exec.Command("sh", "-c", command)
			if err := cmd.Run(); err != nil {
				logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", task.FilePath).Msg("ExportCiImageHtmlSrv ZipAndSave use zip")
				if err := s.UpdateTask.Failure(ctx, task.ID, "zip error"); err != nil {
					logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv UpdateExportTask Failure")
				}
			}
			logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", status.Data.FilePath).Msg("ExportCiImageHtmlSrv ZipAndSave use zip success")

			// 成功之后更新任务
			if err := s.UpdateTask.Success(ctx, task.ID, zipFilename); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv Success export html task success update task")
			}
			break
		} else if status.Data.Status == consts.KoaStatusFailed || status.Data.Status == "" {
			// 保存状态
			logging.Get().Info().Int64("taskID", task.ID).Msg("export html execute failure")
			if err := s.UpdateTask.Failure(ctx, task.ID, status.Data.FailedMsg.Message); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv UpdateExportTask Failure")
			}
			break
		} else {
			logging.Get().Info().Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv export html executing ")
		}
	}
	logging.Get().Info().Int64("taskID", task.ID).Msg("ExportCiImageHtmlSrv export html execute complete")

	return
}
