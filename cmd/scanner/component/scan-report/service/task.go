package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExportTaskInterface interface {
	CreateExportTask(ctx context.Context, data *model.ExportTensorTask) error
	SearchExportTask(ctx context.Context, param types.SearchExportTaskParam, filter *model.Filter) ([]model.ExportTensorTask, int64, error)
	GetExportTask(ctx context.Context, param types.GetExportTaskParam) (*model.ExportTensorTask, error)
	UpdateExportTask(ctx context.Context, id int64, updater map[string]interface{}) error
	CheckScanTask(ctx context.Context, scanTaskID int64) (*ExportLimit, error)
	CreateSearchImage(ctx context.Context, taskID int64, param imagesecModel.ImageListParam) error
	CreateLibScanTaskImage(ctx context.Context, taskID int64, scanGroupID int64) error
	GetTaskSchedule(ctx context.Context, task model.ExportTensorTask) (ExportSchedule, error)
	CreateCiExportData(ctx context.Context, taskID int64, data scanner_ci.PolicyResult) error // cicd导出报告，写入准备数据
	ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) ([]*imagesecModel.ImageBaseResponse, int64, error)
	CreateNodeScanTaskImage(ctx context.Context, exportTaskID int64, scanTaskID int64) error
}

type ExportTaskSrv struct {
	ExportDal               store.ExportTaskDal
	LibImageSrv             types.ImageSrvInterface
	NodeImageSrv            types.ImageSrvInterface
	ScanTaskDal             store.ScanTaskDal
	NodeScanTaskSrv         types.ScanTaskService
	MaxImageByOneExportTask int64
	RedisCli                *redis.Client
	VulnDal                 store.VulnDalInterface
}

func NewExportTaskSrv(
	exportDal store.ExportTaskDal,
	maxImageByOneExportTask int64,
	scanTaskDal store.ScanTaskDal,
	libImageSrv types.ImageSrvInterface,
	nodeImageSrv types.ImageSrvInterface,
	nodeScanTaskSrv types.ScanTaskService,
	redisCli *redis.Client,
	vulnDal store.VulnDalInterface,
) *ExportTaskSrv {
	return &ExportTaskSrv{
		ExportDal:               exportDal,
		LibImageSrv:             libImageSrv,
		NodeImageSrv:            nodeImageSrv,
		ScanTaskDal:             scanTaskDal,
		NodeScanTaskSrv:         nodeScanTaskSrv,
		MaxImageByOneExportTask: maxImageByOneExportTask,
		RedisCli:                redisCli,
		VulnDal:                 vulnDal,
	}
}

func (s *ExportTaskSrv) GetImageCorrelateData(ctx context.Context, param imagesecModel.GetImageAssociateDataParam) (
	*imagesecModel.ImageWithCorrelateData2, error) {
	return s.GetImageSrv(ctx, param.ImageFromType).GetImageCorrelateData(ctx, param)
}

func (s *ExportTaskSrv) ListImageWithScanInfo(ctx context.Context, param imagesecModel.ImageListParam) (
	[]*imagesecModel.ImageBaseResponse, int64, error) {
	return s.GetImageSrv(ctx, param.ImageFromType).ListImageWithScanInfo(ctx, param)
}

type ExportSchedule struct {
	All      int64
	Finished int64
}

func (s *ExportTaskSrv) GetTaskSchedule(ctx context.Context, task model.ExportTensorTask) (ExportSchedule, error) {

	cmd1 := s.RedisCli.Get(ctx, task.GenRedisAllKey())
	if cmd1.Err() != nil && cmd1.Err() != redis.Nil {
		return ExportSchedule{}, cmd1.Err()
	}
	all, _ := cmd1.Int64()

	cmd2 := s.RedisCli.Get(ctx, task.GenRedisFinishedKey())
	if cmd2.Err() != nil && cmd2.Err() != redis.Nil {
		return ExportSchedule{}, cmd2.Err()
	}
	finished, _ := cmd2.Int64()
	if finished >= all {
		finished = all
	}

	return ExportSchedule{All: all, Finished: finished}, nil
}

func (s *ExportTaskSrv) UpdateExportTask(ctx context.Context, id int64, updater map[string]interface{}) error {
	if id <= 0 || len(updater) == 0 {
		return fmt.Errorf("no id or no updater")
	}
	if err := s.ExportDal.UpdateExportTensorTask(ctx, fmt.Sprintf("id = %d", id), updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("UpdateExportTask")
	}
	return nil
}

func (s *ExportTaskSrv) CreateExportTask(ctx context.Context, data *model.ExportTensorTask) error {
	if err := data.Check(); err != nil {
		return err
	}
	// 把文件名写进去，用于前端展示
	if err := s.ExportDal.CreateExportTensorTask(ctx, data); err != nil {
		logging.Get().Err(err).Msg("CreateExportTask")
		return err
	}
	return nil
}

func (s *ExportTaskSrv) SearchExportTask(ctx context.Context, param types.SearchExportTaskParam, filter *model.Filter) (
	[]model.ExportTensorTask, int64, error) {
	tasks, cnt, err := s.ExportDal.SearchExportTensorTask(ctx,
		store.SearchExportTensorTask{
			ExecuteType:  param.ExecuteType,
			Finished:     param.Finished,
			Failure:      param.Failure,
			NeedCiReport: param.NeedCiReport,
		}, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchExportTask")
		return nil, 0, err
	}
	return tasks, cnt, nil
}

func (s *ExportTaskSrv) GetExportTask(ctx context.Context, param types.GetExportTaskParam) (*model.ExportTensorTask, error) {
	if param.ID <= 0 && param.UUID == "" {
		return nil, fmt.Errorf("please input id :%d or uuid:%s", param.ID, param.UUID)
	}

	tasks, _, err := s.ExportDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ID: param.ID, Parameter: param.UUID},
		&model.Filter{
			SortBy:    consts.SortByDesc,
			SortFiled: "id",
			Limit:     1,
		})
	if err != nil {
		logging.Get().Err(err).Msg("GetExportTask")
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("not find the task taskId is :%d,uuid is:%s", param.ID, param.UUID)
	}

	return &(tasks[0]), nil
}

type ExportLimit struct {
	ImageCount int64 `json:"imageCount"`
	ImageLimit int64 `json:"imageLimit"`
}

func (s *ExportTaskSrv) CheckScanTask(ctx context.Context, scanTaskId int64) (*ExportLimit, error) {
	if scanTaskId <= 0 {
		return nil, fmt.Errorf("no scanTaskId")
	}
	_, all, err := s.ScanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
		Statuses: []int{consts.ImageScanSuccess}, TaskIds: []int64{scanTaskId}},
		&model.Filter{Limit: 1, Offset: 0})
	if err != nil {
		logging.Get().Err(err).Int64("scanTaskId", scanTaskId).Msg("CheckScanTask")
		return nil, err
	}
	return &ExportLimit{ImageCount: all, ImageLimit: s.MaxImageByOneExportTask}, nil
}

func (s *ExportTaskSrv) GetImageSrv(ctx context.Context, imageFromType string) types.ImageSrvInterface {
	if imageFromType == imagesecModel.ImageFromNode {
		return s.NodeImageSrv
	}
	return s.LibImageSrv
}

func (s *ExportTaskSrv) CreateNodeScanTaskImage(ctx context.Context, exportTaskID int64, scanTaskID int64) error {
	if exportTaskID <= 0 {
		return fmt.Errorf("no exportTaskID:%d", exportTaskID)
	}

	var lastID int64

	filter := model.EmptyFilter().SetSortFiledByID().SetSortAsc().SetLimit(consts.DefaultLimit)
	for {
		subtasks, _, err := s.NodeScanTaskSrv.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
			TaskID:  scanTaskID,
			StartID: lastID,
			Filter:  filter,
		})
		if err != nil {
			logging.Get().Err(err).Int64("exportTaskID", exportTaskID).Int64("scanTaskID", scanTaskID).
				Msg("CreateScanTaskImage GetTaskList")
			return err
		}

		if len(subtasks) == 0 {
			break
		}
		lastID = subtasks[len(subtasks)-1].ID

		data := make([]*model.ExportTaskImage, 0)
		for i := range subtasks {
			data = append(data, &model.ExportTaskImage{
				TaskID:    exportTaskID,
				ImageID:   subtasks[i].ID,
				ImageName: subtasks[i].ImageName,
			})
		}

		if err := s.ExportDal.CreateExportTaskImage(ctx, data); err != nil {
			logging.Get().Err(err).Int64("exportTaskID", exportTaskID).Int64("scanTaskID", scanTaskID).
				Msg("CreateScanTaskImage CreateExportTaskImage")
		}
	}
	return nil
}

func (s *ExportTaskSrv) CreateLibScanTaskImage(ctx context.Context, taskID int64, scanGroupID int64) error {
	if taskID <= 0 {
		return fmt.Errorf("no taskID:%d", taskID)
	}
	var startID int64
	filter := &model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
	// 前端传过来的是groupID
	scanTasks, _, err := s.ScanTaskDal.GetTaskList(ctx, store.SearchTaskParam{GroupID: scanGroupID}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("groupID", scanGroupID).Msg("CreateScanTaskImage GetTaskList")
		return err
	}
	taskIds := make([]int64, 0)
	for i := range scanTasks {
		taskIds = append(taskIds, scanTasks[i].ID)
	}
	if len(taskIds) == 0 {
		logging.Get().Err(err).Int64("scanGroupID", scanGroupID).Msg("GenImageChan not fond task")
		return nil
	}

	for {
		param := store.SearchSubTaskParam{
			TaskIds:  taskIds,
			Statuses: []int{consts.ImageScanSuccess},
			StartID:  startID,
		}

		subtasks, _, err := s.ScanTaskDal.GetSubTasks(ctx, param, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).
				Msg("CreateScanTaskImage GetSubTasks")
			return err
		}
		if len(subtasks) == 0 {
			break
		}
		startID = subtasks[len(subtasks)-1].ID

		imageIds := make([]int64, 0)
		for i := range subtasks {
			imageIds = append(imageIds, subtasks[i].ImageID)
		}
		imageListParam := imagesecModel.ImageListParam{ImageIds: imageIds, Filter: filter}

		images, _, err := s.GetImageSrv(ctx, imagesecModel.ImageFromRegistry).ListImageWithScanInfo(ctx, imageListParam)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).
				Msg("CreateScanTaskImage ListImageWithScanInfo")
			return err
		}
		data := make([]*model.ExportTaskImage, 0)
		for i := range images {
			data = append(data, &model.ExportTaskImage{
				TaskID:    taskID,
				ImageID:   images[i].ID,
				ImageName: images[i].GetImageName(),
			})
		}

		if err := s.ExportDal.CreateExportTaskImage(ctx, data); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).
				Msg("CreateScanTaskImage CreateExportTaskImage")
		}
	}
	return nil

}

func (s *ExportTaskSrv) CreateSearchImage(ctx context.Context, taskID int64, param imagesecModel.ImageListParam) error {
	if taskID <= 0 {
		return fmt.Errorf("no taskID:%d", taskID)
	}
	var startID int64
	for {
		param.Filter = &model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
		param.StartID = startID

		images, _, err := s.GetImageSrv(ctx, param.ImageFromType).ListImageWithScanInfo(ctx, param)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateSearchImage ListImageWithScanInfo")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID
		data := make([]*model.ExportTaskImage, 0)
		for i := range images {
			data = append(data, &model.ExportTaskImage{
				TaskID:        taskID,
				ImageID:       images[i].ID,
				ImageUniqueID: images[i].UniqueID,
				ImageName:     images[i].GetImageName(),
			})
		}

		if err := s.ExportDal.CreateExportTaskImage(ctx, data); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateSearchImage CreateExportTaskImage")
			return err
		}
	}
	logging.Get().Info().Int64("taskID", taskID).Msg("CreateSearchImage CreateSearchImage finished")
	return nil
}

func (s *ExportTaskSrv) UpdateExportTaskReady(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("no id or no updater")
	}
	updater := map[string]interface{}{"start_at": consts.ExportHtmlReady}
	if err := s.ExportDal.UpdateExportTensorTask(ctx, fmt.Sprintf("id = %d", id), updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("UpdateExportTask")
	}
	return nil
}

func (s *ExportTaskSrv) CreateCiExportData(ctx context.Context, taskID int64, data scanner_ci.PolicyResult) error {

	res := imagesecModel.ImageWithCorrelateData2{
		ImageBaseResponse: imagesecModel.ImageBaseResponse{
			ID:           int64(util.GenerateUUID(data.UUID)),
			FullRepoName: data.Artifact.ImageName,
		},
		Sensitive: make([]*imagesecModel.SensitiveFile, 0),
		Vuln:      make([]*imagesecModel.VulnView, 0),
	}

	if data.Artifact.Artifact.OS != nil {
		res.Image.OS = *data.Artifact.Artifact.OS
		res.ImageBaseResponse.Os = res.GetImageOs()
	}

	ses := make([]*imagesecModel.SensitiveFile, 0)

	if data.MatchSensitiveFiles.Match {
		for i := range data.MatchSensitiveFiles.Files {
			file := data.MatchSensitiveFiles.Files[i]
			ses = append(ses, &imagesecModel.SensitiveFile{Name: file})
		}
		for i := range data.MatchSensitiveFiles.DefaultFiles {
			file := data.MatchSensitiveFiles.DefaultFiles[i]
			ses = append(ses, &imagesecModel.SensitiveFile{Name: file})
		}
	}
	res.Sensitive = ses
	if len(res.Sensitive) > 0 {
		res.ImageBaseResponse.SecurityIssue = append(res.ImageBaseResponse.SecurityIssue,
			imagesecModel.SecurityIssueLabel{Value: model.FlagHasSensitive})
	}

	vulnUnique := make([]uint64, 0)
	for i := range data.Vulnerabilities.Results {
		results := data.Vulnerabilities.Results[i]
		if results.Class != report.ClassOSPkg {
			continue
		}
		for j := range results.Vulnerabilities {
			vu := results.Vulnerabilities[j]
			vulnUnique = append(vulnUnique, util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat,
				vu.VulnerabilityID, vu.PkgName, vu.InstalledVersion)))
		}
	}

	if len(vulnUnique) > 0 {
		vuln, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{UniqueVulns: vulnUnique}, nil)
		if err != nil {
			return err
		}
		res.Vuln = imagesecModel.ConvertVuln(vuln)
		if len(vuln) > 0 {
			res.ImageBaseResponse.SecurityIssue = append(res.ImageBaseResponse.SecurityIssue,
				imagesecModel.SecurityIssueLabel{Value: model.FlagHasVuln})
		}
		for i := range vuln {
			if vuln[i].FixedBy != "" && vuln[i].Class == report.ClassOSPkg {
				res.ImageBaseResponse.ImageAttr.HasFixedVuln = true
				continue
			}
		}
	}

	da := make([]imagesecModel.ImageWithCorrelateData2, 0)
	da = append(da, res)
	bys, err := json.Marshal(da)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateCiExportData,Marshal")
		return err
	}
	prepare := &model.ExportHtmlPrepare{
		TaskID:   taskID,
		DataType: model.ExportHtmlPrepareCicdImageDetail,
		Data:     string(bys),
	}
	if err := s.ExportDal.CreateOrUpdateHTMLPrepare(ctx, prepare); err != nil {
		logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateCiExportData,CreateOrUpdateHTMLPrepare")
		return err
	}
	return nil
}
