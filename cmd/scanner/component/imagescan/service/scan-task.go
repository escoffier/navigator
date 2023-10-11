package service

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanTaskService interface {
	CreateImageScanTask(ctx context.Context, imageSearchParam imagesecModel.ImageSearchApiParam, taskInfo imagesecModel.ImageScanTask) error
	UpdateScanTaskStatus(ctx context.Context, taskID int64, status string) error
	SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanTask, int64, error)
	SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) ([]*imagesecModel.ImageScanSubTask, int64, error)
	RescheduleScanSubtask(ctx context.Context, subtaskID int64) error
	CreateCycleScanTaskByConfig(ctx context.Context) error
	ContinueUpdateTaskAndSubtask(ctx context.Context) error
}

var scanTaskSing *ScanTaskSrv

type ScanTaskSrv struct {
	taskDal           imagesecStore.ScanTaskDal
	preImageDal       imagesecStore.PreImageDal
	preTaskDal        imagesecStore.ScanTaskPreDal
	detectDal         imagesecStore.DetectTaskDal
	imageSrv          types.ImageService
	imageDal          imagesecStore.ImageMetaDal
	userDal           imagesecStore.UserDal
	scanConfigDal     imagesecStore.ScanImageConfigDal
	PreTaskUpdateChan chan *imagesecModel.ImageScanSubTask
}

// 在api 调用时会实例化
func MustGetScanTaskSrv() *ScanTaskSrv {
	for {
		if scanTaskSing == nil {
			time.Sleep(time.Second * 10)
			logging.Get().Info().Str("module", "imagescan").Msg("not get ScanTaskSrv")
		}
		return scanTaskSing
	}
}

func NewScanTaskSrv(
	taskDal imagesecStore.ScanTaskDal,
	preTaskDal imagesecStore.ScanTaskPreDal,
	detectDal imagesecStore.DetectTaskDal,
	imageSrv types.ImageService,
	imageDal imagesecStore.ImageMetaDal,
	scanConfigDal imagesecStore.ScanImageConfigDal,
	preImageDal imagesecStore.PreImageDal,
	userDal imagesecStore.UserDal,
) *ScanTaskSrv {
	// 主要是为了兼容,这后会删除，所以这里直接取，后续方便删除
	if scanTaskSing != nil {
		return scanTaskSing
	}

	s := &ScanTaskSrv{
		taskDal:           taskDal,
		preImageDal:       preImageDal,
		preTaskDal:        preTaskDal,
		detectDal:         detectDal,
		imageSrv:          imageSrv,
		imageDal:          imageDal,
		scanConfigDal:     scanConfigDal,
		userDal:           userDal,
		PreTaskUpdateChan: make(chan *imagesecModel.ImageScanSubTask),
	}

	scanTaskSing = s
	return scanTaskSing
}

func (s *ScanTaskSrv) CreateImageScanTask(ctx context.Context, imageSearchParam imagesecModel.ImageSearchApiParam,
	taskInfo imagesecModel.ImageScanTask) error {

	if err := imageSearchParam.Check(); err != nil {
		return err
	}
	// 加任务时仓库可能已删除
	imageSearchParam.CheckRegDeleted = consts.TrueString
	taskInfo.ImageListParam = imageSearchParam
	imageSearchParam.Filter = model.EmptyFilter().SetLimit(1)

	taskInfo.Status = imagesecModel.TaskStatusNotReady
	taskInfo.StatusStr = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusNotReady)

	_, cnt, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("CreateScanImageTask find image error")
		return scani18.SearchImage(err)
	}
	if cnt == 0 {
		return scani18.NotGetImage()
	}

	if err := s.taskDal.CreateScanTask(ctx, &taskInfo); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("CreateScanTask")
		return scani18.CreateScanTask(err)
	}

	// 加子任务
	go func(taskID int64) {
		_ = s.CreateSubtask(ctx, taskID, imageSearchParam)
	}(taskInfo.ID)
	return nil
}

func (s *ScanTaskSrv) UpdateScanTaskStatus(ctx context.Context, taskID int64, status string) error {
	if taskID <= 0 {
		return scani18.NotGetScanTaskID()
	}
	// 先查
	task, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{TaskID: taskID})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).Msg("UpdateScanTask")
		return scani18.UpdateScanTask(err)
	}
	if len(task) == 0 {
		return scani18.NotGetScanTask()
	}
	if task[0].Status == imagesecModel.TaskStatusNotReady {
		return i18.CreateI18BadReqErr("扫描任务创建中", "task not ready")
	}
	switch status {

	case imagesecModel.TaskStatusPauseStr:
		return s.UpdateTaskPause(ctx, taskID)
	case imagesecModel.TaskStatusTerminateStr:
		return s.UpdateTaskTerminate(ctx, taskID)
	case imagesecModel.TaskStatusPendingStr:
		return s.UpdateTaskPending(ctx, taskID)
	default:
		return i18.CreateI18BadReqErr("扫描任务已完成或已终止，不可更新",
			fmt.Sprintf("task:%d can not updater status:%s", taskID, status))
	}
}

func (s *ScanTaskSrv) SearchScanTask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanTask, int64, error) {
	tasks, cnt, err := s.taskDal.SearchScanTask(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchScanTask")
		return nil, 0, scani18.SearchScanTask(err)
	}
	user := make([]string, 0)
	for i := range tasks {
		group, err := s.taskDal.GroupScanSubtask(ctx, imagesecModel.SearchTaskParam{TaskID: tasks[i].ID})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("TaskID", tasks[i].ID).Msg("GroupScanSubtask")
			return nil, 0, scani18.SearchScanTask(err)
		}

		tasks[i].TaskStatusGroup = group.ToTaskStatusGroupView()
		user = append(user, tasks[i].Creator)
		user = append(user, tasks[i].Updater)
	}

	username, err := s.userDal.GetUsername(ctx, user)
	if err != nil {
		return nil, 0, scani18.SearchScanTask(err)
	}
	for i := range tasks {
		if username[tasks[i].Updater] != "" {
			tasks[i].Updater = username[tasks[i].Updater]
		}
		if username[tasks[i].Creator] != "" {
			tasks[i].Creator = username[tasks[i].Creator]
		}
	}

	return tasks, cnt, nil
}

func (s *ScanTaskSrv) SearchScanSubtask(ctx context.Context, param imagesecModel.SearchTaskParam) (
	[]*imagesecModel.ImageScanSubTask, int64, error) {

	if param.TaskID <= 0 {
		return nil, 0, scani18.NotGetScanTaskID()
	}

	tasks, cnt, err := s.taskDal.SearchScanSubtask(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchScanTask")
		return nil, 0, scani18.SearchScanTask(err)
	}
	uid := make([]uint64, 0)
	for i := range tasks {
		uid = append(uid, tasks[i].ImageUniqueID)
	}
	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uid})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchImage")
		return nil, 0, scani18.SearchScanTask(err)
	}
	for i := range tasks {
		tasks[i].ImageCleared = true
		for j := range image {
			if tasks[i].ImageUniqueID == image[j].UniqueID {
				tasks[i].ImageCleared = false
				break
			}
		}
	}

	return tasks, cnt, nil
}

// 重新调度子任务
func (s *ScanTaskSrv) RescheduleScanSubtask(ctx context.Context, subtaskID int64) error {
	if subtaskID <= 0 {
		return scani18.NotGetScanSubtaskID()
	}
	subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: subtaskID})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("subtaskID", subtaskID).Msg("RescheduleScanSubtask SearchScanTask")
		return scani18.SearchScanSubtask(err)
	}
	if len(subtask) == 0 {
		return scani18.NotGetScanSubtask()
	}

	st := subtask[0]
	tasks, _, err := s.taskDal.SearchScanTask(ctx, imagesecModel.SearchTaskParam{TaskID: st.TaskID})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", st.TaskID).Msg("RescheduleScanSubtask SearchScanTask")
		return scani18.SearchScanTask(err)
	}
	if len(tasks) == 0 {
		return scani18.NotGetScanTask()
	}
	tk := tasks[0]

	subtaskUpdater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusPending,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		"finished_at": 0,
		"started_at":  0,
		"msg":         "",
		"reason":      0,
	}

	taskUpdater := map[string]interface{}{
		"status":      imagesecModel.TaskStatusPending,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
		"finished_at": 0,
	}

	if tk.Status != imagesecModel.TaskStatusInprogress && tk.Status != imagesecModel.TaskStatusSendFinished {
		if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{ID: tk.ID, Updater: taskUpdater,
			Where: fmt.Sprintf("status !=%d", imagesecModel.TaskStatusInprogress)}); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", tk.ID).Msg("RescheduleScanSubtask UpdateScanTask")
			return scani18.UpdateScanTask(err)
		}
	}

	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{ID: subtaskID, Updater: subtaskUpdater,
		Where: fmt.Sprintf("status !=%d", imagesecModel.TaskStatusPending),
	}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("subtaskID", st.ID).Msg("RescheduleScanSubtask UpdateScanTask")
		return scani18.UpdateScanSubtask(err)
	}
	return nil

}

// 新建子任务
func (s *ScanTaskSrv) CreateSubtask(ctx context.Context, taskID int64, imageSearchParam imagesecModel.ImageSearchApiParam) error {

	var startID int64
	imageSearchParam.Filter = model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()
	imageSearchParam.AssociateParam = imagesecModel.ImageAssociateParam{
		RegistryEnable:     true,
		ScanInstanceEnable: true,
		NodeInfoEnable:     true,
	}

	for {
		imageSearchParam.StartID = startID
		subtasks := make([]*imagesecModel.ImageScanSubTask, 0)

		images, _, err := s.imageSrv.ListImageWithScanInfo(ctx, imageSearchParam)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("CreateScanImageTask find image")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID

		for i := range images {
			ima := images[i]
			sub := &imagesecModel.ImageScanSubTask{
				TaskID:        taskID,
				ClusterKey:    ima.ClusterKey,
				ImageUniqueID: ima.UniqueID,
				NodeUniqueID:  ima.NodeUniqueID,
				Status:        imagesecModel.TaskStatusPending,
				StatusStr:     imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusPending),
				ImageName:     ima.GetImageName(),
				Hostname:      ima.NodeHostname,
				ScanInsVer:    ima.ScanInsVer,
			}
			if ima.ImageFromType == imagesecModel.ImageFromRegistry {
				sub.NodeUniqueID = uint64(ima.ScanInstanceID)
				sub.Hostname = ima.RegNameView()
				sub.ImageName = fmt.Sprintf("%s:%s", ima.FullRepoName, ima.Tag)
			}

			subtasks = append(subtasks, sub)
		}

		if err := s.taskDal.CreateScanSubtask(ctx, subtasks); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("CreateScanSubtask")
			continue
		}
		// 2.20版本兼容老版本，如果都升级后，就直接删除这里
		_ = s.AdaptCreateSubtask(ctx, images, subtasks)

	}
	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusPending,
		"status_str": imagesecModel.TaskStatusPendingStr,
	}

	if err := s.taskDal.UpdateScanTask(ctx, imagesecModel.UpdateTaskParam{
		ID:      taskID,
		Updater: updater,
	}); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("taskID", taskID).
			Msg("UpdateScanTask TaskStatusPendingStr")
		return err
	}

	return nil
}
