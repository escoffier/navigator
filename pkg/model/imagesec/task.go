package imagesec

import (
	"encoding/json"
	"fmt"
)

type ImageDetectTask struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	ImageFromType string `gorm:"column:image_from_type" json:"imageFromType"` // 用做列表筛选
	Priority      int64  `gorm:"column:priority" json:"priority"`             // 优先级
	ScanSubTaskID int64  `gorm:"scan_sub_task_id" json:"scanSubTaskID"`
	Status        int64  `gorm:"column:status" json:"status"`
	StatusStr     string `gorm:"column:status_str" json:"statusStr"` // 任务状态
	StartedAt     int64  `json:"startedAt" gorm:"column:started_at"`
	FinishedAt    int64  `json:"finishedAt" gorm:"column:finished_at"`
	Updater       string `gorm:"column:updater" json:"updater"` // 最近一次更新人
	Creator       string `gorm:"column:creator" json:"creator"` // 创建人

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageDetectTask) Check() error {
	return nil
}

func (vi *ImageDetectTask) Serialize() {
	vi.StatusStr = ScanStatusToStr(vi.Status)
}

func (vi *ImageDetectTask) TableName() string {
	return "ivan_image_detect_task"
}

type ImageDetectSubTask struct {
	ID            int64   `gorm:"primaryKey" json:"id"`
	TaskID        int64   `gorm:"column:task_id" json:"taskID"`
	ImageUniqueID uint64  `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	PolicyIds     []int64 `gorm:"-" json:"policyIds"`
	PolicyIdsJson string  `gorm:"column:policy_ids" json:"-"`
	Status        int64   `gorm:"column:status" json:"status"`        // 任务状态
	StatusStr     string  `gorm:"column:status_str" json:"statusStr"` // 任务状态
	StartedAt     int64   `gorm:"column:started_at" json:"startedAt"`
	FinishedAt    int64   `gorm:"column:finished_at" json:"finishedAt"`
	Msg           string  `gorm:"column:msg" json:"msg"`
	CreatedAt     int64   `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64   `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageDetectSubTask) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	if vi.TaskID <= 0 {
		return fmt.Errorf("not get TaskID")
	}

	if len(vi.PolicyIds) <= 0 {
		return fmt.Errorf("not get PolicyID")
	}
	return nil
}

func (vi *ImageDetectSubTask) Serialize() {
	vi.StatusStr = ScanStatusToStr(vi.Status)
	if len(vi.PolicyIds) > 0 {
		if bys, err := json.Marshal(vi.PolicyIds); err == nil {
			vi.PolicyIdsJson = string(bys)
		}
	}
}

func (vi *ImageDetectSubTask) Deserialize() {
	vi.PolicyIds = make([]int64, 0)
	if len(vi.PolicyIdsJson) > 0 {
		ans := make([]int64, 0)
		if err := json.Unmarshal([]byte(vi.PolicyIdsJson), &ans); err == nil {
			vi.PolicyIds = ans
		}
	}
}

func (vi *ImageDetectSubTask) TableName() string {
	return "ivan_image_detect_subtask"
}

type ImageScanTask struct {
	ID                 int64          `gorm:"primaryKey" json:"id"`
	ImageFromType      string         `gorm:"column:image_from_type" json:"imageFromType"` // 用做列表筛选
	Priority           int64          `gorm:"column:priority" json:"priority"`             // 优先级
	ScanType           string         `gorm:"column:scan_type" json:"scanType"`
	Status             int64          `gorm:"column:status" json:"status"`        // 任务状态
	StatusStr          string         `gorm:"column:status_str" json:"statusStr"` // 任务状态
	Updater            string         `gorm:"column:updater" json:"updater"`      // 最近一次更新人
	Creator            string         `gorm:"column:creator" json:"creator"`      // 创建人
	StartedAt          int64          `gorm:"column:started_at" json:"startedAt"`
	FinishedAt         int64          `gorm:"column:finished_at" json:"finishedAt"`
	ImageListParamJson string         `gorm:"column:image_list_param" json:"-"`
	ImageListParam     ImageListParam `gorm:"-" json:"imageListParam"`
	CreatedAt          int64          `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt          int64          `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

	TaskStatusGroup TaskStatusGroupView `gorm:"-" json:"taskStatusGroup"`
}

type TaskStatusGroupView struct {
	All        int64 `json:"all"`
	Pending    int64 `json:"pending"`
	Inprogress int64 `json:"inprogress"`
	Finished   int64 `json:"finished"`
	Pause      int64 `json:"pause"`
	Terminate  int64 `json:"terminate"`
	Failed     int64 `json:"failed"`
}

type TaskStatusGroup struct {
	All            int64 `json:"all"`
	NotReady       int64 `json:"notReady"`
	SendFinished   int64 `json:"sendFinished"`
	Pending        int64 `json:"pending"`
	Inprogress     int64 `json:"inprogress"`
	Pause          int64 `json:"pause"`
	Terminate      int64 `json:"terminate"`
	Failed         int64 `json:"failed"`
	ScanFinished   int64 `json:"scanFinished"`
	DetectFinished int64 `json:"detectFinished"`
}

func (vi *TaskStatusGroup) ToTaskStatusGroupView() TaskStatusGroupView {
	ans := TaskStatusGroupView{
		All:        vi.All,
		Pending:    vi.Pending + vi.NotReady,
		Inprogress: vi.Inprogress + vi.SendFinished + vi.ScanFinished,
		Finished:   vi.DetectFinished,
		Pause:      vi.Pause,
		Terminate:  vi.Terminate,
		Failed:     vi.Failed,
	}
	return ans
}

func (vi *ImageScanTask) TableName() string {
	return "ivan_image_scan_task"
}

func (vi *ImageScanTask) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if err := ImageFromType(vi.ImageFromType).Check(); err != nil {
		return err
	}

	if vi.ScanType == "" {
		return fmt.Errorf("not get ScanType")
	}
	if vi.Creator == "" || vi.Updater == "" {
		return fmt.Errorf("not get Creator or Updater")
	}
	if vi.Updater == "" {
		vi.Updater = vi.Creator
	}

	return nil
}

func (vi *ImageScanTask) Deserialize() {
	if vi.ImageListParamJson != "" {
		is := ImageListParam{}
		if err := json.Unmarshal([]byte(vi.ImageListParamJson), &is); err == nil {
			vi.ImageListParam = is
		}
	}
}

func (vi *ImageScanTask) ToApiView() {
	if vi.Status == TaskStatusNotReady {
		vi.StatusStr = TaskStatusPendingStr
	}
	if vi.Status == TaskStatusSendFinished || vi.Status == TaskStatusScanFinished {
		vi.StatusStr = TaskStatusInprogressStr
	}
}

func (vi *ImageScanTask) ChangeCreator(lan string) {
	vi.Creator = GetScanTaskCreator(vi.Creator, lan)
	vi.Updater = GetScanTaskCreator(vi.Updater, lan)
}

func (vi *ImageScanTask) Serialize() {
	if bys, err := json.Marshal(vi.ImageListParam); err == nil {
		vi.ImageListParamJson = string(bys)
	}
}

type ImageScanSubTask struct {
	ID             int64  `gorm:"primaryKey" json:"id"`
	TaskID         int64  `gorm:"column:task_id" json:"taskID"`
	NodeClusterKey string `gorm:"column:node_cluster_key" json:"nodeClusterKey"`
	ImageUniqueID  uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	NodeUniqueID   uint64 `gorm:"column:node_unique_id" json:"nodeUniqueID,string"`
	Status         int64  `gorm:"column:status" json:"status"`        // 任务状态
	StatusStr      string `gorm:"column:status_str" json:"statusStr"` // 任务状态
	StartedAt      int64  `gorm:"column:started_at" json:"startedAt"`
	FinishedAt     int64  `gorm:"column:finished_at" json:"finishedAt"`
	Msg            string `gorm:"column:msg" json:"msg"`
	Reason         string `gorm:"column:reason" json:"reason"`
	ImageName      string `gorm:"column:image_name" json:"imageName"`
	NodeHostname   string `gorm:"column:node_host_name" json:"nodeHostname"`

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageScanSubTask) TableName() string {
	return "ivan_image_scan_subtask"
}

func (vi *ImageScanSubTask) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}

	if vi.TaskID <= 0 {
		return fmt.Errorf("not get TaskID")
	}

	return nil
}

func (vi *ImageScanSubTask) Serialize() {

}

func (vi *ImageScanSubTask) Deserialize() {

}

func (vi *ImageScanSubTask) ToApiView() {
	if vi.Status == TaskStatusNotReady || vi.Status == TaskStatusPause {
		vi.StatusStr = TaskStatusPendingStr
	}
	if vi.Status == TaskStatusSendFinished || vi.Status == TaskStatusScanFinished {
		vi.StatusStr = TaskStatusInprogressStr
	}
	if vi.Status == TaskStatusTerminate {
		vi.StatusStr = TaskStatusFailedStr
	}
	if vi.StatusStr == TaskStatusPendingStr {
		vi.StartedAt = 0
		vi.FinishedAt = 0
	}
	if vi.StatusStr == TaskStatusInprogressStr {
		vi.FinishedAt = 0
	}
}
