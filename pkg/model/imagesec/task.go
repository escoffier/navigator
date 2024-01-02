package imagesec

import (
	"encoding/json"
	"fmt"
)

type ImageDetectTask struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	Priority      int64  `gorm:"column:priority" json:"priority"` // 优先级
	ScanSubTaskID int64  `gorm:"column:scan_sub_task_id" json:"scanSubTaskID"`
	Status        int64  `gorm:"column:status" json:"status"`
	StatusStr     string `gorm:"column:status_str" json:"statusStr"` // 任务状态
	StartedAt     int64  `gorm:"column:started_at" json:"startedAt"`
	FinishedAt    int64  `gorm:"column:finished_at" json:"finishedAt"`
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
	ID            int64  `gorm:"primaryKey" json:"id"`
	TaskID        int64  `gorm:"column:task_id" json:"taskID"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	PolicyID      int64  `gorm:"column:policy_id" json:"policyID"`
	// PolicyIds     []int64 `gorm:"-" json:"policyIds"`
	// PolicyIdsJson string  `gorm:"column:policy_ids" json:"-"`
	Status     int64  `gorm:"column:status" json:"status"`        // 任务状态
	StatusStr  string `gorm:"column:status_str" json:"statusStr"` // 任务状态
	StartedAt  int64  `gorm:"column:started_at" json:"startedAt"`
	FinishedAt int64  `gorm:"column:finished_at" json:"finishedAt"`
	Msg        string `gorm:"column:msg" json:"msg"`
	CreatedAt  int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt  int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
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
	if vi.PolicyID <= 0 {
		return fmt.Errorf("not get policyID")
	}
	// if len(vi.PolicyIds) <= 0 {
	// 	return fmt.Errorf("not get PolicyID")
	// }
	return nil
}

func (vi *ImageDetectSubTask) Serialize() {
	vi.StatusStr = ScanStatusToStr(vi.Status)
	// if len(vi.PolicyIds) > 0 {
	// 	if bys, err := json.Marshal(vi.PolicyIds); err == nil {
	// 		vi.PolicyIdsJson = string(bys)
	// 	}
	// }
}

func (vi *ImageDetectSubTask) Deserialize() {
	// vi.PolicyIds = make([]int64, 0)
	// if len(vi.PolicyIdsJson) > 0 {
	// 	ans := make([]int64, 0)
	// 	if err := json.Unmarshal([]byte(vi.PolicyIdsJson), &ans); err == nil {
	// 		vi.PolicyIds = ans
	// 	}
	// }
}

func (vi *ImageDetectSubTask) TableName() string {
	return "ivan_image_detect_subtask"
}

type ImageScanTask struct {
	ID                 int64               `gorm:"primaryKey" json:"id"`
	ImageFromType      string              `gorm:"column:image_from_type" json:"imageFromType"` // 用做列表筛选
	Priority           int64               `gorm:"column:priority" json:"priority"`             // 优先级
	ScanType           string              `gorm:"column:scan_type" json:"scanType"`
	Status             int64               `gorm:"column:status" json:"status"`        // 任务状态
	StatusStr          string              `gorm:"column:status_str" json:"statusStr"` // 任务状态
	Updater            string              `gorm:"column:updater" json:"updater"`      // 最近一次更新人
	Creator            string              `gorm:"column:creator" json:"creator"`      // 创建人
	StartedAt          int64               `gorm:"column:started_at" json:"startedAt"`
	FinishedAt         int64               `gorm:"column:finished_at" json:"finishedAt"`
	ImageListParamJson string              `gorm:"column:image_list_param" json:"-"`
	ImageListParam     ImageSearchApiParam `gorm:"-" json:"imageListParam"`
	CreatedAt          int64               `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt          int64               `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds

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
	if vi.Updater == "" {
		vi.Updater = vi.Creator
	}
	if vi.ScanType == ManualTrigger && (vi.Creator == "" && vi.Updater == "") {
		return fmt.Errorf("not get Creator or Updater")
	}
	return nil
}

func (vi *ImageScanTask) Deserialize() {
	if vi.ImageListParamJson != "" {
		is := ImageSearchApiParam{}
		if err := json.Unmarshal([]byte(vi.ImageListParamJson), &is); err == nil {
			vi.ImageListParam = is
		}
	}
}

func (vi *ImageScanTask) ToApiView() {
	if vi.StatusStr == TaskStatusSendFinishedStr || vi.StatusStr == TaskStatusScanFinishedStr {
		vi.StatusStr = TaskStatusInprogressStr
	}
	vi.ChangeTaskCreator()
}

// 新需求:空
func (vi *ImageScanTask) ChangeTaskCreator() {
	zh := map[string]string{
		MalwareDataUpdateTrigger: "",
		SensitiveUpdateTrigger:   "",
		VulnDbUpdateTrigger:      "",
		CycleTrigger:             "",
		ImageSyncTrigger:         "",
	}
	if _, ok := zh[vi.ScanType]; ok {
		vi.Updater = ""
		vi.Creator = ""
	}
}

func (vi *ImageScanTask) Serialize() {
	if bys, err := json.Marshal(vi.ImageListParam); err == nil {
		vi.ImageListParamJson = string(bys)
	}
}

type ImageScanSubTask struct {
	ID            int64  `gorm:"primaryKey" json:"id"`
	TaskID        int64  `gorm:"column:task_id" json:"taskID"`
	ImageUniqueID uint64 `gorm:"column:image_unique_id" json:"imageUniqueID,string"`
	// 对于结点镜像来说，表示节点UniqueID,对于仓库镜像来说表示 subScannerInstanceID
	NodeUniqueID uint64 `gorm:"column:node_unique_id" json:"nodeUniqueID,string"` // 调度的时候使用
	Status       int64  `gorm:"column:status" json:"status"`                      // 任务状态
	StatusStr    string `gorm:"column:status_str" json:"statusStr"`               // 任务状态
	StartedAt    int64  `gorm:"column:started_at" json:"startedAt"`
	FinishedAt   int64  `gorm:"column:finished_at" json:"finishedAt"` // 扫描完成也要更新这个值，因为要加检测任务
	Msg          string `gorm:"column:msg" json:"msg"`
	Reason       string `gorm:"column:reason" json:"reason"`
	ImageName    string `gorm:"column:image_name" json:"imageName"`    // 冗余信息，前端展示
	Hostname     string `gorm:"column:hostname" json:"hostname"`       // 冗余信息，前端展示,节点镜像：节点名，仓库镜像：仓库名
	ScanInsVer   string `gorm:"column:scan_ins_ver" json:"scanInsVer"` // 扫描器版本，为了兼容老版本,对于老版本的扫描器，要使用原来2.20之前的扫描逻辑

	// 扫描器的 uuid，扫描重启动后会变动，通过该字段来判断是否需要重新发送
	ScanUUID     string `gorm:"column:scan_uuid" json:"scanUUID"`
	ImageCleared bool   `gorm:"-" json:"imageCleared"` // 镜像是否被清理了

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ImageScanSubTask) TableName() string {
	return "ivan_image_scan_subtask"
}

func (vi *ImageScanSubTask) LogInfo() string {
	ss := fmt.Sprintf("subtask:%d-%d-%s", vi.TaskID, vi.ID, vi.ImageName)
	return ss
}

func (vi *ImageScanSubTask) Check() error {
	if vi == nil {
		return fmt.Errorf("not get model")
	}
	if vi.ImageUniqueID <= 0 {
		return fmt.Errorf("not get ImageUniqueID")
	}
	if vi.NodeUniqueID <= 0 {
		return fmt.Errorf("not get NodeUniqueID")
	}

	if vi.TaskID <= 0 {
		return fmt.Errorf("not get TaskID")
	}

	return nil
}

func (vi *ImageScanSubTask) Serialize() {

}

func (vi *ImageScanSubTask) Deserialize() {

	// 任务发送到节点或扫描器才能算任务已开始，所以就会有部分情况导致任务失败，但是没有开始时间
	// 比如：任务未发送到节点，任务对应的镜像已清理等
	// 这里取个巧，认为任务是在5秒前开始的，这样页面上计算扫描用时就不会有错
	if vi.FinishedAt > 0 && vi.StartedAt == 0 {
		vi.StartedAt = vi.FinishedAt - 5*1000
	}
}

func (vi *ImageScanSubTask) ToApiView() {
	if vi.StatusStr == TaskStatusNotReadyStr || vi.StatusStr == TaskStatusPauseStr {
		vi.StatusStr = TaskStatusPendingStr
	}
	if vi.StatusStr == TaskStatusSendFinishedStr || vi.StatusStr == TaskStatusScanFinishedStr {
		vi.StatusStr = TaskStatusInprogressStr
	}
	if vi.StatusStr == TaskStatusTerminateStr {
		vi.StatusStr = TaskStatusFailedStr
	}
	if vi.StatusStr == TaskStatusPendingStr {
		vi.StartedAt = 0
		vi.FinishedAt = 0
	}
	if vi.StatusStr != TaskStatusDetectFinishedStr {
		vi.FinishedAt = 0
	}
}

const (
	// task trigger type
	VulnDbUpdateTrigger      = "vulnDbUpdate"      // 漏洞库更新触发扫描
	MalwareDataUpdateTrigger = "malwareDataUpdate" // 病毒库更新触发扫描
	SensitiveUpdateTrigger   = "sensitiveUpdate"   // 敏感文件规则更新触发扫描
	CycleTrigger             = "cycle"             // 周期性扫描任务
	ImageSyncTrigger         = "imageSync"         // 镜像同步触发扫描
	ManualTrigger            = "manual"            // 手动扫描任务

	CicdOperatorZH             = "CICD触发扫描"
	CycleTriggerOperatorZH     = "周期触发扫描"
	SyncTriggerOperatorZH      = "镜像同步触发扫描"
	VulnDbUpdateTriggerZH      = "漏洞库更新触发扫描"
	MalwareDataUpdateTriggerZH = "病毒库更新触发扫描"
	SensitiveUpdateTriggerZH   = "敏感文件规则更新触发扫描"
	ManualTriggerZH            = "手动扫描"

	CycleTriggerOperatorEN     = "sync image"
	SyncTriggerOperatorEN      = "cycle"
	VulnDbUpdateTriggerEN      = "vuln db update"
	MalwareDataUpdateTriggerEN = "malware db update"
	SensitiveUpdateTriggerEN   = "sensitive file rule update"
	ManualTriggerEN            = "Manual scanning"
)

func GetTaskTypeView(lang string) map[string]string {
	avCH := map[string]string{
		VulnDbUpdateTrigger:      VulnDbUpdateTriggerZH,
		MalwareDataUpdateTrigger: MalwareDataUpdateTriggerZH,
		SensitiveUpdateTrigger:   SensitiveUpdateTriggerZH,
		CycleTrigger:             CycleTriggerOperatorZH,
		ImageSyncTrigger:         SyncTriggerOperatorZH,
		ManualTrigger:            ManualTriggerZH,
	}

	avEn := map[string]string{
		VulnDbUpdateTrigger:      VulnDbUpdateTriggerEN,
		MalwareDataUpdateTrigger: MalwareDataUpdateTriggerEN,
		SensitiveUpdateTrigger:   SensitiveUpdateTriggerEN,
		CycleTrigger:             CycleTriggerOperatorEN,
		ImageSyncTrigger:         SyncTriggerOperatorEN,
		ManualTrigger:            ManualTriggerEN,
	}
	if lang == LangEn {
		return avEn
	}

	return avCH
}
