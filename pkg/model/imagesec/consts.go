package imagesec

import (
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageFromType string

func (vi ImageFromType) String() string {
	return string(vi)
}

const (
	ImageFromCI       string = "ci"
	ImageFromNode     string = "node"
	ImageFromRegistry string = "registry"
)

const (
	DetectScopeTypeCluster = "cluster"
	DetectScopeTypeImage   = "image"
)

// ci暂时不整合
func CheckImageFromType(imageFromType string) error {
	switch imageFromType {
	case ImageFromRegistry, ImageFromNode, ImageFromCI:
		return nil
	}
	return fmt.Errorf("incorrect image type:%s", imageFromType)

}

func (vi ImageFromType) Check() error {
	switch vi.String() {
	case ImageFromRegistry, ImageFromNode, ImageFromCI:
		return nil
	}
	return fmt.Errorf("incorrect image type:%s", vi)
}

const (
	UniqueVulnFormat      = "%s-%d"
	UniqueMalwareFormat   = "%s-%s"
	UniqueSensitiveFormat = "%s-%s-%s"
	UniqueLicenseFormat   = "%s-%s-%s"
	UniquePkgFormat       = "%s-%s-%s-%s"
	UniqueEnvFormat       = "%d-%s-%s-%s"
	UniqueWebshellFormat  = "%s-%s"
	UniqueLibImageFormat  = "%d-%s-%s-%s-%s"    // RegID+Repo+Tag+Digest
	UniqueNodeImageFormat = "%d-%s-%s-%s-%s-%s" // NodeID+Repo+Tag+Digest+ImageID
)

const (
	SeverityCriticalInt  = 5
	SeverityHighInt      = 4
	SeverityMediumInt    = 3
	SeverityLowInt       = 2
	SeverityUnknownInt   = 1
	SeverityCritical     = "CRITICAL"
	SeverityHigh         = "HIGH"
	SeverityMedium       = "MEDIUM"
	SeverityLow          = "LOW"
	SeverityUnknown      = "UNKNOWN"
	SeverityCriticalView = "严重"
	SeverityHighView     = "高"
	SeverityMediumView   = "中"
	SeverityLowView      = "低"
	SeverityUnknownView  = "未知"
)

const (
	VulnFlagKernelPkg    = iota // 内核软件包
	VulnFlagClassOSPkg          // 系统包(trivy扫描的)
	VulnFlagClassLangPkg        // 应用包
	VulnFlagClassConfig         // 配置文件
	VulnFlagHasFixed            // 可修复
	VulnFlagAppPkg              // 应用软件包，节点镜像时新增，所以没有按顺序
	VulnFlagNoFixed             // 不可修复

	// 攻击位置难易
	CVSSFlagAVN     // 网络访问
	CVSSFlagAVL     // 本地访问
	CVSSFlagAVP     // 物理访问
	CVSSFlagAVEmpty // 相邻网络访问
	CVSSFlagAVA     // 相邻网络访问

	// 是否自动化触发
	CVSSFlagUIN // 自动
	CVSSFlagUIR // 非自动

	// 所需权限级别 and 攻击复杂度
	CVSSFlagACN // 无
	CVSSFlagACL // 低
	CVSSFlagACH // 高

	// 信息泄露风险
	CVSSFlagCN // 无
	CVSSFlagCL // 低
	CVSSFlagCH // 高

	// 信息/系统篡改风险
	CVSSFlagAN // 无
	CVSSFlagAL // 低
	CVSSFlagAH // 高

	// 权限范围扩大
	CVSSFlagSC // 不变
	CVSSFlagSU // 扩大

	// 造成 DoS 风险
	CVSSFlagPRN // 无
	CVSSFlagPRL // 低
	CVSSFlagPRH // 高

	OnlineVuln = 28 // 在线镜像的漏洞
)

const (
	CVSSNvd              = "nvd"
	VulnClassOSVuln      = "系统漏洞"
	VulnsClassPkgVuln    = "应用漏洞"
	VulnsClassConfigVuln = "配置文件漏洞"
)

const (
	CycleTypeDay     = "day"
	CycleTypeMonth   = "month"
	CycleTypeWeekday = "weekday"
)
const (
	BootRootUser = "root"
)

const (
	DetectPriorityScan         = 100
	DetectPriorityPolicyChange = 99
	DetectPriorityCycle        = 98
)

const (
	TaskStatusNotReady            = iota + 1 // 子任务准备完成
	TaskStatusPending                        // 等到中:子任务已全部添加完成
	TaskStatusInprogress                     // 执行中,对于任务:开始调度起，对于子任务来说:发rpc成功后
	TaskStatusSendFinished                   // 扫描子任务发送到节点
	TaskStatusScanFinished                   // 扫描完成但是检测未已完成
	TaskStatusPause                          // 暂停
	TaskStatusTerminate                      // 终止
	TaskStatusFailed                         // 失败
	TaskStatusDetectFinished                 // 扫描完成，检测也完成
	TaskStatusPauseAllSubtask                // 任务暂停后，暂停完所有的子任务
	TaskStatusTerminateAllSubtask            // 任务终止后，终止完所有的子任务
)

const (
	TaskStatusNotReadyStr       = "notReady"     // 没有准备好
	TaskStatusPendingStr        = "pending"      // 等到中
	TaskStatusInprogressStr     = "inprogress"   // 执行中
	TaskStatusPauseStr          = "pause"        // 暂停
	TaskStatusScanFinishedStr   = "scanFinished" // 扫描完成但是检测未已完成
	TaskStatusTerminateStr      = "terminate"    // 终止
	TaskStatusFailedStr         = "failed"       // 失败
	TaskStatusSendFinishedStr   = "sendFinished" //  发送完成
	TaskStatusDetectFinishedStr = "finished"     //  扫描完成，检测也完成
)

var scanStatusToStrMap map[int64]string
var scanStatusStrToIntMap map[string]int64

func ScanStatusToStr(st int64) string {
	if scanStatusToStrMap == nil {
		scanStatusToStrMap = map[int64]string{
			TaskStatusNotReady:       TaskStatusNotReadyStr,
			TaskStatusPending:        TaskStatusPendingStr,
			TaskStatusInprogress:     TaskStatusInprogressStr,
			TaskStatusSendFinished:   TaskStatusSendFinishedStr,
			TaskStatusPause:          TaskStatusPauseStr,
			TaskStatusScanFinished:   TaskStatusScanFinishedStr,
			TaskStatusDetectFinished: TaskStatusDetectFinishedStr,
			TaskStatusTerminate:      TaskStatusTerminateStr,
			TaskStatusFailed:         TaskStatusFailedStr,
		}
	}
	return scanStatusToStrMap[st]
}

func ScanStatusStrToInt(st string) int64 {

	if scanStatusStrToIntMap == nil {
		scanStatusStrToIntMap = map[string]int64{
			TaskStatusNotReadyStr:       TaskStatusNotReady,
			TaskStatusPendingStr:        TaskStatusPending,
			TaskStatusInprogressStr:     TaskStatusInprogress,
			TaskStatusPauseStr:          TaskStatusPause,
			TaskStatusScanFinishedStr:   TaskStatusScanFinished,
			TaskStatusTerminateStr:      TaskStatusTerminate,
			TaskStatusFailedStr:         TaskStatusFailed,
			TaskStatusSendFinishedStr:   TaskStatusSendFinished,
			TaskStatusDetectFinishedStr: TaskStatusDetectFinished,
		}
	}
	return scanStatusStrToIntMap[st]
}

const (
	TaskFailedReasonTimeout         = "timeout"        // 超时
	TaskFailedReasonSaveData        = "saveData"       // 保存数据出错
	TaskFailedReasonScanner         = "scanFailed"     // 扫描出器
	TaskFailedReasonSendNode        = "sendToNode"     // 未发送到扫描节点
	TaskFailedReasonNotFindImage    = "notFindImage"   // 未找到对应的镜像
	TaskFailedReasonNotFindNodeInfo = "notFindNode"    // 未找到对应的节点
	TaskFailedTerminated            = "taskTerminated" // 任务已被终止
)

var taskReasonEN map[string]string
var taskReasonZH map[string]string

func GetTaskReason(reason, lang string) string {
	if taskReasonZH == nil {
		taskReasonZH = map[string]string{
			TaskFailedReasonTimeout:         "超时",
			TaskFailedReasonSaveData:        "保存数据出错",
			TaskFailedReasonScanner:         "扫描出器",
			TaskFailedReasonSendNode:        "未发送到扫描节点",
			TaskFailedReasonNotFindImage:    "未找到对应镜像",
			TaskFailedReasonNotFindNodeInfo: "未找到对应节点",
			TaskFailedTerminated:            "任务被终止",
		}
	}

	if taskReasonEN == nil {
		taskReasonEN = map[string]string{
			TaskFailedReasonTimeout:         "time out",
			TaskFailedReasonSaveData:        "can not save scan data",
			TaskFailedReasonScanner:         "scan fail",
			TaskFailedReasonSendNode:        "can send scan task to node",
			TaskFailedReasonNotFindImage:    "can not find image",
			TaskFailedReasonNotFindNodeInfo: "can not find node",
			TaskFailedTerminated:            "task terminated",
		}
	}
	if lang == model.LangEn {
		return taskReasonEN[reason]
	}
	return taskReasonZH[reason]
}

// 镜像在节点已删除，保存数据失败，scanner 内部出错，节点到主集群网络不通，节点扫描器出错，扫描超时

const (
	ScanTaskOperatorCi     = "CI触发扫描"
	ScanTaskOperatorCycle  = "周期触发扫描"
	ScanTaskOperatorSync   = "镜像同步触发扫描"
	ScanTaskSensitiveFlush = "敏感文件规则更新触发扫描"

	ScanCycleCheckInternal = time.Minute * 5
)

// task trigger type
const (
	VulnDbUpdateTrigger      = "vulnDbUpdate"      // 漏洞库更新触发扫描
	MalwareDataUpdateTrigger = "malwareDataUpdate" // 病毒库更新触发扫描
	SensitiveUpdateTrigger   = "sensitiveUpdate"   // 敏感文件规则更新触发扫描
	CycleTrigger             = "cycle"             // 周期性扫描任务
	ImageSyncTrigger         = "imageSync"         // 镜像同步触发扫描
	ManualTrigger            = "manual"            // 手动扫描任务
)

const (
	SensitiveRuleTypeFilename = "filename"
)

const (
	ConfigTypeNodeScanImage = "nodeImage"
)

const (
	DeletePolicyAndDeletedDetectResult = 1
)

const (
	WebshellRiskLevelCertain = "certainly"
	WebshellRiskLevelMaybe   = "maybe"
	HMWebshellSalt           = "ssdeep"
)

const (
	CicdOperatorZH         = "CICD触发扫描"
	CycleTriggerOperatorZH = "周期触发扫描"
	SyncTriggerOperatorZH  = "镜像同步触发扫描"
	VulnDbUpdateTriggerZH  = "漏洞库更新触发扫描"

	CicdOperatorEN         = "cicd"
	CycleTriggerOperatorEN = "sync image"
	SyncTriggerOperatorEN  = "cycle"
	VulnDbUpdateTriggerEN  = "vuln db update"
)

func GetScanTaskCreator(cr, lang string) string {
	zh := map[string]string{
		VulnDbUpdateTrigger: VulnDbUpdateTriggerZH,
		CycleTrigger:        CycleTriggerOperatorZH,
		ImageSyncTrigger:    SyncTriggerOperatorZH,
	}
	en := map[string]string{
		VulnDbUpdateTrigger: VulnDbUpdateTriggerEN,
		CycleTrigger:        CycleTriggerOperatorEN,
		ImageSyncTrigger:    SyncTriggerOperatorEN,
	}

	if lang == model.LangZh {
		if zh[cr] != "" {
			return zh[cr]
		}
		return cr
	}

	if lang == model.LangEn {
		if en[cr] != "" {
			return en[cr]
		}
		return cr
	}
	return cr
}
