package imagesec

import (
	"fmt"
	"time"
)

type ImageFromType string

func (vi ImageFromType) String() string {
	return string(vi)
}

const (
	ImageFromCI       string = "ci"
	ImageFromNode     string = "node"
	ImageFromRegistry string = "registry"
	ImageFromDeploy   string = "deploy"
)

const (
	DetectScopeTypeCluster = "cluster"
	DetectScopeTypeReg     = "registry"
	DetectScopeTypeImage   = "image"
)
const (
	DBTypeVulnTrivy = "trivyVuln"
)

func (vi ImageFromType) Check() error {
	switch vi.String() {
	case ImageFromRegistry, ImageFromNode, ImageFromCI, ImageFromDeploy:
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
	UniqueLibImageFormat  = "%d-%s-%s-%s"    // RegID+Image+Digest+ImageFromType
	UniqueNodeImageFormat = "%d-%s-%s-%s-%s" // NodeID+Image+Digest+ImageID+ImageFromType
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
	VulnFlagKernel       = iota // 内核软件包
	VulnFlagClassOSPkg          // 系统包(trivy扫描的)
	VulnFlagClassLangPkg        // 应用包
	VulnFlagClassConfig         // 配置文件
	VulnFlagHasFixed            // 可修复
	VulnFlagNotKernel           // 应用软件包，节点镜像时新增，所以没有按顺序
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

	VulnFlagOnlineImage = 28 // 在线镜像的漏洞
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
	DetectPriorityScan          = 100
	DetectAddImage              = 99
	DetectPriorityPolicyCreate  = 98
	DetectPriorityPolicyUpdate  = 97
	DetectPriorityPolicyDelete  = 96
	DetectPriorityDefaultPolicy = 95
	DetectUpdateNodeImageInReg  = 94
	DetectPriorityCycle         = 93
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
	TaskStatusPendingStr        = "pending"      // 等待中
	TaskStatusInprogressStr     = "inprogress"   // 执行中
	TaskStatusPauseStr          = "pause"        // 暂停
	TaskStatusScanFinishedStr   = "scanFinished" // 扫描完成但是检测未已完成
	TaskStatusTerminateStr      = "terminate"    // 终止
	TaskStatusFailedStr         = "failed"       // 失败
	TaskStatusSendFinishedStr   = "sendFinished" //  发送完成
	TaskStatusDetectFinishedStr = "finished"     //  扫描完成，检测也完成

	TaskStatusImageSyncFinishedStr = "finished" //  镜像同步完成
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
	TaskFailedReasonTimeout         = "timeout"             // 超时
	TaskFailedReasonSaveData        = "saveData"            // 保存数据出错
	TaskFailedReasonScanner         = "scanFailed"          // 扫描出器
	TaskFailedReasonSendNode        = "notSendToNode"       // 未发送到扫描节点
	TaskFailedReasonSendScanner     = "notSendToScanner"    // 未发送到扫描的scanner
	TaskFailedReasonNotFindImage    = "notFindImage"        // 未找到对应的镜像
	TaskFailedReasonNotFindNodeInfo = "notFindNode"         // 未找到对应的节点
	TaskFailedReasonNotFindScanner  = "notFindScanInstance" // 未找到对应的扫描器
	TaskFailedTerminated            = "taskTerminated"      // 任务已被终止

)

var taskReasonEN map[string]string
var taskReasonZH map[string]string

func GetTaskReason(reason, lang string) string {
	if taskReasonZH == nil {
		taskReasonZH = map[string]string{
			TaskFailedReasonTimeout:         "超时",
			TaskFailedReasonSaveData:        "保存数据出错",
			TaskFailedReasonScanner:         "扫描出错",
			TaskFailedReasonSendNode:        "未发送到扫描节点",
			TaskFailedReasonSendScanner:     "未发送到扫描器",
			TaskFailedReasonNotFindImage:    "未找到对应镜像",
			TaskFailedReasonNotFindNodeInfo: "未找到对应节点",
			TaskFailedReasonNotFindScanner:  "未找到对应的扫描器",
			TaskFailedTerminated:            "任务被终止",
		}
	}

	if taskReasonEN == nil {
		taskReasonEN = map[string]string{
			TaskFailedReasonTimeout:         "time out",
			TaskFailedReasonSaveData:        "can not save scan data",
			TaskFailedReasonScanner:         "scan fail",
			TaskFailedReasonSendNode:        "can send scan task to node",
			TaskFailedReasonSendScanner:     "can send scan task to scanner",
			TaskFailedReasonNotFindImage:    "can not find image",
			TaskFailedReasonNotFindNodeInfo: "can not find node",
			TaskFailedReasonNotFindScanner:  "can not find scanner",
			TaskFailedTerminated:            "task terminated",
		}
	}
	if lang == LangEn {
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

const (
	SensitiveRuleTypeFileContent = "FileContent"
	SensitiveRuleTypeFilename    = "Filename"
)

const (
	ConfigTypeNodeScanImage = "nodeImage"
	ConfigTypeRegScanImage  = "regImage"
	ConfigTypeDeploy        = "deploy"
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
	AcceptLanguage = "Accept-Language"
)

const (
	DBMetaTypeVuln     = "vuln"
	DBMetaTypeWebshell = "webshell"
	DBMetaTypeClamav   = "clamav"
	DBMetaTypeAvira    = "avira"
)

const (
	AliAcrVersion           = "ali-acr"
	AliAcrEEVersion         = "ali-acr-ee"
	DockerRegistryV2Version = "registry-v2"
	HarborV1Version         = "harbor-v1.0"
	HarborV2Version         = "harbor-v2.0"
	HarborVersion           = "harbor" // 前端不再区分v1,v2
	HaiWeiSwrVersion        = "hw-swr"
	HaiWeiSwrENVersion      = "hw-swr-en"
	JfrogVersion            = "jfrog"
)

type SyncType string

func (s SyncType) String() string {
	return string(s)
}

const (
	TimingFullSync SyncType = "TimingFullSync"
	CycleFullSync  SyncType = "CycleFullSync"
	CycleIncSync   SyncType = "CycleIncSync"
	ManualSync     SyncType = "ManualSync"
)
const (
	RegAbnormal = "abnormal" // 仓库异常
	RegNormal   = "normal"   // 仓库正常
)

const (
	LangEn = "en"
	LangZh = "zh"
)

var OpenLicense = []string{"GPL", "MIT", "Apache License", "BSD", "MPL", "FreeBSD", "ISC"}

const (
	ExportExcel = "excel"
	ExportHtml  = "html"
)

var reasonZHMap = map[int64]string{}
var reasonENMap = map[int64]string{}

func GetRejectReason(lag string) map[int64]string {
	if lag == LangZh {
		return reasonZHMap
	} else if lag == LangEn {
		return reasonENMap
	}
	return make(map[int64]string)
}

const (
	CacheTypeImagePrepare = "imagePrepare"
	CacheTypVulnOverview  = "vulnOverview"
)
