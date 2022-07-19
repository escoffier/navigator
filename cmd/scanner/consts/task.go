package consts

// task status
const (
	Unknown = iota
	Pending
	InProgress
	End
	Pause
	Terminate
	NotScan // deprecated
)

// task result
const (
	ResultUnknown = iota
	ScanSuccess
	ScanFail
)

// image(subtask) scan status
const (
	ImageScanUnknown = iota
	ImageScanPending
	ImageScanInProgress
	ImageScanSuccess
	ImageScanFailed
	ImageNotScan
)

const (
	FullScan   = iota // 全量扫描
	SingleScan        // 单个扫描

)

// task scan type
const (
	ScanVul           = "scan-vuln"
	ScanMalicious     = "scan-malicious"
	ScanSensitiveFile = "scan-sensitive"
	ScanWebshell      = "scan-webshell"
	ScanEnv           = "scan-env"
	ScanLicense       = "scan-license"
)

// task trigger type
const (
	UnknownTrigger = iota
	CiCdTrigger
	VulDataUpdateTrigger
	VirusDataUpdateTrigger
	ScheduleTrigger
	ImageSyncTrigger
	ManualTrigger
)

const CheckTaskInterval = 60 * 1 // 检查是否加扫描任务的时间间隔，单位：秒
const SubTaskMaxRetryCount = 3   // 一次任务的最大重试次数

const SubTaskBatchInsertCount = 200

const (
	CicdOperator         = "CICD触发扫描"
	CycleTriggerOperator = "周期触发扫描"
	SyncTriggerOperator  = "镜像同步触发扫描"
)
const (
	ErrScanPullImage      = iota + 1 // "拉取镜像出错"
	ErrScanTrivy                     // "扫描镜像出错"
	ErrScanSaveResult                // "保存扫描数据出错"
	ErrScanConfig                    // "解析扫描配置出错"
	ErrScanGetImage                  // "查询待扫描镜像出错"
	ErrScanImageRemoved              // "镜像已被删除"
	ErrScanGetRegistry               // "查询镜像仓库出错"
	ErrScanInternal                  // "程序内部出错"
	ErrExceededRetryCount            // "超过重试次数"
	ErrRegRemoved                    // "仓库已删除"
)

func GetErrMsgEnu(errNo int) string {
	switch errNo {
	case ErrScanPullImage:
		return "拉取镜像出错"
	case ErrScanTrivy:
		return "扫描镜像出错"
	case ErrScanSaveResult:
		return "保存扫描数据出错"
	case ErrScanConfig:
		return "解析扫描配置出错"
	case ErrScanGetImage:
		return "查询待扫描镜像出错"
	case ErrScanGetRegistry:
		return "查询镜像仓库出错"
	case ErrScanInternal:
		return "程序内部出错"
	case ErrExceededRetryCount:
		return "超过重试次数"
	case ErrScanImageRemoved:
		return "镜像已被清除"
	case ErrRegRemoved:
		return "仓库已删除"
	default:
		return "程序内部出错"
	}
}

const (
	IsSyncingImage  = true  // 正在同步
	NotSyncingImage = false // 没在同步
)
