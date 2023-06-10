package consts

// task status
const (
	Unknown = iota
	Pending
	InProgress
	End
	Pause
	Terminate
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
	FullScan                 = iota // 全量扫描
	SingleScan                      // 单个扫描
	DefaultMaxInProgressTask = 5
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

const CheckTaskInterval = 60 * 1   // 检查是否加扫描任务的时间间隔，单位：秒
const DefaultMaxRetryCount = 3     // 默认的最大重试次数
const DefaultSlaveDelay = 5 * 1000 // 默认主从延迟:5s

const SubTaskBatchInsertCount = 200

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

const (
	IsSyncingImage  = true  // 正在同步
	NotSyncingImage = false // 没在同步
)

const (
	DetectAtHour = 18 // 每天03点的时候加检测任务(服务器中用的是 utc 时间)
)
