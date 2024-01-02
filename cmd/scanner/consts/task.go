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
	ImageScanAdapt = 21 // 2.19版本的数据已经适配到2.20之后的版本
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
	DetectAtHour             = 18 // 每天03点的时候加检测任务(服务器中用的是 utc 时间)
	DefaultHmEnginCnt        = 5  // 默认河马引擎的个数
	DefaultFileExpirationDay = 30 // 上传的文件默认保存30天
)
