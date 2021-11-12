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

const CheckTaskInterval = 60 * 5 // 检查是否加扫描任务的时间间隔，单位：妙

const (
	CicdOperator        = "CICD触发扫描"
	SyncTriggerOperator = "周期触发扫描"
)
