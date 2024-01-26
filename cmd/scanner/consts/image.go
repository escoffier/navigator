package consts

const (
	AndString      = "and"
	OrString       = "or"
	BootRootUser   = "root"
	TrueString     = "true"
	FalseString    = "false"
	VulnLanguageGO = "go"
	LOGGINGDebug   = "0"
)

const (
	DefaultMaxLimit        = 100
	DefaultPerPage         = 10
	DefaultCreateInBatches = 50
	SortByDesc             = "desc"
	SortByAsc              = "asc"
	DuplicateKey           = "Duplicate"
	RiskImageTOPN          = 5
)

const (
	NoRiskImageScore            = 100
	DataMigrateModelImage       = "imagesec"
	ImageStatusImageAdapted     = 20
	ImageStatusImageForScanTask = 21

	DefaultSubtaskCntBySingeTask = 400
	SyncScanTaskCheckInterval    = 2 * 60 * 1000
	TrivyRedisIndex              = 1
)

const (
	ScannerVersion211 = "2.11.1"
	ScannerVersion220 = "2.20"
)

const (
	StatusInternalServerErrorMsg = "服务器开小差了，请稍后再试"
)

const (
	DefaultRedisDB                  = 0
	DefaultSensitiveRuleENPath      = "/configs/scanner/patterns.json"
	DefaultSensitiveRuleZHPath      = "/configs/scanner/patterns-zh.json"
	DefaultAdminUser                = "SeedAdmin"
	DefaultAviraSavServerListenPort = 9200
	DefaultHmEnginCnt               = 10 // 默认河马引擎的个数
	DetectAtHour                    = 18 // 每天03点的时候加检测任务(服务器中用的是 utc 时间)
	DefaultFileExpirationDay        = 30 // 上传的文件默认保存30天
	DefaultMaxRetryCount            = 3  // 默认的最大重试次数
)

const (
	ConstViewTypeVulnAttackPath = "vulnAttackPath"
	ConstViewTypeScanTaskType   = "scanTaskType"
	ConstViewTypeVulnClass      = "vulnClass"
	ConstViewTypeVulnSeverity   = "vulnSeverity"
	ConstViewDetectPolicyScope  = "detectPolicyScope"
	ConstViewDetectPolicyType   = "detectPolicyType"
	ConstViewImageFromType      = "imageFromType"
	ConstViewDeployAction       = "deployAction"
	ConstViewOpenLicense        = "openLicense"
)

const (
	// 需要整理一下
	ClamavName = "clamav"
	AviraName  = "avira"
	TrivyName  = "trivy"

	DBPassword   = "tanzhen2020scanner"
	VersionStr   = "version"
	TrivyDbName  = "trivy.db"
	CustomDbName = "custom.db"

	DeployGraphDay30  = "day30"
	DeployGraphDay7   = "day7"
	DeployGraphHour24 = "hour24"
)

const (
	ModuleImageMeta     = "imageMeta"
	ModuleImagesecSrv   = "imagesec"
	ModulePreInit       = "preInit"
	ModuleImageScan     = "scanImage"
	ModuleDeploy        = "deployImage"
	ModuleDetect        = "detectImage"
	ModuleMigrate       = "migrate"
	ModuleKafkaReport   = "kafkaReport"
	ModuleRpcStream     = "rpcStream"
	ModuleUBUpdate      = "dbUpdate"
	ModuleRegistryImage = "registryImage"
	LogModule           = "module"
	LogSubModule        = "submodule"
)

const (
	SubtaskLogName  = "subtask"
	TaskLogName     = "task"
	ImageLogName    = "image"
	RegistryLogName = "registry"
	NodeLogName     = "node"
	ScanJobLogName  = "scanJob"
)

const (
	WebshellFileDir             = "webshell"
	MaxInprogressSubtaskPerNode = 5
	MaxInprogressTask           = 5
	MillisecondPerDay           = 24 * 60 * 60 * 1000
	DefaultScanTimeout          = 30    // 30分钟
	DefaultSlaveDelay           = 50000 // 5000毫秒
)

const (
	StreamStatusOK            = 0
	StreamStatusFailed        = 1
	StreamStatusRegOK         = 2
	StreamStatusRegNotOK      = 3
	StreamStatusSyncFinished  = 5
	StreamStatusSyncFailed    = 6
	StreamStatusSyncProgress  = 7
	StreamStatusStartScanTask = 8

	StreamMsgSaveAviraOK = "save avira db ok"

	RegistryNormal   = "normal"
	RegistryAbnormal = "abnormal"
)
