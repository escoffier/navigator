package consts

const (
	OnlineImageRedisKey        = "container_images"
	RedisPositiveInfinity      = "+inf"
	DefaultRedisDB             = 0
	DefaultSensitiveRuleENPath = "/configs/scanner/patterns.json"
	DefaultSensitiveRuleZHPath = "/configs/scanner/patterns-zh.json"
	DefaultAdminUser           = "admin"
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
	ClamavName = "clamav"
	AviraName  = "avira"
	DBPassword = "tanzhen2020scanner"
	VersionStr = "version"

	DeployGraphDay30  = "day30"
	DeployGraphDay7   = "day7"
	DeployGraphHour24 = "hour24"
)

const (
	RiskImageTOPN = 5
)

const (
	ModelImageMeta   = "imageMeta"
	ModelImageScan   = "imagescan"
	ModuleDeploy     = "deployImage"
	LogModule        = "module"
	LogSubModule     = "submodule"
	ModelImageDetect = "imageDetect"
)
