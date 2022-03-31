package consts

const (
	SeverityCritical   = 5
	SeverityHigh       = 4
	SeverityMedium     = 3
	SeverityLow        = 2
	SeverityUnknown    = 1
	SeverityNegligible = 0
)

const (
	UniqueVulnFamat          = "%s-%s-%s"    // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueImageFamat         = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.FromType, im.RegistryID))
	MaxWebshellAndVirusScore = 40            // 评分细则规定webshell和病毒都算恶意文件加起来满分40
	ImageEmptyFlag           = 0
)
