package consts

const (
	UniqueVulnFamat               = "%s-%s-%s"    // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueImageFamat              = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.FromType, im.RegistryID))
	MaxWebshellAndVirusScore      = 40            // 评分细则规定webshell和病毒都算恶意文件加起来满分40
	ImageEmptyFlag                = 0
	VulnSourceFromGobinary        = "gobinary"
	VulnSourceFromDevFramework    = "开发框架"
	VulnSourceFromProgramLanguage = "编程语言"
	VulnSourceFromSoftware        = "软件"
	VulnLanguageGO                = "go"
)
