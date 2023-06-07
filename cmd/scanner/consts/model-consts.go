package consts

// 后面做仓库镜像重构时移出
const (
	UniqueVulnFamat      = "%s-%s-%s" // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueVirusFamat     = "%s-%s-%s"
	UniqueSensitiveFamat = "%s-%s"
	UniqueLicenseFamat   = "%s-%s-%s"
	UniqueSoftwareFamat  = "%s-%s"
	UniqueENVFamat       = "%s-%s-%t"
	UniqueWebshellFamat  = "%s-%s-%s"
	UniqueImageFamat     = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.ImageFromType, im.RegID))
)
