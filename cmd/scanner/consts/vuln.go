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
	UniqueVulnFamat  = "%s-%s-%s"    // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueImageFamat = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.FromType, im.RegistryID))
)
