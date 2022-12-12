package consts

const (
	UniqueVulnFamat      = "%s-%s-%s" // vn.Name, vn.PkgName, vn.PkgVersion
	UniqueVirusFamat     = "%s-%s-%s"
	UniqueSensitiveFamat = "%s-%s"
	UniqueLicenseFamat   = "%s-%s-%s"
	UniqueSoftwareFamat  = "%s-%s"
	UniqueENVFamat       = "%s-%s-%t"
	UniqueWebshellFamat  = "%s-%s-%s"
	UniqueImageFamat     = "%s-%s-%d-%d" // im.FullRepoName, im.Tags, im.FromType, im.RegistryID))
	VulnLanguageGO       = "go"
)

const (
	SeverityCRITICALString = "CRITICAL"
	SeverityHIGHString     = "HIGH"
	SeverityMEDIUMString   = "MEDIUM"
	SeverityLOWString      = "LOW"
	SeverityUNKNOWNString  = "UNKNOWN"
)

const (
	SeverityCRITICAL = 5
	SeverityHIGH     = 4
	SeverityMEDIUM   = 3
	SeverityLOW      = 2
	SeverityUNKNOWN  = 1
)
const (
	EnvIsAbnormal = 1
)
