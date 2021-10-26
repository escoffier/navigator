package model

type Collection int

const (
	Cve2cnnvdCollection Collection = iota
	HarborProjectConfigCollection
	VirusScanTaskCollection
)

func GetCollectionNames() []string {
	return []string{
		"CVE2CNNVD",
		"harborProjectConfig",
		"virusScanTasks",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
