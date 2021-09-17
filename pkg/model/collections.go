package model

type Collection int

const (
	ClusterCollection Collection = iota

	Cve2cnnvdCollection
	HarborProjectConfigCollection
	VirusScanTaskCollection
)

func GetCollectionNames() []string {
	return []string{
		"cluster",

		"CVE2CNNVD",
		"harborProjectConfig",
		"virusScanTasks",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
