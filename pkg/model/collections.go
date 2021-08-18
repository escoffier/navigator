package model

type Collection int

const (
	ClusterCollection Collection = iota

	Cve2cnnvdCollection
	CheckHistoryEntryCollection
	HarborProjectConfigCollection

	VirusScanTaskCollection

	GCTaskCollection
	DataTTLSettingCollection
	DataWaterlineSettingCollection
)

func GetCollectionNames() []string {
	return []string{
		"cluster",

		"CVE2CNNVD",
		"checkHistoryEntry",
		"harborProjectConfig",

		"virusScanTasks",

		"gcTasks",
		"dataTTLSetting",
		"dataWaterlineSetting",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
