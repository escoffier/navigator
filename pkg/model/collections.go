package model

type Collection int

const (
	ClusterCollection Collection = iota
	ComplianceCheckResults
	ComplianceCheckKubeRecordsCollection
	ComplianceCheckDockerRecordsCollection
	ComplianceCheckHostRecordsCollection
	Cve2cnnvdCollection
	CheckHistoryEntryCollection
	HarborProjectConfigCollection

	VirusScanTaskCollection
	ExportFileTaskCollection

	GCTaskCollection
	DataTTLSettingCollection
	DataWaterlineSettingCollection
)

func GetCollectionNames() []string {
	return []string{
		"cluster",
		"complianceCheckResults",
		"kube-bench-records",
		"docker-bench-records",
		"host-bench-records",
		"CVE2CNNVD",
		"checkHistoryEntry",
		"harborProjectConfig",

		"virusScanTasks",
		"exportFileTasks",

		"gcTasks",
		"dataTTLSetting",
		"dataWaterlineSetting",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
