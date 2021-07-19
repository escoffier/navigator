package model

type Collection int

const (
	AssetsContainersCollection Collection = iota
	ClusterCollection
	ComplianceCheckResults
	ComplianceCheckKubeRecordsCollection
	ComplianceCheckDockerRecordsCollection
	ComplianceCheckHostRecordsCollection
	Cve2cnnvdCollection
	CheckHistoryEntryCollection
	PodOwnerRefRelationCollection
	HarborProjectConfigCollection

	VirusScanTaskCollection
	ExportFileTaskCollection

	GCTaskCollection
	DataTTLSettingCollection
	DataWaterlineSettingCollection
)

func GetCollectionNames() []string {
	return []string{
		"assets-containers",
		"cluster",
		"complianceCheckResults",
		"kube-bench-records",
		"docker-bench-records",
		"host-bench-records",
		"CVE2CNNVD",
		"checkHistoryEntry",
		"podOwnerRefRelation",
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
