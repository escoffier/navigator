package model

type Collection int

const (
	AssetsContainersCollection Collection = iota
	ClusterCollection
	ScanTasksCollection
	ComplianceCheckResults
	ComplianceCheckKubeRecordsCollection
	ComplianceCheckDockerRecordsCollection
	ComplianceCheckHostRecordsCollection
	Cve2cnnvdCollection
	CheckHistoryEntryCollection
	VulnerabilitiesInImagesCollection
	PodServiceRelationCollection
	PodOwnerRefRelationCollection
	ServiceRelationCollection
	ServiceAliasCollection
	HarborProjectConfigCollection
	TensorServiceCollection
	VirusScanTaskCollection
	ImageListCollection
	ExportFileTaskCollection

	GCTaskCollection
	DataTTLSettingCollection
	DataWaterlineSettingCollection
)

func GetCollectionNames() []string {
	return []string{
		"assets-containers",
		"cluster",
		"scantasks",
		"complianceCheckResults",
		"kube-bench-records",
		"docker-bench-records",
		"host-bench-records",
		"CVE2CNNVD",
		"checkHistoryEntry",
		"vulnerabilitiesInImages",
		"podServiceRelation",
		"podOwnerRefRelation",
		"serviceRelation",
		"serviceAlias",
		"harborProjectConfig",
		"tensor-service",

		"virusScanTasks",
		"imageList",
		"exportFileTasks",

		"gcTasks",
		"dataTTLSetting",
		"dataWaterlineSetting",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
