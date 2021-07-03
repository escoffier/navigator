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
	PodServiceRelationCollection
	PodOwnerRefRelationCollection
	ServiceRelationCollection
	ServiceAliasCollection
	HarborProjectConfigCollection
	TensorServiceCollection
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
		"podServiceRelation",
		"podOwnerRefRelation",
		"serviceRelation",
		"serviceAlias",
		"harborProjectConfig",
		"tensor-service",

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
