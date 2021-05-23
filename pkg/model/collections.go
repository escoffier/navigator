package model

type Collection int

const (
	AlertsCollection Collection = iota
	AssetsContainersCollection
	ClusterCollection
	RulesCollection
	RulesDefinitionsCollection
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
		"alerts",
		"assets-containers",
		"cluster",
		"rules",
		"rulesDefinitions",
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
