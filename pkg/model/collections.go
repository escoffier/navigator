package model

type Collection int

const (
	AlertsCollection Collection = iota
	AssetsContainersCollection
	AuditCollection
	ClusterCollection
	GCCollection
	ESGCCollection
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
	ExportFileTaskCollection
)

func GetCollectionNames() []string {
	return []string{
		"alerts",
		"assets-containers",
		"audit",
		"cluster",
		"gc",
		"esgc",
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
		"exportFileTasks",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
