package model

type Collection int

const (
	AlertsCollection Collection = iota
	AssetsContainersCollection
	AuditCollection
	ClusterCollection
	GCCollection
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
	ServiceCollection
	ServiceRelationCollection
	ServiceAliasCollection
	HarborProjectConfigCollection
	TensorServiceCollection
)

func GetCollectionNames() []string {
	return []string{
		"alerts",
		"assets-containers",
		"audit",
		"cluster",
		"gc",
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
		"service",
		"serviceRelation",
		"serviceAlias",
		"harborProjectConfig",
		"tensor-service",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
