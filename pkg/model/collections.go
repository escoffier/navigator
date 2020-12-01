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
	ComplianceCheckKubeRecordsCollection
	ComplianceCheckDockerRecordsCollection
	ComplianceCheckHostRecordsCollection
	Cve2cnnvdCollection
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
		"kube-bench-records",
		"docker-bench-records",
		"host-bench-records",
		"CVE2CNNVD",
	}
}

func (c Collection) String() string {
	return GetCollectionNames()[c]
}
