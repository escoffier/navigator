package k8saudit

const (
	AuditIndexPrefixEnv     = "K8S_AUDIT_INDEX_PREFIX"
	DefaultAuditIndexPrefix = "audit_"

	SyslogEnableEnv     = "K8S_AUDIT_SYSLOG_ENABLE"
	DefaultSyslogEnable = false

	SyslogNetworkEnv     = "K8S_AUDIT_SYSLOG_NETWORK"
	DefaultSyslogNetwork = "udp"

	SyslogServerAddrEnv = "K8S_AUDIT_SYSLOG_SERVER_ADDR"

	SyslogFacilityEnv     = "K8S_AUDIT_SYSLOG_FACILITY"
	DefaultSyslogFacility = 1

	SyslogSeverityEnv     = "K8S_AUDIT_SYSLOG_SEVERITY"
	DefaultSyslogSeverity = 5

	SyslogTagEnv     = "K8S_AUDIT_SYSLOG_TAG"
	DefaultSyslogTag = "k8s-audit"
)
