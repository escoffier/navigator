package env

// env
const (
	MonitorLabelApps        = "MONITOR_LABEL_APPS" // eg value: DefaultMonitorAppLabels
	DefaultMonitorAppLabels = "holmes,scanner,cluster-manager"

	SoftName        = "SOFT_NAME"
	DefaultSoftName = "tensor"
	SoftVersionEnv  = "SOFT_VERSION"

	NodeName    = "MY_NODE_NAME"
	PodAppLabel = "MY_POD_APP_LABEl"

	MonitorDuration = "MONITOR_DURATION" //  单位:s
)

const (
	EnvTopicMonitor     = "KAFKA_MONITOR_TOPIC" // 监控容器 topic
	DefaultTopicMonitor = "container-monitor"   //
)
