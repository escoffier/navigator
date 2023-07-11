package consts

const (
	StreamStatusOK       = 0
	StreamStatusFailed   = 1
	StreamMsgSaveVulnOK  = "save vuln db ok"
	StreamMsgSaveAviraOK = "save avira db ok"
)

type ServiceType string

const (
	TypeServiceImageAsset       ServiceType = "image-asset"
	TypeServiceTaskManager      ServiceType = "task-manager"
	TypeServiceImageResultCache ServiceType = "image-result-cache-service"
	TypeServiceStream           ServiceType = "stream-service"
	TypeServiceAvira            ServiceType = "avira"
	TypeServiceDBUpdater        ServiceType = "db-updater"
	TypeServiceNotify           ServiceType = "notify"
)

func (vi ServiceType) String() string {
	return string(vi)
}

const (
	ScanMalwareTypeAvira  = "avira"
	ScanMalwareTypeSavapi = "savapi"
	ScanMalwareTypeClamAv = "clamav"
	VulnDBFile            = "vuln-db.zip"
	AviraDBFile           = "avira.zip"
)

type NotifyEventType string

const (
	NotifyEventTypeVulnDBUpdate   NotifyEventType = "vuln-db-update"
	NotifyEventTypeAviraDBUpdate  NotifyEventType = "avira-db-update"
	NotifyEventTypeConfigModified NotifyEventType = "config-modified"
)
