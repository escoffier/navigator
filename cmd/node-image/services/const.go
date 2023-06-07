package services

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

const (
	ScanMalwareTypeAvira  = "avira"
	ScanMalwareTypeClamAv = "clamav"
)
