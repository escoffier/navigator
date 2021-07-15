// 在这个包内定义常

package consts

const (
	ScanTaskComeFrom = iota
	ScanTaskComeFromWeb
	ScanTaskComeFromCICD
)

const (
	OverallSeverity = iota
	OverallSeverityNegligible
	OverallSeverityLow
	OverallSeverityMedium
	OverallSeverityHigh
	OverallSeverityCritical
)

const EncryptPasswordKey = "talkerss"

const (
	IntervalDay    = "day"
	IntervalHour   = "hour"
	TwentyFourHour = "24h"
	SevenDay       = "7d"
)

const TimeFormat = "2006-01-02 15:04:05.000000Z"
const TimeFormatWithHour = "2006-01-02 15"
const TimeFormatWithDay = "2006-01-02"

const DuplicateKey = "duplicate key value"

const (
	EventcenterURI               = "/eventcenter/sendNotification"
	ImageSecurity                = "imageSecurity"
	AlertKindCICD                = "scan image in ci/cd"
	AlertKindK8s                 = "scan image on k8s admission controller"
	AlertKindOnline              = "scan online image"
	AlertModuleContainerSecurity = "ContainerSecurity"

	HTTPS_CLIENT_CERT_PATH                              = "/eventcenter-config/tls.crt"
	HTTPS_CLIENT_PRIVATE_KEY                            = "/eventcenter-config/tls.key"
	GRPC_CA_PATH                                        = "/auth/ca/tls.crt"
	TENSORSEC_EVENTCENTER_SERVICE_HOST                  = "https://tensorsec-eventcenter"
	TENSORSEC_EVENTCENTER_SERVICE_PORT_EVENTCENTER_HTTP = ":8080"

	EventIntervalUUID = 2 // 表示每2分钟生成一个uuid
)
