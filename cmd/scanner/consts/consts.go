// 在这个包内定义常

package consts

import (
	"fmt"
)

const (
	ScanTaskComeFrom = iota
	ScanTaskComeFromWeb
	ScanTaskComeFromCICD
)
const (
	TrustedImage   = 1
	UnTrustedImage = 0
	TrueString     = "true"
	FalseString    = "false"
	AllString      = "all"
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

	HTTPS_CLIENT_CERT_PATH             = "/eventcenter-config/tls.crt"
	HTTPS_CLIENT_PRIVATE_KEY           = "/eventcenter-config/tls.key"
	GRPC_CA_PATH                       = "/auth/ca/tls.crt"
	TENSORSEC_EVENTCENTER_SERVICE_HOST = "https://eventcenter"
	TENSORSEC_EVENTCENTER_SERVICE_PORT = "8080"

	EventIntervalUUID = 2 // 表示每2分钟生成一个uuid
)

const (
	RegistryDefaultSyncInterval = 5 // 5分钟
)

const (
	VulnType             = "vuln_info_json"
	PkgType              = "pkg_info_json"
	SensitiveFileType    = "sensitive_file_json"
	MaliciousInfoType    = "malicious_info_json"
	WebsellInfoType      = "webshell_info_json"
	EnvEnableType        = "env_type"
	SoftWoreType         = "soft_ware_type"
	LicenseEnableType    = "licenceType"
	PrivilegedEnableType = "privileged"

	BaseImageType       = 1
	AppImageType        = 0
	BaseImageTypeString = "1"
	AppImageTypeString  = "0"
)

const (
	ValidateCreate = "create"
	ValidateUpdate = "update"
)

const (
	StatusInternalServerErrorMsg = "服务器开小差了，请稍后再试"
)

const (
	NodeSafeSalt     = "tensorsecurity"
	NodeSafeTage     = "%s/" + NodeSafeSalt + "/%s/%s/%s/%s/%s" // 仓库地址/tensorsec/clusterKey/namespace/podName/podIp/os/镜像名
	NodeSafeFullName = NodeSafeSalt + "/%s/&s/%s/%s/%s/%s"      // tensorsec/hostname/ip/os/镜像名
)

const (
	IsTrustedImageString  = "1"
	NotTrustedImageString = "0"
	IsTrustedImage        = 1
	NotTrustedImage       = 0

	NotHasFixedvuln = 0
	HasFixedvuln    = 1

	NotHasFixedvulnString = "0"
	HasFixedvulnStringd   = "1"

	PrivilegedBootImage    = 1
	NotPrivilegedBootImage = 0

	PrivilegedBootString    = "1"
	NotPrivilegedBootString = "0"

	IsReinforceImage    = 1
	IsNotReinforceImage = 0

	IsReinforceImageString    = "1"
	IsNotReinforceImageString = "0"
)

var NotNodeImageErr = fmt.Errorf("not find node info")

const SpecialImageTypeK8s = "k8s"
