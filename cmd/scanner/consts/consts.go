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

	YesString = "y"
	NoString  = "n"
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

const DuplicateKey = "Duplicate"

const (
	EventcenterURI               = "/eventcenter/sendNotification"
	ImageSecurity                = "imageSecurity"
	AlertKindCICD                = "scan image in ci/cd"
	AlertKindK8s                 = "scan image on k8s admission controller"
	AlertKindOnline              = "scan online image"
	AlertModuleContainerSecurity = "ContainerSecurity"

	HTTPSClientCertPath    = "/eventcenter-config/tls.crt"
	HTTPSClientPrivateKey  = "/eventcenter-config/tls.key"
	GrpcCAPath             = "/auth/ca/tls.crt"
	EventCenterServiceHost = "https://eventcenter"
	EventCenterServicePort = "8080"

	EventIntervalUUID = 2 // 表示每2分钟生成一个uuid
)

const (
	RegistryDefaultSyncInterval = 5 // 5分钟
)

const (
	ValidateCreate = "create"
	ValidateUpdate = "update"
)

const (
	StatusInternalServerErrorMsg = "服务器开小差了，请稍后再试"
)

const (
	NodeSafeSalt     = "nodemirroringsalt"
	NodeSafeTage     = "%s/" + NodeSafeSalt + "/%s/%s/%s/%s/%s" // 仓库地址/tensorsec/clusterKey/namespace/podName/os/镜像名
	ColonSalt        = "nodecolonsalt"
	NodeSafeFullName = NodeSafeSalt + "/%s/&s/%s/%s/%s/%s" // tensorsec/hostname/ip/os/镜像名
)

const (
	IsTrustedImageString  = "1"
	NotTrustedImageString = "0"
	IsTrustedImage        = 1
	NotTrustedImage       = 0

	NotHasFixedvuln = 0
	HasFixedvuln    = 1

	NotHasFixedvulnString = "0"
	HasFixedvulnString    = "1"

	PrivilegedBootImage    = 1
	NotPrivilegedBootImage = 0

	PrivilegedBootString    = "1"
	NotPrivilegedBootString = "0"

	IsReinforceImage    = 1
	IsNotReinforceImage = 0

	IsReinforceImageString    = "1"
	IsNotReinforceImageString = "0"
)

var ErrNotNodeImage = fmt.Errorf("not find node info")

const SpecialImageTypeK8s = "k8s"

const DefaultVulnTopNImage = 5
const MaxVulnTopNImage = 20
const DefaultBathSize = 500 // 批量取数据时，默认每次取的条数
const DefaultLimit = 200
const DefaultOffset = 0
const DefaultCreateInBatches = 50

const (
	SortByDesc = "desc"
	SortByAsc  = "asc"
)

const SecureImageRiskScore = 60

const (
	ScannerUser    = "X-Tensorsec-cicd-key"
	InternalApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
)
