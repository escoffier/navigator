package consts

const (
	AliAcrVersion           = "ali-acr"
	AliAcrEEVersion         = "ali-acr-ee"
	DockerRegistryV2Version = "registry-v2"
	HarborV1Version         = "harbor-v1.0"
	HarborV2Version         = "harbor-v2.0"
	HarborVersion           = "harbor" // 前端不再区分v1,v2
	HaiWeiSwrVersion        = "hw-swr"
	HaiWeiSwrENVersion      = "hw-swr-en"
	JfrogVersion            = "jfrog"
)

type SyncType string

func (s SyncType) String() string {
	return string(s)
}

const (
	TimingFullSync SyncType = "TimingFullSync"
	CycleFullSync  SyncType = "CycleFullSync"
	CycleIncSync   SyncType = "CycleIncSync"
	RetryIncSync   SyncType = "RetryIncSync"
	ManualSync     SyncType = "ManualSync"
)
const (
	SyncImageMaxCountDefault = 50
	RegAbnormal              = "abnormal" // 仓库异常
	RegNormal                = "normal"   // 仓库正常
)
