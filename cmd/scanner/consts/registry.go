package consts

const (
	AliAcrVersion           = "ali-acr"
	AliAcrEEVersion         = "ali-acr-ee"
	DockerRegistryV2Version = "registry-v2"
	HarborV1Version         = "harbor-v1.0"
	HarborV2Version         = "harbor-v2.0"
	HaiWeiSwrVersion        = "hw-swr"
	JfrogVersion            = "jfrog"
)

type SyncType string

const (
	TimingFullSync SyncType = "TimingFullSync"
	CycleFullSync  SyncType = "CycleFullSync"
	CycleIncSync   SyncType = "CycleIncSync"
	ManualSync     SyncType = "ManualSync"
)
const (
	SyncImageMaxCountDefault = 50
)
