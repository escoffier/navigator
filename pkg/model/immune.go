package model

import "time"

type PolicyKind int32

const (
	PolicyKindSyscalls   PolicyKind = 1
	PolicyKindFileRW     PolicyKind = 2
	PolicyKindBinaryExec PolicyKind = 3
	PolicyKindCmdExec    PolicyKind = 4
)

type Decision int32

const (
	DecisionAlert   Decision = 1
	DecisionDefense Decision = 2
)

type PolicyStatus int32

const (
	StatusEnable     PolicyStatus = 2
	StatusSoftDelete PolicyStatus = 1
	StatusDisable    PolicyStatus = 0
)

type ImmunePolicy struct {
	ID              int64        `gorm:"column:id" json:"id"`
	Name            string       `gorm:"column:name" json:"name"`
	Description     string       `gorm:"column:description" json:"description"`
	Kind            PolicyKind   `gorm:"column:kind" json:"kind"`
	ResourceUUID    uint32       `gorm:"column:resource_uuid" json:"resourceUUID"`
	ClusterKey      string       `gorm:"column:cluster_key"`
	ResourceVersion int64        `gorm:"column:resource_version"`
	Decision        Decision     `gorm:"decision" json:"decision"`
	Status          PolicyStatus `gorm:"status" json:"status"`
	Creator         string       `gorm:"column:creator" json:"creator"`
	Updater         string       `gorm:"column:updater" json:"updater"`
	CreatedAt       time.Time    `gorm:"created_at" json:"created_at"`
	UpdatedAt       time.Time    `gorm:"updated_at" json:"updated_at"`
}

func (ImmunePolicy) TableName() string {
	return "immune_policies"
}

type ImmuneProfile struct {
	UUID          int64     `gorm:"column:uuid"`
	PolicyID      int64     `gorm:"column:policy_id"`
	ContainerName string    `gorm:"column:container_name"`
	Value         []byte    `gorm:"column:value"`
	Status        int32     `gorm:"column:status"`
	Creator       string    `gorm:"column:creator"`
	CreatedAt     time.Time `gorm:"created_at"`
}

func (ImmuneProfile) TableName() string {
	return "immune_profiles"
}

type SyscallsConfigurations []string
type FileRWConfigurations []FRWElement
type FRWElement struct {
	FilePath string `json:"filePath"`
	RW       string `json:"rw"`
}
type CmdLineExecConfigurations []CmdExecElement
type CmdExecElement struct {
	CommandLine string `json:"commandLine"`
	Env         string `json:"env"`
}
