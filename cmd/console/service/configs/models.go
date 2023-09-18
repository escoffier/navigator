package configs

import (
	"time"
)

const (
	Segment   = "Segment"
	Resource  = "Resource"
	IPBlock   = "IPBlock"
	Namespace = "Namespace"
	Tenant    = "Tenant"
	Nsgrp     = "Nsgrp"

	ProtocolUDP = "UDP"
	ProtocolTCP = "TCP"

	Allow = "Allow"
	Deny  = "Deny"
	Drop  = "Drop"
	Log   = "Log"

	Ingress = "Ingress"
	Egress  = "Egress"
)

var directionToDao = map[string]int{
	Ingress: 1,
	Egress:  2,
}

var directionToDto = map[int]string{
	1: Ingress,
	2: Egress,
}

var microTypeToDao = map[string]int{
	Segment:   1,
	Resource:  2,
	IPBlock:   3,
	Namespace: 4,
	Tenant:    5,
	Nsgrp:     6,
}

var microTypeToDto = map[int]string{
	1: Segment,
	2: Resource,
	3: IPBlock,
	4: Namespace,
	5: Tenant,
	6: Nsgrp,
}

var protocolTypeToDao = map[string]int{
	ProtocolTCP: 1,
	ProtocolUDP: 2,
}

var protocolTypeToDto = map[int]string{
	1: ProtocolTCP,
	2: ProtocolUDP,
}

var actionToDao = map[string]int{
	Allow: 1,
	Deny:  2,
	Log:   3,
}

var actionToDto = map[int]string{
	1: Allow,
	2: Deny,
	3: Log,
}

type BaseInfo struct {
	Status    int `gorm:"type:smallint"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserInfo struct {
	Creator string `gorm:"type:varchar(100);"`
	Updater string `gorm:"type:varchar(100);"`
}

type MicrosegOperatorStatus struct {
	Status bool
}

// MicrosegTenant
type TensorMicrosegTenant struct {
	ID               int64  `gorm:"type:bigserial;primarykey"`
	UUID             uint32 `gorm:"type:bigint"`
	Name             string `gorm:"type:varchar(100)"`
	Cluster          string `gorm:"type:varchar(100)"`
	PolicyNamespace  string `gorm:"type:varchar(100)"`
	Namespaces       string `gorm:"type:varchar(1024)"`
	Users            string `gorm:"type:varchar(100)"`
	LogicCluster     int64  `gorm:"type:bigint;default:-1"`
	LogicClusterName string `gorm:"-"`
	Privilege        int
	BaseInfo
}

func (t *TensorMicrosegTenant) TableName() string {
	return "ivan_microseg_tenants"
}

// MicrosegLogicCluster
type TensorMicrosegLogicCluster struct {
	ID          int64                  `gorm:"type:bigserial;primarykey"`
	Name        string                 `gorm:"type:varchar(100)"`
	Cluster     string                 `gorm:"type:varchar(100)"`
	Tenants     string                 `gorm:"type:varchar(100)"`
	TenantInfos []TensorMicrosegTenant `gorm:"-"`
	Nodes       string                 `gorm:"type:varchar(1024)"`
	BaseInfo
}

func (t *TensorMicrosegLogicCluster) TableName() string {
	return "ivan_microseg_logic_clusters"
}

// MicrosegNsgrp
type TensorMicrosegNsgrp struct {
	ID              int64  `gorm:"type:bigserial;primarykey"`
	UUID            uint32 `gorm:"type:bigint"`
	Name            string `gorm:"type:varchar(100)"`
	Cluster         string `gorm:"type:varchar(100)"`
	PolicyNamespace string `gorm:"type:varchar(100)"`
	Namespaces      string `gorm:"type:varchar(1024)"`
	BaseInfo
}

func (t *TensorMicrosegNsgrp) TableName() string {
	return "ivan_microseg_nsgrps"
}

// MicrosegPolicy
type TensorMicrosegPolicy struct {
	Name          string `gorm:"type:varchar(64);primarykey"`
	Status        int    `gorm:"type:smallint"`
	Cluster       string `gorm:"type:varchar(100)"`
	Namespace     string `gorm:"type:varchar(100)"`
	AllowExternal bool   `gorm:"default:false"`
	Type          string `gorm:"type:varchar(20)"`
	Trusted       bool   `gorm:"default:false"`
	Revision      int
	UserInfo
	BaseInfo
}

func (t *TensorMicrosegPolicy) TableName() string {
	return "ivan_microseg_policies"
}

// MicrosegResource
type TensorMicrosegResource struct {
	ID          uint32 `gorm:"type:bigint;primarykey"`
	SegmentID   uint32 `gorm:"type:bigint;index:idx_res_sid"`
	SegmentName string `gorm:"type:varchar(100);index:idx_res_sname"`
	Cluster     string `gorm:"type:varchar(100)"`
	Namespace   string `gorm:"type:varchar(100)"`
	Kind        string `gorm:"type:varchar(100)"`
	Name        string `gorm:"type:varchar(100)"`
	Policy      string `gorm:"type:varchar(100)"`
	NetworkType int    `gorm:"type:smallint"`
	ResourceTag int    `gorm:"type:smallint"`
	BaseInfo
	Enabled int `gorm:"-"`
}

func (t *TensorMicrosegResource) TableName() string {
	return "ivan_microseg_resources"
}

type TensorMicrosegResourcePolicy struct {
	Resource TensorMicrosegResource
	Policy   TensorMicrosegPolicy
}

// MicrosegRule
type TensorMicrosegRule struct {
	Policy     string `gorm:"type:varchar(100)"`
	Direction  int    `gorm:"type:smallint"`
	SrcType    int    `gorm:"type:smallint"`
	SrcID      uint32 `gorm:"type:bigint"`
	SrcIPBlock string `gorm:"type:varchar(100)"`
	DstType    int    `gorm:"type:smallint"`
	DstID      uint32 `gorm:"type:bigint"`
	DstIPBlock string `gorm:"type:varchar(100)"`
	Action     int    `gorm:"type:smallint"`
	Protocol   int    `gorm:"type:smallint"`
	Ports      string `gorm:"type:varchar(100)"`
	Comment    string `gorm:"type:text"`
	IsSegRule  bool
	BaseInfo
}

func (t *TensorMicrosegRule) TableName() string {
	return "ivan_microseg_rules"
}

// MicrosegSegment
type TensorMicrosegSegment struct {
	ID        uint32 `gorm:"type:bigint;primarykey"`
	Name      string `gorm:"type:varchar(100);index:idx_seg_name"`
	Cluster   string `gorm:"type:varchar(100)"`
	Namespace string `gorm:"type:varchar(100)"`
	Policy    string `gorm:"type:varchar(100)"`
	UserInfo
	BaseInfo
	Enabled int `gorm:"-"`
}

func (t *TensorMicrosegSegment) TableName() string {
	return "ivan_microseg_segments"
}

// Microseg Import struct
type CreatePolicyRequest struct {
	Status        int    `json:"status"`
	Rules         []Rule `json:"rules"`
	Revision      int    `json:"revision"`
	Operator      string `json:"operator"`
	AllowExternal bool   `json:"allowExternal"`
}

type CreateNamespacePolicyRequest struct {
	CreatePolicyRequest
	Trusted bool `json:"trusted"`
}

type CreateTenantPolicyRequest = CreateNamespacePolicyRequest

type CreateNsgrpPolicyRequest = CreateNamespacePolicyRequest

type CreateSegmentRequest = struct {
	Name string `json:"name"`
}

// tenants
type TenantBaseInfo struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	Privileges []string `json:"privileges"`
	Users      []string `json:"users"`
}

type CreateTenantRequest struct {
	BaseInfo   TenantBaseInfo            `json:"baseInfo"`
	PolicyInfo CreateTenantPolicyRequest `json:"policyInfo"`
}

type UpdateTenantRequest = CreateTenantRequest

type SingleTenant struct {
	ID             int64              `json:"id"`
	UUID           uint32             `json:"uuid"`
	Name           string             `json:"name"`
	Cluster        string             `json:"cluster"`
	Namespaces     []string           `json:"namespaces"`
	Users          []string           `json:"users"`
	IsAdmin        bool               `json:"is_admin"`
	Resources      []SingleResource   `json:"resources"`
	Privileges     []string           `json:"privileges"`
	Enabled        int                `json:"enabled"`
	Trusted        bool               `json:"trusted"`
	LogicCluster   SingleLogicCluster `json:"logicCluster"`
	PolicyInfo     PolicyResponse     `json:"policyInfo"`
	TotalResources int                `json:"totalResources"`
}

// resource
type SingleResource struct {
	ID          uint32 `json:"id"`
	SegmentID   uint32 `json:"segmentId"`
	SegmentName string `json:"segmentName"`
	IsFake      bool   `json:"isFake"`
	DstPort     int    `json:"dstPort"`
	Protocol    string `json:"protocol"`
	Enabled     int    `json:"enabled"`
	K8sResource
}

type K8sResource struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

// logic_Cluster
type SingleLogicCluster struct {
	ID      int64          `json:"id"`
	Name    string         `json:"name"`
	Cluster string         `json:"cluster"`
	Nodes   []string       `json:"nodes"`
	Tenants []SingleTenant `json:"tenants"`
}

type CreateLogicClusterRequest struct {
	Name    string   `json:"name"`
	Nodes   []string `json:"nodes"`
	Tenants []int64  `json:"tenants"`
}

type UpdateLogicClusterRequest = CreateLogicClusterRequest

// nsgrp
type SingleNsgrp struct {
	ID             int64            `json:"id"`
	UUID           uint32           `json:"uuid"`
	Name           string           `json:"name"`
	Cluster        string           `json:"cluster"`
	Namespaces     []string         `json:"namespaces"`
	Resources      []SingleResource `json:"resources"`
	Enabled        int              `json:"enabled"`
	Trusted        bool             `json:"trusted"`
	PolicyInfo     PolicyResponse   `json:"policyInfo"`
	TotalResources int              `json:"totalResources"`
}

type NsgrpBaseInfo struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
}

type CreateNsgrpRequest struct {
	BaseInfo   NsgrpBaseInfo            `json:"baseInfo"`
	PolicyInfo CreateNsgrpPolicyRequest `json:"policyInfo"`
}

type UpdateNsgrpRequest = CreateNsgrpRequest

// policy
type PolicyResponse struct {
	Enabled       int       `json:"enabled"`
	Rules         []Rule    `json:"rules"`
	Creator       string    `json:"creator"`
	Updater       string    `json:"updater"`
	UpdateTime    time.Time `json:"updateTime"`
	Revision      int       `json:"revision"`
	Tusted        bool      `json:"tusted"`
	Total         int       `json:"total"`
	AllowExternal bool      `json:"allowExternal"`
}

// rule
type Rule struct {
	Direction    string              `json:"direction"`
	SrcType      string              `json:"srcType"`
	SrcId        uint32              `json:"srcId"`
	SrcIPBlock   string              `json:"srcIPBlock"`
	SrcResource  SuggestionResource  `json:"srcResource"`
	SrcSegment   SuggestionSegment   `json:"srcSegment"`
	SrcNamespace SuggestionNamespace `json:"srcNamespace"`
	SrcTenant    SuggestionTenant    `json:"srcTenant"`
	SrcNsgrp     SuggestionNsgrp     `json:"srcNsgrp"`
	DstType      string              `json:"dstType"`
	DstId        uint32              `json:"dstId"`
	DstIPBlock   string              `json:"dstIPBlock"`
	DstResource  SuggestionResource  `json:"dstResource"`
	DstSegment   SuggestionSegment   `json:"dstSegment"`
	DstNamespace SuggestionNamespace `json:"dstNamespace"`
	DstTenant    SuggestionTenant    `json:"dstTenant"`
	DstNsgrp     SuggestionNsgrp     `json:"dstNsgrp"`
	Action       string              `json:"action"`
	Protocol     string              `json:"protocol"`
	Ports        string              `json:"ports"`
	Comment      string              `json:"comment"`
	IsSegRule    bool                `json:"isSegRule"`
}

type SuggestionResource struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

type SuggestionSegment struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

type SuggestionNamespace struct {
	Name    string `json:"name"`
	Cluster string `json:"cluster"`
}

type SuggestionTenant struct {
	Name    string `json:"name"`
	Cluster string `json:"cluster"`
}

type SuggestionNsgrp struct {
	Name    string `json:"name"`
	Cluster string `json:"cluster"`
}

type CommonMicroSegObject struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

type RespErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type PolicyEnabling struct {
	Enable   int `json:"enable"`
	Revision int `json:"revision"`
}
