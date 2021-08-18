package model

import (
	"k8s.io/apiserver/pkg/apis/audit"
)

type AuditRecord struct {
	audit.Event
	Namespace          string // ObjectRef.Namespace
	ResourceKind       string // ObjectRef.Resource
	ResourceName       string // ObjectRef.Name
	ResponseStatusCode int32  // ResponseStatus.code
	RequestContent     string // RequestObject json string
	ResponseContent    string // ResponseObject json string
}

func (r *AuditRecord) ToDisplay(id string) *AuditDisplay {
	result := &AuditDisplay{}
	result.ID = id
	result.SourceIPs = r.SourceIPs
	result.Verb = r.Verb
	result.Namespace = r.Namespace
	result.ResourceKind = r.ResourceKind
	result.ResourceName = r.ResourceName
	result.ResponseStatusCode = r.ResponseStatusCode
	result.Stage = string(r.Stage)
	result.StageTimestamp = r.StageTimestamp.UnixNano() / 1e6
	result.Username = r.User.Username
	result.Level = string(r.Level)
	result.RequestReceivedTimestamp = r.RequestReceivedTimestamp.UnixNano() / 1e6
	result.UserAgent = r.UserAgent
	result.RequestURI = r.RequestURI
	result.APIVersion = r.APIVersion
	result.AuthorizationDecision = r.Annotations["authorization.k8s.io/decision"]
	result.AuthorizationReason = r.Annotations["authorization.k8s.io/reason"]
	return result
}

type AuditDisplay struct {
	ID                 string
	SourceIPs          []string
	Verb               string
	Namespace          string
	ResourceKind       string
	ResourceName       string
	ResponseStatusCode int32
	Stage              string
	StageTimestamp     int64 // StageTimestamp

	Username                 string
	Level                    string
	RequestReceivedTimestamp int64
	UserAgent                string
	RequestURI               string
	APIVersion               string
	AuthorizationDecision    string
	AuthorizationReason      string
}

type AuditLogConfig struct {
	LogEnabled bool `json:"logEnabled"`
}

var (
	DefaultAuditLogConf = &AuditLogConfig{LogEnabled: true}
)
