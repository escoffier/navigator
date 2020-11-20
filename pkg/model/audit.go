package model

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/audit"
)

const (
	AuditConfigCollection = "audit"
)

// AuditConfig...
type AuditConfig struct {
	audit.AuditedEntry `json:"-" bson:"auditedentry, omitempty"`
	ColdStorageDays    int       `json:"coldStorageDays" bson:"coldStorageDays"`
	CreatedAt          time.Time `json:"-" bson:"created_at"`
	DeletedAt          time.Time `json:"-" bson:"deleted_at"`
	Active             bool      `json:"-" bson:"active"`
}
