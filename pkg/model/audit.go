package model

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/metadata"
)

const (
	AuditConfigCollection = "audit"
)

// AuditConfig...
type AuditConfig struct {
	metadata.MetadataEntry `json:"-" bson:",inline"`
	ColdStorageDays        int       `json:"coldStorageDays" bson:"coldStorageDays"`
	CreatedAt              time.Time `json:"-" bson:"created_at"`
	DeletedAt              time.Time `json:"-" bson:"deleted_at,omitempty"`
}
