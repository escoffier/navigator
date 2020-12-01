package model

import (
	"time"
)

// AuditConfig...
type AuditConfig struct {
	MetadataEntry   `json:"-" bson:",inline"`
	ColdStorageDays int       `json:"coldStorageDays" bson:"coldStorageDays"`
	CreatedAt       time.Time `json:"-" bson:"created_at"`
	DeletedAt       time.Time `json:"-" bson:"deleted_at,omitempty"`
}
