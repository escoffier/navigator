package model

import (
	"time"
)

const (
	AuditConfigCollection = "audit"
)

// AuditConfig...
type AuditConfig struct {
	HotStorageDays  int       `json:"hotStorageDays" bson:"hotStorageDays"`
	ColdStorageDays int       `json:"coldStorageDays" bson:"coldStorageDays"`
	CreatedAt       time.Time `json:"-" bson:"created_at"`
	DeletedAt       time.Time `json:"-" bson:"deleted_at"`
	Active          bool      `json:"-" bson:"active"`
}
