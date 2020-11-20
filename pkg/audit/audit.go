package audit

import "time"

// AuditedEntry
type AuditedEntry struct {
	AuditTimestamp time.Time `json:"-" bson:"audit_timestamp,omitempty"`
}
