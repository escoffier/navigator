package scapper

import uuid "github.com/satori/go.uuid"

type Check struct {
	CheckType string
	CheckUUID uuid.UUID
	ClusterID string
	Namespace string
}
