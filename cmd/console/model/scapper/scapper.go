package scapper

import (
	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Check struct {
	CheckType model.ComplianceCheckType
	CheckUUID uuid.UUID
	ClusterID string
	Namespace string
}
