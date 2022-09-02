package model

import (
	"database/sql/driver"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ComplianceCheckType string
type ScanState uint8

func (s *ScanState) Scan(value interface{}) error {
	if t, ok := value.(int64); ok && t >= 0 && t <= 3 {
		*s = ScanState(t)
		return nil
	} else {
		return fmt.Errorf("invaild ScanState: %v", value)
	}
}

func (s ScanState) Value() (driver.Value, error) {
	switch s {
	case ScanStateCompleted, ScanStateInProgress, ScanStateFailed, ScanStateUnknown:
		return int64(s), nil
	default:
		return nil, fmt.Errorf("invalid scan state value: %v", s)
	}
}

const (
	ScanStateCompleted  ScanState = 0
	ScanStateInProgress ScanState = 1
	ScanStateFailed     ScanState = 2
	ScanStateUnknown    ScanState = 3

	ComplianceCheckTargetTypeKube   ComplianceCheckType = "kube"
	ComplianceCheckTargetTypeDocker ComplianceCheckType = "docker"
	ComplianceCheckTargetTypeHost   ComplianceCheckType = "host"
)

func GetModeScanType(checkType string) uint8 {
	var t uint8

	switch ComplianceCheckType(checkType) {
	case ComplianceCheckTargetTypeKube:
		t = 1
	case ComplianceCheckTargetTypeDocker:
		t = 2
	case ComplianceCheckTargetTypeHost:
		t = 3
	}
	return t

}

type ComplianceCronConfig struct {
	ClusterKey      string     `json:"clusterKey"`
	KubeBenchCron   CronConfig `json:"kubeBenchCron"`
	DockerBenchCron CronConfig `json:"dockerBenchCron"`
	HostBenchCron   CronConfig `json:"hostBenchCron"`
}

type CronConfig struct {
	CronString string     `json:"cronString" `
	CronID     int        `json:"cronID"`
	PrevRun    *time.Time `json:"prevRun"`
	NextRun    *time.Time `json:"nextRun"`
}

type ComplianceCheckEntryBase struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID       string             `json:"check_id" bson:"checkId"`
	NodeName      string             `json:"node_name" bson:"nodeName"`
	ClusterID     string             `json:"cluster_id" bson:"clusterId"`
	Status        string             `json:"status" bson:"status,omitempty"`
	CreatedAt     int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt    int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Logs          string             `json:"logs" bson:"logs,omitempty"`
}

func IsAnyCheckType(checkType ComplianceCheckType) bool {
	if checkType != ComplianceCheckTargetTypeKube &&
		checkType != ComplianceCheckTargetTypeDocker &&
		checkType != ComplianceCheckTargetTypeHost {
		return false
	}
	return true
}
