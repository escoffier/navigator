package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ComplianceCheckType string

const (
	ComplianceCheckStatusInProgress = "inprogress"
	ComplianceCheckStatusCompleted  = "completed"
	ComplianceCheckStatusFailed     = "failed"

	ComplianceCheckTargetTypeKube   ComplianceCheckType = "kube"
	ComplianceCheckTargetTypeDocker ComplianceCheckType = "docker"
	ComplianceCheckTargetTypeHost   ComplianceCheckType = "host"
)

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

func GetMongoCollectionForCheckType(checkType ComplianceCheckType) string {
	if checkType == ComplianceCheckTargetTypeKube {
		return ComplianceCheckKubeRecordsCollection.String()
	} else if checkType == ComplianceCheckTargetTypeDocker {
		return ComplianceCheckDockerRecordsCollection.String()
	} else if checkType == ComplianceCheckTargetTypeHost {
		return ComplianceCheckHostRecordsCollection.String()
	} else {
		return ""
	}
}

func IsAnyCheckType(checkType ComplianceCheckType) bool {
	if checkType != ComplianceCheckTargetTypeKube &&
		checkType != ComplianceCheckTargetTypeDocker &&
		checkType != ComplianceCheckTargetTypeHost {
		return false
	}
	return true
}
