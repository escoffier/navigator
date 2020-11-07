package model

import "go.mongodb.org/mongo-driver/bson/primitive"

const (
	ComplianceCheckStatusInProgress = "inprogress"
	ComplianceCheckStatusCompleted  = "completed"
	ComplianceCheckStatusFailed     = "failed"

	ComplianceCheckKubeRecordsCollection   = "kube-bench-records"
	ComplianceCheckDockerRecordsCollection = "docker-bench-records"
	ComplianceCheckHostRecordsCollection   = "host-bench-records"

	ComplianceCheckTargetTypeKube   = "kube"
	ComplianceCheckTargetTypeDocker = "docker"
	ComplianceCheckTargetTypeHost   = "host"
)

type ComplianceCheckEntryBase struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	ClusterID  string             `json:"cluster_id" bson:"clusterId"`
	Status     string             `json:"status" bson:"status,omitempty"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Logs       string             `json:"logs" bson:"logs,omitempty"`
}

func GetMongoCollectionForCheckType(checkType string) string {
	if checkType == ComplianceCheckTargetTypeKube {
		return ComplianceCheckKubeRecordsCollection
	} else if checkType == ComplianceCheckTargetTypeDocker {
		return ComplianceCheckDockerRecordsCollection
	} else if checkType == ComplianceCheckTargetTypeHost {
		return ComplianceCheckHostRecordsCollection
	} else {
		return ""
	}
}

func IsAnyCheckType(checkType string) bool {
	if checkType != ComplianceCheckTargetTypeKube &&
		checkType != ComplianceCheckTargetTypeDocker &&
		checkType != ComplianceCheckTargetTypeHost {
		return false
	}
	return true
}
