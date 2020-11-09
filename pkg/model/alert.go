package model

import (
	"encoding/json"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	AlertCollection = "alerts"

	AlertKindImageScan       = "imageScan"
	AlertKindComplianceCheck = "complianceCheck"
)

type Alert struct {
	ID                   primitive.ObjectID    `json:"id" bson:"_id, omitempty"`
	AlertKind            string                `json:"kind" bson:"kind"`
	Acknowledged         bool                  `json:"acknowledged" bson:"acknowledged"`
	Timestamp            time.Time             `json:"timestamp" bson:"timestamp"`
	Severity             string                `json:"severity" bson:"severity"`
	ImageScanAlert       *ImageScanAlert       `json:"imageScanAlert,omitempty" bson:"imageScanAlert,omitempty"`
	ComplianceCheckAlert *ComplianceCheckAlert `json:"complianceCheckAlert,omitempty" bson:"complianceCheckAlert,omitempty"`
}

type ImageScanAlert struct {
	ElasticID   string  `json:"elasticId" bson:"elasticId"`
	ContainerID string  `json:"containerId" bson:"containerId"`
	PodUID      string  `json:"podUid" bson:"podUid"`
	PodName     string  `json:"podName" bson:"podName"`
	RuleName    string  `json:"ruleName" bson:"ruleName"`
	Cvss3Vector string  `json:"cvss3Vector" bson:"cvss3Vector"`
	Cvss3Score  float64 `json:"cvss3Score" bson:"cvss3Score"`
}

type ComplianceCheckAlert struct {
	AffectedNodes *[]string `json:"affectedNodes" bson:"affectedNodes"`
	ClusterID     string    `json:"clusterID" bson:"clusterID"`
	CheckID       string    `json:"checkID" bson:"checkID"`
	CheckType     string    `json:"checkType" bson:"checkType"`
	PolicyID      string    `json:"policyID" bson:"policyID"`
	Message       string    `json:"message" bson:"message"`
}

func (a *Alert) MarshalJSON() ([]byte, error) {
	if a.ImageScanAlert != nil {
		return json.Marshal(&struct {
			ID             primitive.ObjectID `json:"id"`
			AlertKind      string             `json:"kind"`
			Acknowledged   bool               `json:"acknowledged"`
			Timestamp      time.Time          `json:"timestamp"`
			ImageScanAlert *ImageScanAlert    `json:"data"`
		}{
			ID:           a.ID,
			AlertKind:    a.AlertKind,
			Acknowledged: a.Acknowledged,
			Timestamp:    a.Timestamp,
			// Severity add TODO
			ImageScanAlert: a.ImageScanAlert,
		})
	} else if a.ComplianceCheckAlert != nil {
		return json.Marshal(&struct {
			ID                   primitive.ObjectID    `json:"id"`
			AlertKind            string                `json:"kind"`
			Acknowledged         bool                  `json:"acknowledged"`
			Timestamp            time.Time             `json:"timestamp"`
			Severity             string                `json:"severity"`
			ComplianceCheckAlert *ComplianceCheckAlert `json:"data"`
		}{
			ID:                   a.ID,
			AlertKind:            a.AlertKind,
			Acknowledged:         a.Acknowledged,
			Timestamp:            a.Timestamp,
			Severity:             a.Severity,
			ComplianceCheckAlert: a.ComplianceCheckAlert,
		})
	}
	return json.Marshal(&struct {
		ID           primitive.ObjectID `json:"id"`
		AlertKind    string             `json:"kind"`
		Acknowledged bool               `json:"acknowledged"`
		Timestamp    time.Time          `json:"timestamp"`
		Severity     string             `json:"severity"`
		EmptyPayload *struct{}          `json:"data"`
	}{
		ID:           a.ID,
		AlertKind:    a.AlertKind,
		Acknowledged: a.Acknowledged,
		Timestamp:    a.Timestamp,
		Severity:     a.Severity,
		EmptyPayload: &struct{}{},
	})
}
