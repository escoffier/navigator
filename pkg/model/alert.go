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
	AlertKindExploitRisk     = "exploitRisk"
)

type Alert struct {
	ID                   primitive.ObjectID    `json:"id" bson:"_id, omitempty"`
	AlertKind            string                `json:"kind" bson:"kind"`
	Acknowledged         bool                  `json:"acknowledged" bson:"acknowledged"`
	Timestamp            time.Time             `json:"timestamp" bson:"timestamp"`
	Severity             string                `json:"severity" bson:"severity"`
	ImageScanAlert       *ImageScanAlert       `json:"imageScanAlert,omitempty" bson:"imageScanAlert,omitempty"`
	ComplianceCheckAlert *ComplianceCheckAlert `json:"complianceCheckAlert,omitempty" bson:"complianceCheckAlert,omitempty"`
	ExploitRiskAlert     *ExploitRiskAlert     `json:"exploitRiskAlert,omitempty" bson:"exploitRiskAlert,omitempty"`
	Message              string                `json:"message" bson:"message"`
}

type ImageScanAlert struct {
	ElasticID   string  `json:"elasticId" bson:"elasticId"`
	ContainerID string  `json:"containerId" bson:"containerId"`
	PodUID      string  `json:"podUid" bson:"podUid"`
	PodName     string  `json:"podName" bson:"podName"`
	Description string  `json:"description" bson:"description"`
	RuleName    string  `json:"ruleName" bson:"ruleName"`
	Cvss2Vector string  `json:"cvss2Vector" bson:"cvss2Vector"`
	Cvss2Score  float64 `json:"cvss2Score" bson:"cvss2Score"`
	Cvss3Vector string  `json:"cvss3Vector" bson:"cvss3Vector"`
	Cvss3Score  float64 `json:"cvss3Score" bson:"cvss3Score"`
}

type ExploitRiskAlert struct {
	ElasticID   string `json:"elasticId" bson:"elasticId"`
	ContainerID string `json:"containerId" bson:"containerId"`
	Description string `json:"description" bson:"description"`
	PodUID      string `json:"podUid" bson:"podUid"`
	PodName     string `json:"podName" bson:"podName"`
	RuleName    string `json:"ruleName" bson:"ruleName"`
	PID         int    `json:"pid" bson:"pid"`
}

type ComplianceCheckAlert struct {
	AffectedNodes *[]string `json:"affectedNodes" bson:"affectedNodes"`
	ClusterID     string    `json:"clusterID" bson:"clusterID"`
	CheckID       string    `json:"checkID" bson:"checkID"`
	CheckType     string    `json:"checkType" bson:"checkType"`
	PolicyID      string    `json:"policyID" bson:"policyID"`
}

func (a *Alert) MarshalJSON() ([]byte, error) {
	if a.ImageScanAlert != nil {
		return json.Marshal(&struct {
			ID             primitive.ObjectID `json:"id"`
			AlertKind      string             `json:"kind"`
			Acknowledged   bool               `json:"acknowledged"`
			Timestamp      time.Time          `json:"timestamp"`
			Severity       string             `json:"severity"`
			Message        string             `json:"message"`
			ImageScanAlert *ImageScanAlert    `json:"data"`
		}{
			ID:             a.ID,
			AlertKind:      a.AlertKind,
			Acknowledged:   a.Acknowledged,
			Timestamp:      a.Timestamp,
			Severity:       a.Severity,
			Message:        a.Message,
			ImageScanAlert: a.ImageScanAlert,
		})
	} else if a.ComplianceCheckAlert != nil {
		return json.Marshal(&struct {
			ID                   primitive.ObjectID    `json:"id"`
			AlertKind            string                `json:"kind"`
			Acknowledged         bool                  `json:"acknowledged"`
			Timestamp            time.Time             `json:"timestamp"`
			Severity             string                `json:"severity"`
			Message              string                `json:"message"`
			ComplianceCheckAlert *ComplianceCheckAlert `json:"data"`
		}{
			ID:                   a.ID,
			AlertKind:            a.AlertKind,
			Acknowledged:         a.Acknowledged,
			Timestamp:            a.Timestamp,
			Severity:             a.Severity,
			Message:              a.Message,
			ComplianceCheckAlert: a.ComplianceCheckAlert,
		})
	} else if a.ExploitRiskAlert != nil {
		return json.Marshal(&struct {
			ID               primitive.ObjectID `json:"id"`
			AlertKind        string             `json:"kind"`
			Acknowledged     bool               `json:"acknowledged"`
			Timestamp        time.Time          `json:"timestamp"`
			Severity         string             `json:"severity"`
			Message          string             `json:"message"`
			ExploitRiskAlert *ExploitRiskAlert  `json:"data"`
		}{
			ID:               a.ID,
			AlertKind:        a.AlertKind,
			Acknowledged:     a.Acknowledged,
			Message:          a.Message,
			Timestamp:        a.Timestamp,
			Severity:         a.Severity,
			ExploitRiskAlert: a.ExploitRiskAlert,
		})
	}
	return json.Marshal(&struct {
		ID           primitive.ObjectID `json:"id"`
		AlertKind    string             `json:"kind"`
		Acknowledged bool               `json:"acknowledged"`
		Message      string             `json:"message"`
		Timestamp    time.Time          `json:"timestamp"`
		Severity     string             `json:"severity"`
		EmptyPayload *struct{}          `json:"data"`
	}{
		ID:           a.ID,
		AlertKind:    a.AlertKind,
		Acknowledged: a.Acknowledged,
		Timestamp:    a.Timestamp,
		Message:      a.Message,
		Severity:     a.Severity,
		EmptyPayload: &struct{}{},
	})
}
