package model

import (
	"encoding/json"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var alertSortableFields = func() map[string]string {
	return map[string]string{
		"timestamp": "timestamp",
		"severity":  "severityInt",
	}
}

func GetDefaultAlertSortableName() string {
	return "timestamp"
}

func GetAlertSortableNames() []string {
	keys := make([]string, len(alertSortableFields()))

	i := 0
	for k := range alertSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

type AlertKind string

const (
	AlertModuleContainerSecurity = "ContainerSecurity"
)

type Alert struct {
	MetadataEntry        `json:"-" bson:",inline"`
	ID                   primitive.ObjectID    `json:"id" bson:"_id, omitempty"`
	AlertKind            string                `json:"kind" bson:"kind"`
	Acknowledged         bool                  `json:"acknowledged" bson:"acknowledged"`
	Timestamp            time.Time             `json:"timestamp" bson:"timestamp"`
	Severity             string                `json:"severity" bson:"severity"`
	SeverityInt          int                   `json:"severityInt" bson:"severityInt"`
	ComplianceCheckAlert *ComplianceCheckAlert `json:"complianceCheckAlert,omitempty" bson:"complianceCheckAlert,omitempty"`
	Message              string                `json:"message" bson:"message"`
	MessageEn            string                `json:"-" bson:"message_en"`
	MessageZh            string                `json:"-" bson:"message_zh"`
	Active               bool                  `json:"-" bson:"active,omitempty"`
	Cluster              string                `json:"cluster" bson:"cluster"`
	Namespace            string                `json:"namespace" bson:"namespace,omitempty"`
	Service              string                `json:"service" bson:"service,omitempty"`
	Histories            []AlertContext        `json:"histories" bson:"histories,omitempty"`
}

type AlertContext struct {
	ElasticID   string    `json:"-" bson:"elasticID"`
	ContainerID string    `json:"containerId" bson:"containerId"`
	PodName     string    `json:"podName" bson:"podName"`
	PodUID      string    `json:"podUid" bson:"podUid"`
	Active      bool      `json:"active" bson:"active"`
	Timestamp   time.Time `json:"timestamp" bson:"timestamp"`
}

type ComplianceCheckAlert struct {
	AffectedNodes *[]string `json:"affectedNodes" bson:"affectedNodes"`
	ClusterID     string    `json:"clusterID" bson:"clusterID"`
	CheckID       string    `json:"checkID" bson:"checkID"`
	CheckType     string    `json:"checkType" bson:"checkType"`
	PolicyID      string    `json:"policyID" bson:"policyID"`
}

func (a *Alert) MarshalJSON() ([]byte, error) {
	if a.ComplianceCheckAlert != nil {
		return json.Marshal(&struct {
			ID                   primitive.ObjectID    `json:"id"`
			AlertKind            string                `json:"kind"`
			Acknowledged         bool                  `json:"acknowledged"`
			Timestamp            time.Time             `json:"timestamp"`
			Severity             string                `json:"severity"`
			Message              string                `json:"message"`
			ComplianceCheckAlert *ComplianceCheckAlert `json:"data"`
			Histories            []AlertContext        `json:"histories,omitempty"`
		}{
			ID:                   a.ID,
			AlertKind:            a.AlertKind,
			Acknowledged:         a.Acknowledged,
			Timestamp:            a.Timestamp,
			Severity:             a.Severity,
			Message:              a.Message,
			ComplianceCheckAlert: a.ComplianceCheckAlert,
			Histories:            a.Histories,
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
		Cluster      string             `json:"cluster"`
		Namespace    string             `json:"namespace"`
		Service      string             `json:"service"`
		Histories    []AlertContext     `json:"histories,omitempty"`
	}{
		ID:           a.ID,
		AlertKind:    a.AlertKind,
		Acknowledged: a.Acknowledged,
		Timestamp:    a.Timestamp,
		Message:      a.Message,
		Severity:     a.Severity,
		Cluster:      a.Cluster,
		Namespace:    a.Namespace,
		Service:      a.Service,
		EmptyPayload: &struct{}{},
		Histories:    a.Histories,
	})
}
