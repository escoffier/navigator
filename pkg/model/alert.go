package model

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var alertSortableFields = func() map[string]string {
	return map[string]string{
		"timestamp": "timestamp",
		"severity":  "severityInt",
	}
}

func GetAlertSortableField(key string) string {
	return alertSortableFields()[key]
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
	AlertKindAny              AlertKind = "any"
	AlertKindRuntimeDetection AlertKind = "runtimeDetection"
	AlertKindComplianceCheck  AlertKind = "complianceCheck"
	AlertKindExploitRisk      AlertKind = "exploitRisk"
	AlertKindDriftPrevention  AlertKind = "driftPrevention"
)

func AlertKindFromQuery(r *http.Request) (AlertKind, error) {
	kindRaw := r.URL.Query().Get("kind")
	if kindRaw == "" {
		return AlertKindAny, nil
	}
	kind := AlertKind(kindRaw)
	if kind != AlertKindComplianceCheck && kind != AlertKindExploitRisk && kind != AlertKindRuntimeDetection && kind != AlertKindDriftPrevention {
		allowed := fmt.Sprintf("allowed: %s/%s/%s/%s", AlertKindComplianceCheck, AlertKindExploitRisk, AlertKindRuntimeDetection, AlertKindDriftPrevention)
		return AlertKindAny, NewFieldError(http.StatusBadRequest,
			fmt.Errorf("invalid kind param value (%s)", allowed),
			Suberror{"kind", allowed})
	}
	return kind, nil
}

type Alert struct {
	MetadataEntry         `json:"-" bson:",inline"`
	ID                    primitive.ObjectID     `json:"id" bson:"_id, omitempty"`
	AlertKind             string                 `json:"kind" bson:"kind"`
	Acknowledged          bool                   `json:"acknowledged" bson:"acknowledged"`
	Timestamp             time.Time              `json:"timestamp" bson:"timestamp"`
	Severity              string                 `json:"severity" bson:"severity"`
	SeverityInt           int                    `json:"severityInt" bson:"severityInt"`
	RuntimeDetectionAlert *RuntimeDetectionAlert `json:"runtimeDetectionAlert,omitempty" bson:"runtimeDetectionAlert,omitempty"`
	ComplianceCheckAlert  *ComplianceCheckAlert  `json:"complianceCheckAlert,omitempty" bson:"complianceCheckAlert,omitempty"`
	ExploitRiskAlert      *ExploitRiskAlert      `json:"exploitRiskAlert,omitempty" bson:"exploitRiskAlert,omitempty"`
	DriftPreventionAlert  *DriftPreventionAlert  `json:"driftPreventionAlert,omitempty" bson:"driftPreventionAlert,omitempty"`
	Message               string                 `json:"message" bson:"message"`
	MessageEn             string                 `json:"-" bson:"message_en"`
	MessageZh             string                 `json:"-" bson:"message_zh"`
	Active                bool                   `json:"-" bson:"active,omitempty"`
	Histories             []AlertContext         `json:"histories" bson:"histories,omitempty"`
}

type AlertContext struct {
	ElasticID   string    `json:"-" bson:"elasticID"`
	ContainerID string    `json:"containerId" bson:"containerId"`
	PodName     string    `json:"podName" bson:"podName"`
	PodUID      string    `json:"podUid" bson:"podUid"`
	Timestamp   time.Time `json:"timestamp" bson:"timestamp"`
}

type RuntimeDetectionAlert struct {
	ElasticID     string             `json:"-" bson:"elasticId"`
	ContainerID   string             `json:"containerId" bson:"containerId"`
	PodUID        string             `json:"podUid" bson:"podUid"`
	PodName       string             `json:"podName" bson:"podName"`
	Description   string             `json:"description" bson:"description"`
	DescriptionEn string             `json:"-" bson:"description_en"`
	DescriptionZh string             `json:"-" bson:"description_zh"`
	RuleID        primitive.ObjectID `json:"-" bson:"rule_id"`
	RuleName      string             `json:"ruleName" bson:"ruleName"`
	RuleNameEn    string             `json:"-" bson:"ruleName_en"`
	RuleNameZh    string             `json:"-" bson:"ruleName_zh"`
	Cvss2Vector   string             `json:"cvss2Vector" bson:"cvss2Vector"`
	Cvss2Score    float64            `json:"cvss2Score" bson:"cvss2Score"`
	Cvss3Vector   string             `json:"cvss3Vector" bson:"cvss3Vector"`
	Cvss3Score    float64            `json:"cvss3Score" bson:"cvss3Score"`
}

type ExploitRiskAlert struct {
	ElasticID     string             `json:"-" bson:"elasticId"`
	ContainerID   string             `json:"containerId" bson:"containerId"`
	Description   string             `json:"description" bson:"description"`
	DescriptionEn string             `json:"-" bson:"description_en"`
	DescriptionZh string             `json:"-" bson:"description_zh"`
	RuleID        primitive.ObjectID `json:"-" bson:"rule_id"`
	PodUID        string             `json:"podUid" bson:"podUid"`
	PodName       string             `json:"podName" bson:"podName"`
	RuleName      string             `json:"ruleName" bson:"ruleName"`
	RuleNameEn    string             `json:"-" bson:"ruleName_en"`
	RuleNameZh    string             `json:"-" bson:"ruleName_zh"`
	PID           int                `json:"pid" bson:"pid"`
}

type ComplianceCheckAlert struct {
	AffectedNodes *[]string `json:"affectedNodes" bson:"affectedNodes"`
	ClusterID     string    `json:"clusterID" bson:"clusterID"`
	CheckID       string    `json:"checkID" bson:"checkID"`
	CheckType     string    `json:"checkType" bson:"checkType"`
	PolicyID      string    `json:"policyID" bson:"policyID"`
}

type DriftPreventionAlert struct {
	AffectedPod   string `json:"affectedPod" bson:"affectedPod"`
	Filepath      string `json:"filepath" bson:"filepath"`
	CRC32Expected uint32 `json:"crc32Expected,omitempty" bson:"crc32Expected,omitempty"`
	CRC32Actual   uint32 `json:"crc32Actual,omitempty" bson:"crc32Actual,omitempty"`
	Reason        string `json:"reason" bson:"reason"`
	Action        string `json:"action" bson:"action"`
	Syscall       string `json:"syscall" bson:"syscall"`
}

func (a *Alert) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		a.Message = a.MessageZh
	} else {
		a.Message = a.MessageEn
	}
	if a.ExploitRiskAlert != nil {
		a.ExploitRiskAlert.ApplyTranslation(ctx)
	}
	if a.RuntimeDetectionAlert != nil {
		a.RuntimeDetectionAlert.ApplyTranslation(ctx)
	}
}

func (isa *RuntimeDetectionAlert) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		isa.Description = isa.DescriptionZh
		isa.RuleName = isa.RuleNameZh
	} else {
		isa.Description = isa.DescriptionEn
		isa.RuleName = isa.RuleNameEn
	}
}

func (era *ExploitRiskAlert) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		era.Description = era.DescriptionZh
		era.RuleName = era.RuleNameZh
	} else {
		era.Description = era.DescriptionEn
		era.RuleName = era.RuleNameEn
	}
}

func (a *Alert) MarshalJSON() ([]byte, error) {
	if a.RuntimeDetectionAlert != nil {
		return json.Marshal(&struct {
			ID                    primitive.ObjectID     `json:"id"`
			AlertKind             string                 `json:"kind"`
			Acknowledged          bool                   `json:"acknowledged"`
			Timestamp             time.Time              `json:"timestamp"`
			Severity              string                 `json:"severity"`
			Message               string                 `json:"message"`
			RuntimeDetectionAlert *RuntimeDetectionAlert `json:"data"`
			Histories             []AlertContext         `json:"histories,omitempty"`
		}{
			ID:                    a.ID,
			AlertKind:             a.AlertKind,
			Acknowledged:          a.Acknowledged,
			Timestamp:             a.Timestamp,
			Severity:              a.Severity,
			Message:               a.Message,
			RuntimeDetectionAlert: a.RuntimeDetectionAlert,
			Histories:             a.Histories,
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
	} else if a.ExploitRiskAlert != nil {
		return json.Marshal(&struct {
			ID               primitive.ObjectID `json:"id"`
			AlertKind        string             `json:"kind"`
			Acknowledged     bool               `json:"acknowledged"`
			Timestamp        time.Time          `json:"timestamp"`
			Severity         string             `json:"severity"`
			Message          string             `json:"message"`
			ExploitRiskAlert *ExploitRiskAlert  `json:"data"`
			Histories        []AlertContext     `json:"histories,omitempty"`
		}{
			ID:               a.ID,
			AlertKind:        a.AlertKind,
			Acknowledged:     a.Acknowledged,
			Message:          a.Message,
			Timestamp:        a.Timestamp,
			Severity:         a.Severity,
			ExploitRiskAlert: a.ExploitRiskAlert,
			Histories:        a.Histories,
		})
	} else if a.DriftPreventionAlert != nil {
		return json.Marshal(&struct {
			ID                   primitive.ObjectID    `json:"id"`
			AlertKind            string                `json:"kind"`
			Acknowledged         bool                  `json:"acknowledged"`
			Timestamp            time.Time             `json:"timestamp"`
			Severity             string                `json:"severity"`
			Message              string                `json:"message"`
			DriftPreventionAlert *DriftPreventionAlert `json:"data"`
		}{
			ID:                   a.ID,
			AlertKind:            a.AlertKind,
			Acknowledged:         a.Acknowledged,
			Message:              a.Message,
			Timestamp:            a.Timestamp,
			Severity:             a.Severity,
			DriftPreventionAlert: a.DriftPreventionAlert,
		})
	} else if a.DriftPreventionAlert != nil {
		return json.Marshal(&struct {
			ID                   primitive.ObjectID    `json:"id"`
			AlertKind            string                `json:"kind"`
			Acknowledged         bool                  `json:"acknowledged"`
			Timestamp            time.Time             `json:"timestamp"`
			Severity             string                `json:"severity"`
			Message              string                `json:"message"`
			DriftPreventionAlert *DriftPreventionAlert `json:"data"`
		}{
			ID:                   a.ID,
			AlertKind:            a.AlertKind,
			Acknowledged:         a.Acknowledged,
			Message:              a.Message,
			Timestamp:            a.Timestamp,
			Severity:             a.Severity,
			DriftPreventionAlert: a.DriftPreventionAlert,
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
		Histories    []AlertContext     `json:"histories,omitempty"`
	}{
		ID:           a.ID,
		AlertKind:    a.AlertKind,
		Acknowledged: a.Acknowledged,
		Timestamp:    a.Timestamp,
		Message:      a.Message,
		Severity:     a.Severity,
		EmptyPayload: &struct{}{},
		Histories:    a.Histories,
	})
}
