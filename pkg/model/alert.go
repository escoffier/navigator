package model

import (
	"context"
	"encoding/json"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/audit"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	AlertCollection = "alerts"

	AlertKindRuntimeDetection = "runtimeDetection"
	AlertKindComplianceCheck  = "complianceCheck"
	AlertKindExploitRisk      = "exploitRisk"
)

type Alert struct {
	audit.AuditedEntry    `json:"-" bson:"auditedentry, omitempty"`
	ID                    primitive.ObjectID     `json:"id" bson:"_id, omitempty"`
	AlertKind             string                 `json:"kind" bson:"kind"`
	Acknowledged          bool                   `json:"acknowledged" bson:"acknowledged"`
	Timestamp             time.Time              `json:"timestamp" bson:"timestamp"`
	Severity              string                 `json:"severity" bson:"severity"`
	RuntimeDetectionAlert *RuntimeDetectionAlert `json:"runtimeDetectionAlert,omitempty" bson:"runtimeDetectionAlert,omitempty"`
	ComplianceCheckAlert  *ComplianceCheckAlert  `json:"complianceCheckAlert,omitempty" bson:"complianceCheckAlert,omitempty"`
	ExploitRiskAlert      *ExploitRiskAlert      `json:"exploitRiskAlert,omitempty" bson:"exploitRiskAlert,omitempty"`
	Message               string                 `json:"message" bson:"message"`
	MessageEn             string                 `json:"-" bson:"message_en"`
	MessageZh             string                 `json:"-" bson:"message_zh"`
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

func (a *Alert) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		a.Message = a.MessageZh
	} else {
		a.Message = a.MessageEn
	}
	if a.ExploitRiskAlert != nil {
		a.ExploitRiskAlert.ApplyTranslation((ctx))
	}
	if a.RuntimeDetectionAlert != nil {
		a.RuntimeDetectionAlert.ApplyTranslation((ctx))
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
		}{
			ID:                    a.ID,
			AlertKind:             a.AlertKind,
			Acknowledged:          a.Acknowledged,
			Timestamp:             a.Timestamp,
			Severity:              a.Severity,
			Message:               a.Message,
			RuntimeDetectionAlert: a.RuntimeDetectionAlert,
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
