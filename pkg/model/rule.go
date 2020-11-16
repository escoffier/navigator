package model

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	RuleCollection           = "rules"
	RuleDefinitionCollection = "rulesDefinitions"
)

// Rule ...
type Rule struct {
	ID            primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	CreatedAt     time.Time          `json:"-" bson:"created_at"`
	DeletedAt     time.Time          `json:"-" bson:"deleted_at"`
	Description   string             `json:"description"`
	DescriptionEn string             `json:"-" bson:"description_en"`
	DescriptionZh string             `json:"-" bson:"description_zh"`
	Name          string             `json:"name"`
	NameEn        string             `json:"-" bson:"name_en"`
	NameZh        string             `json:"-" bson:"name_zh"`
	Enabled       bool               `json:"enabled" bson:"enabled"`
	Active        bool               `json:"-" bson:"active"`
	Cvss3Vector   string             `json:"cvss3Vector" bson:"cvss3Vector"`
	Cvss3Score    float64            `json:"cvss3Score" bson:"cvss3Score"`
	Cvss2Vector   string             `json:"cvss2Vector" bson:"cvss2Vector"`
	Cvss2Score    float64            `json:"cvss2Score" bson:"cvss2Score"`
}

func (r *Rule) ApplyTranslation(ctx context.Context) {
	if lang.Language(ctx) == lang.LanguageZH {
		r.Name = r.NameZh
		r.Description = r.DescriptionZh
	} else {
		r.Name = r.NameEn
		r.Description = r.DescriptionEn
	}
}

// RuleDefinition ...
type RuleDefinition struct {
	ID            primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	DescriptionEn string             `json:"description_en" bson:"description_en" yaml:"description_en"`
	DescriptionZh string             `json:"description_zh" bson:"description_zh" yaml:"description_zh"`
	NameEn        string             `json:"name_en" bson:"name_en" yaml:"name_en"`
	NameZh        string             `json:"name_zh" bson:"name_zh" yaml:"name_zh"`
	Cvss3Vector   string             `json:"cvss3Vector" bson:"cvss3Vector" yaml:"cvss_3_vector"`
	Cvss3Score    float64            `json:"cvss3Score" bson:"cvss3Score" yaml:"cvss_3_score"`
	Cvss2Vector   string             `json:"cvss2Vector" bson:"cvss2Vector" yaml:"cvss_2_vector"`
	Cvss2Score    float64            `json:"cvss2Score" bson:"cvss2Score" yaml:"cvss_2_score"`
}
