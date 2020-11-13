package model

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	RuleCollection = "rules"
)

type Rule struct {
	ID            primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	Description   string             `json:"description"`
	DescriptionEn string             `json:"-" bson:"description_en"`
	DescriptionZh string             `json:"-" bson:"description_zh"`
	Name          string             `json:"name"`
	NameEn        string             `json:"-" bson:"name_en"`
	NameZh        string             `json:"-" bson:"name_zh"`
	Enabled       bool               `json:"enabled" bson:"enabled"`
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

type RuleDefinition struct {
	DescriptionEn string  `yaml:"description_en"`
	DescriptionZh string  `yaml:"description_zh"`
	NameEn        string  `yaml:"name_en"`
	NameZh        string  `yaml:"name_zh"`
	Cvss3Vector   string  `yaml:"cvss_3_vector"`
	Cvss3Score    float64 `yaml:"cvss_3_score"`
	Cvss2Vector   string  `yaml:"cvss_2_vector"`
	Cvss2Score    float64 `yaml:"cvss_2_score"`
}
