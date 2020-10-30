package rule

import "go.mongodb.org/mongo-driver/bson/primitive"

type Rule struct {
	ID          primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	Description string             `json:"description"`
	Name        string             `json:"name"`
	Enabled     bool               `json:"enabled"`
	Cvss3Vector string             `json:"cvss3Vector"`
	Cvss3Score  float64            `json:"cvss3Score"`
}

type RuleDefinition struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Cvss3Vector string  `yaml:"cvss_3_vector"`
	Cvss3Score  float64 `yaml:"cvss_3_score"`
}
