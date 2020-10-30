package alert

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Alert struct {
	ID           primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	Acknowledged bool               `json:"acknowledged" bson:"acknowledged"`
	ElasticID    string             `json:"elasticId" bson:"elasticId"`
	Timestamp    time.Time          `json:"timestamp" bson:"timestamp"`
	ContainerID  string             `json:"containerId" bson:"containerId"`
	PodUID       string             `json:"podUid" bson:"podUid"`
	PodName      string             `json:"podName" bson:"podName"`
	RuleName     string             `json:"ruleName" bson:"ruleName"`
	Cvss3Vector  string             `json:"cvss3Vector" bson:"cvss3Vector"`
	Cvss3Score   float64            `json:"cvss3Score" bson:"cvss3Score"`
}
