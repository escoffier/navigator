package alert

import "go.mongodb.org/mongo-driver/bson/primitive"

type Alert struct {
	ID           primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	Acknowledged bool               `json:"acknowledged" bson:"acknowledged"`
	ElasticID    string             `json:"elasticId" bson:"elasticId"`
	Timestamp    string             `json:"timestamp" bson:"timestamp"`
	ContainerID  string             `json:"containerId" bson:"containerId"`
	PodUID       string             `json:"podUid" bson:"podUid"`
	PodName      string             `json:"podName" bson:"podName"`
	RuleName     string             `json:"ruleName" bson:"ruleName"`
}

type ElasticAlertDocSource struct {
	Matched  ElasticAlertDocMatched `json:"match_body"`
	RuleName string                 `json:"rule_name"`
}

type ElasticAlertDocMatched struct {
	ID          string `json:"_id"`
	Timestamp   string `json:"@timestamp"`
	ContainerID string `json:"ContainerID"`
	PodUID      string `json:"PodUID"`
	PodName     string `json:"PodName"`
}
