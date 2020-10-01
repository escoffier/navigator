package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type Cluster struct {
	ID          primitive.ObjectID   `json:"id" bson:"_id, omitempty"`
	ClusterName string               `json:"name" bson:"name"`
	KubeConfig  string               `json:"config" bson:"config"`
	CronConfig  ComplianceCronConfig `json:"cronConfig" bson:"cronConfig"`
}

type ComplianceCronConfig struct {
	KubeBenchCronString   string `json:"kubeBenchCronString" bson:"kubeBenchCronString"`
	DockerBenchCronString string `json:"dockerBenchCronString" bson:"dockerBenchCronString"`
	HostBenchCronString   string `json:"hostBenchCronString" bson:"hostBenchCronString"`
}
