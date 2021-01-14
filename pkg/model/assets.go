package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AssetContainer struct {
	MetadataEntry `json:"-" bson:",inline"`
	// PodName-Name is a "primary key"
	PodName string `json:"podName" bson:"podName"` // ind
	Name    string `json:"name" bson:"name"`       // ind

	LastUpdateTimeEpoch int64 `json:"lastUpdateTime" bson:"lastUpdateTime"` // ind

	Namespace    string `json:"namespace" bson:"namespace"`       // ind
	PodOwnerName string `json:"podOwnerName" bson:"podOwnerName"` // ind
	PodOwnerKind string `json:"podOwnerKind" bson:"podOwnerKind"` // ind

	IsDeleted bool `json:"isDeleted" bson:"isDeleted"` // ind

	Repository  string `json:"repository" bson:"repository"`
	Tag         string `json:"tag" bson:"tag"`
	Digest      string `json:"digest" bson:"digest"`
	Node        string `json:"node" bson:"node"`
	State       string `json:"state" bson:"state"`
	ContainerID string `json:"containerID" bson:"containerID"` // optional

	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty" bson:"vulnerabilities,omitempty"`
	SensitiveFiles  []Sensitive         `json:"sensitiveFiles,omitempty" bson:"sensitiveFiles,omitempty"`
	WasScanned      bool                `json:"wasScanned" bson:"wasScanned"`
	HarborURL       string              `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	TaskID          primitive.ObjectID  `json:"taskID,omitempty" bson:"taskID,omitempty"`
	TopVulns        []VulnerabilityInfo `json:"topVulnerabilities,omitempty" bson:"topVulnerabilities,omitempty"`
	OverallSeverity string              `json:"overallSeverity,omitempty" bson:"overallSeverity,omitempty"`
}

type Service struct {
	Namespace string `json:"namespace" bson:"namespace"`
	Name      string `json:"name" bson:"name"`
	PodName   string `json:"podName" bson:"podName"`
	IP        string `json:"ip"  bson:"ip"`
}
