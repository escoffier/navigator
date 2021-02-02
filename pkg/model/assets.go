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

	Cluster      string `json:"cluster" bson:"cluster"`
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
	Image       string `json:"image" bson:"image"`

	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty" bson:"vulnerabilities,omitempty"`
	SensitiveFiles  []Sensitive         `json:"sensitiveFiles,omitempty" bson:"sensitiveFiles,omitempty"`
	WasScanned      bool                `json:"wasScanned" bson:"wasScanned"`
	HarborURL       string              `json:"harborURL,omitempty" bson:"harborURL,omitempty"`
	TaskID          primitive.ObjectID  `json:"taskID,omitempty" bson:"taskID,omitempty"`
	TopVulns        []VulnerabilityInfo `json:"topVulnerabilities,omitempty" bson:"topVulnerabilities,omitempty"`
	OverallSeverity string              `json:"overallSeverity,omitempty" bson:"overallSeverity,omitempty"`
}

type Service struct {
	MetadataEntry `json:"-" bson:",inline"`
	Cluster       string `json:"cluster" bson:"cluster"`
	Namespace     string `json:"namespace" bson:"namespace"`
	Name          string `json:"name" bson:"name"`
	PodName       string `json:"podName" bson:"podName"`
	PodUID        string `json:"podUid" bson:"podUid"`
	IP            string `json:"ip"  bson:"ip"`
	Type          string `json:"type" bson:"type"`
	Kind          string `json:"kind" bson:"kind"`
}

type ServiceRelation struct {
	Cluster   string `json:"cluster" bson:"cluster"`
	Namespace string `json:"namespace" bson:"namespace"`
	Name      string `json:"name" bson:"name"`
	FocusName string `json:"focusName,omitempty" bson:"focusName,omitempty"`
	ResName   string `json:"resName,omitempty"  bson:"resName,omitempty"`
}

type ServiceAlias struct {
	MetadataEntry `json:"-" bson:",inline"`
	Cluster       string `json:"cluster" bson:"cluster"`
	Namespace     string `json:"namespace" bson:"namespace"`
	Name          string `json:"name" bson:"name"`
	AliasName     string `json:"aliasName,omitempty" bson:"aliasName,omitempty"`
}
