package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AssetContainer struct {
	MetadataEntry `json:"-" bson:",inline"`
	// PodName-Name is a "primary key"
	PodName string `json:"podName" bson:"podName"` // ind
	PodUID  string `json:"podUID" bson:"podUID"`
	Name    string `json:"name" bson:"name"` // ind

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

	DriftPrevention string `json:"driftPrevention" bson:"driftPrevention"`
	SeccompProfile  string `json:"seccompProfile" bson:"seccompProfile"`
}

type Service struct {
	MetadataEntry      `json:"-" bson:",inline"`
	Cluster            string `json:"cluster" bson:"cluster"`
	Namespace          string `json:"namespace" bson:"namespace"`
	Name               string `json:"name" bson:"name"`
	OwnerReferenceName string `json:"ownerReferenceName" bson:"ownerReferenceName"`
	PodName            string `json:"podName" bson:"podName"`
	PodUID             string `json:"podUid" bson:"podUid"`
	IP                 string `json:"ip"  bson:"ip"`
	Kind               string `json:"kind" bson:"kind"`
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

type TensorService struct {
	TensorServiceName string `json:"tensorServiceName" bson:"tensorServiceName"`
	Namespace         string `json:"namespace" bson:"namespace"`
	Cluster           string `json:"cluster" bson:"cluster"`
	OwnerReferences   []struct {
		UID  string `json:"uid" bson:"uid"`
		Name string `json:"name" bson:"name"`
		Kind string `json:"kind" bson:"kind"`
	} `json:"ownerReferences" bson:"ownerReferences"`
	Selectors   map[string]string `json:"selectors" bson:"selectors"`
	ServiceName string            `json:"serviceName" bson:"serviceName"`
	ServiceUID  string            `json:"serviceUID" bson:"serviceUID"`
	Ports       []struct {
		Port       int    `json:"port" bson:"port"`
		Protocol   string `json:"protocol" bson:"protocol"`
		TargetPort int    `json:"targetPort" bson:"targetPort"`
	} `json:"ports" bson:"ports"`
	ServiceType string `json:"serviceType" bson:"serviceType"`
	CreatedAt   int64  `json:"createdAt" bson:"createdAt"`
	UpdatedAt   int64  `json:"updatedAt" bson:"updatedAt"`
}
