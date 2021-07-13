package model

import (
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	NodeTypeService  = "service"
	NodeTypeOwnerRef = "ownerReference"
)

var (
	TypeAssertErr = errors.New("type cast error")
)

type AssetContainer struct {
	MetadataEntry `json:"-" bson:",inline"`
	// PodName-Name is a "primary key"
	PodName string `json:"podName" bson:"podName"` // ind
	PodUID  string `json:"podUID" bson:"podUID"`
	Name    string `json:"name" bson:"name"` // ind

	LastUpdateTimeEpoch int64 `json:"lastUpdateTime" bson:"lastUpdateTime"` // ind

	Cluster         string `json:"cluster" bson:"cluster"`
	Namespace       string `json:"namespace" bson:"namespace"`             // ind
	PodOwnerName    string `json:"podOwnerName" bson:"podOwnerName"`       // ind
	PodOwnerKind    string `json:"podOwnerKind" bson:"podOwnerKind"`       // ind
	PodResourceName string `json:"podResourceName" bson:"podResourceName"` // The resource of this pod: could be the Deployment/StatefulSet/DaemonSet/Job...
	PodResourceKind string `json:"podResourceKind" bson:"podResourceKind"`

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

func (AssetContainer) TableName() string {
	return "assets-containers"
}

type PodServiceRelation struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Cluster       string             `json:"cluster" bson:"cluster"`
	Namespace     string             `json:"namespace" bson:"namespace"`
	Name          string             `json:"name" bson:"name"`
	PodName       string             `json:"podName" bson:"podName"`
	PodUID        string             `json:"podUid" bson:"podUid"`
	IP            string             `json:"ip"  bson:"ip"`
}

type PodOwnerRefRelation struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Cluster       string             `json:"cluster" bson:"cluster"`
	Namespace     string             `json:"namespace" bson:"namespace"`
	OwnerRefName  string             `json:"ownerRefName" bson:"ownerRefName"`
	OwnerRefKind  string             `json:"ownerRefKind" bson:"ownerRefKind"`
	PodName       string             `json:"podName" bson:"podName"`
	PodUID        string             `json:"podUid" bson:"podUid"`
	IP            string             `json:"ip"  bson:"ip"`
}
