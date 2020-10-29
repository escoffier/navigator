package model

const (
	AssetsContainerCollection = "assets-containers"
)

type AssetContainer struct {
	// PodName-Name is a "primary key"
	PodName string `json:"podName" bson:"podName"` // ind
	Name    string `json:"name" bson:"name"`       // ind

	LastUpdateTimeEpoch int64 `json:"lastUpdateTime" bson:"lastUpdateTime"` // ind

	PodOwnerName string `json:"podOwnerName" bson:"podOwnerName"` // ind
	PodOwnerKind string `json:"podOwnerKind" bson:"podOwnerKind"` // ind

	IsDeleted bool `json:"isDeleted" bson:"isDeleted"` // ind

	Repository  string `json:"repository" bson:"repository"`
	Tag         string `json:"tag" bson:"tag"`
	Digest      string `json:"digest" bson:"digest"`
	Namespace   string `json:"namespace" bson:"namespace"`
	Node        string `json:"node" bson:"node"`
	State       string `json:"state" bson:"state"`
	ContainerID string `json:"containerID" bson:"containerID"` // optional
}
