package registry

import (
	"time"
)

// Namespace dev/nginx:1.20, "dev" is the namespace
type Namespace struct {
	Name			string
	Description		string
	CreationTime 	time.Time
	UpdateTime 		time.Time
}

// Repository dev/nginx:1.20, "nginx" is the repository
type Repository struct {
	Name			string
	NameSpace		string
	Description		string
	PullCount 		uint
	CreationTime 	time.Time
	UpdateTime 		time.Time
}

// Tag dev/nginx:1.20, "1.20" is the tag
type Tag struct {
	Name 			string
	Digest 			string
	PushTime 		time.Time
	PullTime 		time.Time
}

// Image dev/nginx:1.20, this is the image
type Image struct {
	RegistryId   uint
	ImageDigest  string
	Repository   string
	Tag          string
	Size         uint
	Created      time.Time
	LastPushTime time.Time
	LastPullTime time.Time
	ManifestV2   string
	ManifestV1   string
	ConfigJson   string
	Status       uint
	Message      string
}
