package harborv2

import (
	"time"
)

// Project harbor v2 api return project info
// detail: https://editor.swagger.io/?url=https://raw.githubusercontent.com/goharbor/harbor/master/api/v2.0/swagger.yaml
type Project struct {
	Name         string    `json:"name"`
	ProjectID    int       `json:"project_id"`
	Deleted      bool      `json:"deleted"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
}

// Repository harbor v2 api return repository info
type Repository struct {
	Name         string    `json:"name"`
	ProjectID    int       `json:"project_id"`
	Description  string    `json:"description"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
}

// Artifact harbor v2 api return artifact, one artifact can relate to multi tags
type Artifact struct {
	Digest     string `json:"digest"`
	Size       uint   `json:"size"`
	ExtraAttrs Extra  `json:"extra_attrs"`
	Tags       []Tag  `json:"tags"`
}

type Extra struct {
	Created time.Time `json:"created"`
	Author  string    `json:"author"`
}

type Tag struct {
	Name     string    `json:"name"`
	PushTime time.Time `json:"push_time"`
	PullTime time.Time `json:"pull_time"`
}
type HarborV2Config struct {
	Type          string `json:"type"`
	RegistryId    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	Insecure      bool   `json:"insecure"`
}
