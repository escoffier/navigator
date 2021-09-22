package harborv1

import (
	"time"
)

// Project harbor v1 api return project info
// detail: https://github.com/goharbor/harbor/blob/v1.10.1/api/harbor/swagger.yaml
type Project struct {
	Name         string    `json:"name"`
	ProjectID    int       `json:"project_id"`
	Deleted      bool      `json:"deleted"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
}

// Repository harbor v1 api return repository info
type Repository struct {
	Name         string    `json:"name"`
	ProjectID    int       `json:"project_id"`
	Description  string    `json:"description"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
	Labels       []Label   `json:"labels"`
}

type Tag struct {
	Digest   string    `json:"digest"`
	Name     string    `json:"name"`
	Size     uint      `json:"size"`
	Author   string    `json:"author"`
	Created  time.Time `json:"created"`
	PushTime time.Time `json:"push_time"`
	PullTime time.Time `json:"pull_time"`
}
type Label struct {
	Deleted bool `json:"deleted"`
}

type HarborV1Config struct {
	Type          string `json:"type"`
	RegistryId    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	Insecure      bool   `json:"insecure"`
}
