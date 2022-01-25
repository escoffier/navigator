package docker

import (
	"time"
)

// Repository registry v2 api return repository info
type Repository struct {
	Name         string    `json:"name"`
	ProjectID    int       `json:"project_id"`
	Description  string    `json:"description"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
}

// Tag registry v2 api return tag info
type Tag struct {
	Digest   string    `json:"digest"`
	Name     string    `json:"name"`
	Size     uint      `json:"size"`
	Author   string    `json:"author"`
	PushTime time.Time `json:"push_time"`
	PullTime time.Time `json:"pull_time"`
}

type RegisterConfig struct {
	Type          string `json:"type"`
	RegistryID    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	Insecure      bool   `json:"insecure"`
}
