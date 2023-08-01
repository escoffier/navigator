package hwswree

import (
	"time"
)

type Config struct {
	Type          string `json:"type"`
	RegistryID    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Insecure      bool   `json:"insecure"`
}

type Repository struct {
	Name         string    `json:"name"`
	Category     string    `json:"category"`
	Description  string    `json:"description"`
	Size         int       `json:"size"`
	IsPublic     bool      `json:"is_public"`
	NumImages    int       `json:"num_images"`
	NumDownload  int       `json:"num_download"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Logo         string    `json:"logo"`
	Url          string    `json:"url"`
	Path         string    `json:"path"`
	InternalPath string    `json:"internal_path"`
	DomainName   string    `json:"domain_name"`
	Namespace    string    `json:"namespace"`
	Tags         []string  `json:"tags"`
	Status       bool      `json:"status"`
	TotalRange   int       `json:"total_range"`
}

type Namespace struct {
	Id           int    `json:"id"`
	Name         string `json:"name"`
	CreatorName  string `json:"creator_name"`
	DomainPublic int    `json:"domain_public"`
	Auth         int    `json:"auth"`
}
