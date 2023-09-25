package jfrog

type Repository struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	PackageType string `json:"packageType"`
}

type RepoImages struct {
	Repositories []string `json:"repositories"`
}

type ImageTage struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type Config struct {
	Type          string `json:"type"`
	RegistryID    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	Insecure      bool   `json:"insecure"`
}
