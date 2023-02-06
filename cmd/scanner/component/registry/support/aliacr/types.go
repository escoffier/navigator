package aliacr

type Config struct {
	Type          string `json:"type"`
	RegistryID    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"` // 阿里云平台的用户名
	Password      string `json:"password"` // 阿里云平台的密码
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	Domain        string `json:"domain"`
	// 阿里云平台AccessKey管理中心所生成的AccessKey
	AccessKey string `json:"access_key"`
	// 阿里云平台AccessKey管理中心所生成的AccessSecret
	AccessSecret string `json:"access_secret"`
	Insecure     bool   `json:"insecure"`
	UseType      int64  `json:"use_type"`
}

type aliACRNamespaceResp struct {
	Data struct {
		Namespaces []aliACRNamespace `json:"namespaces"`
	} `json:"data"`
	RequestID string `json:"requestId"`
}

type aliACRNamespace struct {
	Namespace       string `json:"namespace"`
	AuthorizeType   string `json:"authorizeType"`
	NamespaceStatus string `json:"namespaceStatus"`
}

type aliReposResp struct {
	Data struct {
		Page     int       `json:"page"`
		Total    int       `json:"total"`
		PageSize int       `json:"pageSize"`
		Repos    []aliRepo `json:"repos"`
	} `json:"data"`
	RequestID string `json:"requestId"`
}

type aliRepo struct {
	Summary        string `json:"summary"`
	RegionID       string `json:"regionId"`
	RepoName       string `json:"repoName"`
	RepoNamespace  string `json:"repoNamespace"`
	RepoStatus     string `json:"repoStatus"`
	RepoID         int    `json:"repoId"`
	RepoType       string `json:"repoType"`
	RepoBuildType  string `json:"repoBuildType"`
	GmtCreate      int64  `json:"gmtCreate"`
	RepoOriginType string `json:"repoOriginType"`
	GmtModified    int64  `json:"gmtModified"`
	RepoDomainList struct {
		Internal string `json:"internal"`
		Public   string `json:"public"`
		Vpc      string `json:"vpc"`
	} `json:"repoDomainList"`
	Downloads         int    `json:"downloads"`
	RepoAuthorizeType string `json:"repoAuthorizeType"`
	Logo              string `json:"logo"`
	Stars             int    `json:"stars"`
}

type aliTagResp struct {
	Data struct {
		Total    int `json:"total"`
		PageSize int `json:"pageSize"`
		Page     int `json:"page"`
		Tags     []struct {
			ImageUpdate int64  `json:"imageUpdate"`
			ImageID     string `json:"imageId"`
			Digest      string `json:"digest"`
			ImageSize   int    `json:"imageSize"`
			Tag         string `json:"tag"`
			ImageCreate int64  `json:"imageCreate"`
			Status      string `json:"status"`
		} `json:"tags"`
	} `json:"data"`
	RequestID string `json:"requestId"`
}
