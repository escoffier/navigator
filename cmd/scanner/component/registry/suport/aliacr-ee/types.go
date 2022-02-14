package aliacree

type Config struct {
	Type       string `json:"type"`
	RegistryID int64  `json:"registry_id"`
	URL        string `json:"url"`

	// 阿里云平台的用户名
	Username string `json:"username"`
	// 阿里云平台的密码
	Password string `json:"password"`

	SkipTLSVerify bool   `json:"skip_tls_verify"`
	RegionID      string `json:"region_id"`
	Domain        string `json:"domain"`

	// 阿里云平台AccessKey管理中心所生成的AccessKey
	AccessKey string `json:"access_key"`

	// 阿里云平台AccessKey管理中心所生成的AccessSecret
	AccessSecret string `json:"access_secret"`
	Insecure     bool   `json:"insecure"`
	InstanceID   string `json:"instance_id"`
}

type HTTPResponse struct {
	Instances    []Instance   `json:"Instances"`
	Namespaces   []Namespace  `json:"Namespaces"`
	Repositories []Repository `json:"Repositories"`
	Images       []Image      `json:"Images"`
	IsSuccess    bool         `json:"IsSuccess"`
	RequestID    string       `json:"requestId"`
	TotalCount   int64        `json:"TotalCount"`
	PageSize     int64        `json:"PageSize"`
	PageNo       int64        `json:"PageNo"`
	Code         string       `json:"Code"`
	Message      string       `json:"Message"`
}

type Instance struct {
	InstanceName          string `json:"InstanceName"`
	InstanceID            string `json:"InstanceId"`
	InstanceStatus        string `json:"InstanceStatus"`
	RegionID              string `json:"RegionId"`
	InstanceSpecification string `json:"InstanceSpecification"`
}

type Namespace struct {
	NamespaceName   string `json:"NamespaceName"`
	NamespaceStatus string `json:"NamespaceStatus"`
	DefaultRepoType string `json:"DefaultRepoType"`
	AutoCreateRepo  bool   `json:"AutoCreateRepo"`
	InstanceID      string `json:"InstanceId"`
	NamespaceID     string `json:"NamespaceId"`
}

type Repository struct {
	RepoNamespaceName string `json:"RepoNamespaceName"`
	TagImmutability   bool   `json:"TagImmutability"`
	RepoBuildType     string `json:"RepoBuildType"`
	RepoStatus        string `json:"RepoStatus"`
	RepoType          string `json:"RepoType"`
	InstanceID        string `json:"InstanceId"`
	RepoName          string `json:"RepoName"`
	Summary           string `json:"Summary"`
	RepoID            string `json:"RepoId"`
}

type Image struct {
	Status      string `json:"status"`
	ImageCreate int64  `json:"ImageCreate"`
	ImageSize   int64  `json:"ImageSize"`
	ImageUpdate int64  `json:"ImageUpdate"`
	Digest      string `json:"Digest"`
	ImageID     string `json:"ImageId"`
	Tag         string `json:"Tag"`
}
