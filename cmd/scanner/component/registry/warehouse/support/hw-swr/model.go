package hwswr

type Config struct {
	Type          string `json:"type"`
	RegistryID    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"` // 根据华为云的算法生成的新的username
	Password      string `json:"password"` // 根据华为云的算法生成新的password
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	AccessKey     string `json:"access_key"` // 页面上的username 转化为accessKey
	SecretKey     string `json:"secret_key"` // 页面上的password 转化为secretKey
	Insecure      bool   `json:"insecure"`
}
