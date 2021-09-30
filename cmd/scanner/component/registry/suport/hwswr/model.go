package hwswr

type HwSwrConfig struct {
	Type          string `json:"type"`
	RegistryId    int64  `json:"registry_id"`
	URL           string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Region        string `json:"region"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	Insecure      bool   `json:"insecure"`
}
