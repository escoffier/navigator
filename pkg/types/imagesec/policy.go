package imagesec

// ImageScope 漏洞安全策略镜像规则生效范围
type ImageScope struct {
	Enabled bool   `json:"enabled"`
	Regexp  string `json:"regexp"`
}

// ClusterScope 漏洞安全策略集群生效范围
type ClusterScope struct {
	Enabled    bool   `json:"enabled"`
	ClusterKey string `json:"clusterKey"`
}

// VulnRule 漏洞安全策略
type VulnRule struct {
	Enabled           bool     `json:"enabled"`
	Severity          string   `json:"severity"`
	IDBlackList       []string `json:"IDBlackList"`
	IDWhiteList       []string `json:"IDWhiteList"`
	IgnoreUnfixed     bool     `json:"ignoreUnfixed"`
	IgnoreLangPkgVuln bool     `json:"ignoreLangPkgVuln"`
}

// VulnRuleResult 漏洞安全策略命中结果
type VulnRuleResult struct {
	Severity          []VulnerabilityBrief `json:"severityResults"` // 按漏洞严重级别匹配的结果
	IDBlackList       []VulnerabilityBrief `json:"IDBlackList"`     // 命中漏洞id黑名单规则的漏洞
	IDWhiteList       []VulnerabilityBrief `json:"IDWhiteList"`     // 命中漏洞id白名单规则的漏洞
	IgnoreUnfixed     []VulnerabilityBrief `json:"ignoreUnfixed"`   //
	IgnoreLangPkgVuln []VulnerabilityBrief `json:"IgnoreLangPkgVuln"`
}

// MalwareRule 恶意文件规则
type MalwareRule struct {
	Enabled           bool     `json:"enabled"`
	FileNameWhiteList []string `json:"fileNameWhiteList"`
}

type Malware struct {
	Filename    string `json:"filename"`    // 文件名
	Hash        string `json:"hash"`        // hash值
	MalwareName string `json:"malwareName"` // 恶意软件名字
	Layer       string `json:"layer"`
}

// MalwareRuleResult 恶意文件策略检测结果
type MalwareRuleResult struct {
	Malwares          []Malware `json:"malwares"`
	FileNameWhiteList []Malware `json:"fileNameWhiteList"`
}

// SensitiveFileRule 敏感文件检测规则
type SensitiveFileRule struct {
	Enabled          bool     `json:"enabled"`
	NameRegBlackList []string `json:"nameRegBlackList"`
	NameRegWhiteList []string `json:"nameRegWhiteList"`
}

// SensitiveFileRuleResult 敏感文件检测结果
type SensitiveFileRuleResult struct {
	BlackListFiles []SensitiveFile `json:"blackListFiles"`
	WhiteListFiles []SensitiveFile `json:"whiteListFiles"`
}

// WebshellRule webshell策略规则
type WebshellRule struct {
	Enabled            bool     `json:"enabled"`
	RiskLevelBlackList []string `json:"riskLevel"`
}

// WebshellRuleResult webshell规则检测结果
type WebshellRuleResult struct {
	Webshells []HmWebshell `json:"webshells"`
}

// PkgVersionRule 软件包策略规则
type PkgVersionRule struct {
	Enabled   bool      `json:"enabled"`
	BlackList []Package `json:"blackList"`
}

// PkgVersionRuleResult 软件包策略检测结果
type PkgVersionRuleResult struct {
	Packages []Package `json:"packages"`
}

// PkgLicenseRule 软件包协议策略
type PkgLicenseRule struct {
	Enabled   bool     `json:"enabled"`
	BlackList []string `json:"blackList"`
}

// PkgLicenseRuleResult 软件包协议检测结果
type PkgLicenseRuleResult struct {
	Packages []Package `json:"packages"`
}

// EnvRule 环境变量策略
type EnvRule struct {
	Enabled         bool     `json:"enabled"`
	ContainPassWord bool     `json:"containPassWord"`
	NameBlackList   []string `json:"nameBlackList"`
}

// EnvRuleResult 环境变量规则检测结果
type EnvRuleResult struct {
	NameBlackList []string `json:"nameBlackList"`
	PassWordEnvs  []string `json:"passWordEnvs"`
}

// RootUserRule 镜像是否为root用户
type RootUserRule struct {
	Enabled bool `json:"enabled"`
}

// RootUserRuleResult 镜像root用户检测结果
type RootUserRuleResult struct {
	IsRoot bool `json:"isRoot"`
}

// SecPolicy 安全策略
type SecPolicy struct {
	PolicyID          string            `json:"policyID"` // 策略id
	Version           string            `json:"version"`  // 策略版本
	ImageScope        ImageScope        `json:"imageScope"`
	ClusterScope      ClusterScope      `json:"clusterScope"`
	VulnRule          VulnRule          `json:"vulnerabilityRule"`
	MalwareRule       MalwareRule       `json:"malwareRule"`
	WebshellRule      WebshellRule      `json:"webshellRule"`
	SensitiveFileRule SensitiveFileRule `json:"sensitiveFileRule"`
	PkgVersionRule    PkgVersionRule    `json:"pkgRule"`
	PkgLicenseRule    PkgLicenseRule    `json:"pkgLicenseRule"`
	EnvRule           EnvRule           `json:"envRule"`
	RootUserRule      RootUserRule      `json:"rootUserRule"`
}

// SecPolicyResult 安全策略检测结果
type SecPolicyResult struct {
	SecPolicySnapShot  SecPolicy               `json:"secPolicySnapShot"`
	Vulns              VulnRuleResult          `json:"vulns"`
	Malwares           MalwareRuleResult       `json:"malwares"`
	WebshellRuleResult WebshellRuleResult      `json:"webshellRuleResult"`
	Sensitives         SensitiveFileRuleResult `json:"sensitives"`
	PkgsWithVersion    PkgVersionRuleResult    `json:"PkgsWithVersion"`
	PkgsWithLicense    PkgLicenseRuleResult    `json:"PkgsWithLicense"`
	Envs               EnvRuleResult           `json:"envs"`
	RootUserRuleResult RootUserRuleResult      `json:"rootUserRuleResult"`
}
