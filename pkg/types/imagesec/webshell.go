package imagesec

// HmEngineVersion hm工具版本
type HmEngineVersion struct {
	Hash    string `json:"hash"` // hm binary md5 hash
	Version string `json:"version"`
	Comment string `json:"comment"`
}

// HmWebshell 扫描出来的webshell
type HmWebshell struct {
	Filename            string `json:"filename"`    // full path.e.g. /host/var/lib/docker/overlay2/xyz/diff/opt/abc
	MD5                 string `json:"md5"`         // hash value
	Mod                 string `json:"mod"`         // 文件权限.e.g.-rw-r--r-- ubuntu ubuntu
	Size                int64  `json:"size"`        // file size. byte
	Code                string `json:"code"`        // 可疑代码
	RiskLevel           string `json:"riskLevel"`   // 风险程度
	Description         string `json:"description"` // 描述。如php一句话木马
	Layer               string `json:"layer"`
	FilePathInContainer string `json:"filePathInContainer"` // webshell file path in container.e.g. /opt/abc  节点镜像使用
}

// WebshellResults webshell扫描结果
type WebshellResults struct {
	Scanned         bool            `json:"scanned"`
	HmWebshells     []HmWebshell    `json:"webshells,omitempty"` // 所有webshell结果
	HmEngineVersion HmEngineVersion `json:"hmEngineVersion"`
}
