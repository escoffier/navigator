package imagesec

// SensitiveFileDBVersion 敏感文件规则库版本
type SensitiveFileDBVersion struct {
	Version string `json:"version"`
	Comment string `json:"comment"`
	Hash    string `json:"hash"` // MD5，用于检查版本库变化
}

type SensitiveFile struct {
	Filename string `json:"filename"` // 敏感文件，全路径
	Layer    string `json:"layer"`
	MD5      string `json:"md5"`
	Rule     string `json:"rule"`

	DescriptionEn string `json:"descriptionEn,omitempty"`
	DescriptionZh string `json:"descriptionZh,omitempty"`
}

// SensitiveFileResults 敏感文件扫描结果
type SensitiveFileResults struct {
	SensitiveFiles []SensitiveFile        `json:"sensitiveFiles"` // 扫描出来的所有敏感文件
	DBVersion      SensitiveFileDBVersion `json:"dbVersion"`      // 规则库版本
}

// 敏感文件规则
type SensitiveRule struct {
	ID          int64  `json:"id"`
	Description string `json:"description"`
	Value       string `json:"value"`    // 唯一
	RuleType    string `json:"ruleType"` // filename fileContent
	IsDefault   bool   `json:"isDefault"`
	Enable      bool   `json:"enable"`
}
