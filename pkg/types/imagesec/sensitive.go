package imagesec

// SensitiveFileDBVersion 敏感文件规则库版本
type SensitiveFileDBVersion struct {
	Version string `json:"version"`
	Comment string `json:"comment"`
	Hash    string `json:"hash"` // MD5，用于检查版本库变化
}

type SensitiveFile struct {
	Filename string `json:"filename"` // 敏感文件，全路径
}

// SensitiveFileResults 敏感文件扫描结果
type SensitiveFileResults struct {
	SensitiveFiles []SensitiveFile        `json:"sensitiveFiles"` // 扫描出来的所有敏感文件
	DBVersion      SensitiveFileDBVersion `json:"dbVersion"`      // 规则库版本
}
