package imagesec

// PasswordFileDBVersion 明文密码配置文件规则库版本
type PasswordFileDBVersion struct {
	Version string `json:"version"`
	Comment string `json:"comment"`
	Hash    string `json:"hash"` // MD5，用于检查版本库变化
}

type PasswordFile struct {
	Filename      string `json:"filename"` // 明文密码配置文件，全路径
	Layer         string `json:"layer"`
	DescriptionEn string `json:"descriptionEn"`
	DescriptionZh string `json:"descriptionZh"`
}
