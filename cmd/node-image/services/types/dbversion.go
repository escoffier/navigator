package types

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 路径信息做统一规整
type DBPathInfo struct {
	WorkVersionFile   string // 正在使用的文件中version文件的绝对路径文件名
	WorkPath          string // 执行执行所加载的库文件目录
	SavApiWorkPath    string // savapi的目录
	UpdateVersionFile string // 上传文件中version文件的绝对路径文件名
	SavApiBinFile     string // 二制进执行文件名的
	SavApiConfFile    string // 配置文件
	SavApiLogFile     string // log 文件
	UpdatePath        string // 上传文件所保存的目录
	UpdateZipFile     string // 上传zip文件的绝对路径文件名
	UpdateUnZipPath   string // 上传文件的解压路径
}

// 版本信息，和scanner 一起调整，统一结构
type DBVersionInfo struct {
	WorkVersion   imagesecModel.DBVersion // 正在使用的version
	UpdateVersion imagesecModel.DBVersion // 上传文件中version
}

type AviraVersion struct {
	CompressDBVersion string `json:"compressDBVersion"`
	AviraVersion      struct {
		Version string `json:"version"`
		Comment string `json:"comment"`
		Hash    string `json:"hash"`
	} `json:"AviraVersion"`
	UpdateTime int64 `json:"updateTime"`
}

func (vi *DBVersionInfo) NeedUpdate() bool {
	if vi.WorkVersion.Version == "" && vi.UpdateVersion.Version != "" {
		return true
	}
	if vi.WorkVersion.Version == "" && vi.UpdateVersion.Version != "" {
		return false
	}
	newTime, _ := time.Parse(consts.VulnDBVersionLayout, vi.UpdateVersion.Version)
	curTime, _ := time.Parse(consts.VulnDBVersionLayout, vi.WorkVersion.Version)

	return newTime.After(curTime)
}
