package helper

import (
	"encoding/json"
	"os"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func GetSavApiBinaryHash() string {

	hash, _ := util.Md5FromFile(filepath.Join(consts.AviraBinaryPath, consts.ScanMalwareTypeSavapi))

	return hash
}

// 当做常量使用
// node-image 统一挂载 /host 目录
func GetAviraDBPathInfo() types.DBPathInfo {
	pa := types.DBPathInfo{
		WorkVersionFile:   "/usr/local/savapi-sdk-linux64/bin/version",
		SavApiWorkPath:    "/usr/local/savapi-sdk-linux64/bin/savapi/",
		WorkPath:          "/usr/local/savapi-sdk-linux64/bin",
		SavApiBinFile:     "/usr/local/savapi-sdk-linux64/bin/savapi",
		SavApiConfFile:    "/etc/savapi/savapi.conf",
		SavApiLogFile:     "/tmp/sav-server.log",
		UpdateVersionFile: "/host/var/lib/tensor/db/avira/avira/version",
		UpdatePath:        "/host/var/lib/tensor/db/avira/",
		UpdateZipFile:     "/host/var/lib/tensor/db/avira/avira.zip",
		UpdateUnZipPath:   "/host/var/lib/tensor/db/avira/avira/",
	}
	return pa
}

func GetAviraDBVersion() types.DBVersionInfo {

	pa := GetAviraDBPathInfo()
	in := types.DBVersionInfo{}
	uv := types.AviraVersion{}
	wv := types.AviraVersion{}

	data, _ := os.ReadFile(pa.WorkVersionFile)
	if err := json.Unmarshal(data, &wv); err == nil {
		in.WorkVersion = imagesecModel.DBVersion{
			Version:  wv.AviraVersion.Version,
			Comment:  wv.AviraVersion.Comment,
			Hash:     wv.AviraVersion.Hash,
			UpdateAt: wv.UpdateTime,
		}
	}
	data2, _ := os.ReadFile(pa.UpdateVersionFile)
	if err := json.Unmarshal(data2, &wv); err == nil {
		in.UpdateVersion = imagesecModel.DBVersion{
			Version:  uv.AviraVersion.Version,
			Comment:  uv.AviraVersion.Comment,
			Hash:     uv.AviraVersion.Hash,
			UpdateAt: uv.UpdateTime,
		}
	}
	return in
}
