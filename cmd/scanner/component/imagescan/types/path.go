package types

import (
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func GetAviraDBPathInfo() imagesecModel.DBPathInfo {
	pa := imagesecModel.DBPathInfo{
		WorkVersionFilename: "/usr/local/savapi-sdk-linux64/version",
		WorkPath:            "/usr/local/savapi-sdk-linux64/",
		BinFilename:         "/usr/local/savapi-sdk-linux64/bin/savapi",
		WorkConfFilename:    "/etc/savapi/savapi.conf",
		UpdatePath:          "/root/alldb/malware/avira/",
		UpdateUnZipPath:     "/root/alldb/malware/avira/",
	}
	return pa
}

func GetClamavDBPathInfo() imagesecModel.DBPathInfo {
	pa := imagesecModel.DBPathInfo{
		WorkVersionFilename: "/var/lib/clamav/version",
		WorkPath:            "/var/lib/clamav/",
		UpdatePath:          "/root/alldb/malware/clamav/",
		UpdateUnZipPath:     "/root/alldb/malware/clamav/",
	}
	return pa
}
