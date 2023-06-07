package helper

import (
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"os"
	"path/filepath"
)

const (
	AviraBinaryPath = "/usr/local/savapi-sdk-linux64/bin"
)

// GetDownloadAviraDBPath /host/var/lib/tensor/db/avira
func GetDownloadAviraDBPath() string {
	return filepath.Join(GetDownloadDBPath(), "avira")
}

// GetDownloadAviraDBVersionPath /host/var/lib/tensor/db/avira/version
func GetDownloadAviraDBVersionPath() string {
	return filepath.Join(GetDownloadAviraDBPath(), "version")
}

func GetDownloadAviraDBVersion() (string, error) {
	// todo: change to avira db version
	version := &imagesec.OfflineVulnDBVersion{}
	data, err := os.ReadFile(GetDownloadAviraDBVersionPath())
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(data, version)
	if err != nil {
		return "", err
	}
	return version.TrivyVersion.Version, nil
}

func GetWorkingAviraDBVersionFilePath() string {
	return filepath.Join(AviraDBPath, "version")
}

func GetWorkingAviraDBVersion() (string, error) {
	// todo: change to avira
	version := &imagesec.OfflineVulnDBVersion{}
	data, err := os.ReadFile(GetWorkingAviraDBVersionFilePath())
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(data, version)
	if err != nil {
		return "", err
	}
	return version.TrivyVersion.Version, nil
}

func GetSavApiBinaryHash() string {
	hash, _ := util.Md5FromFile(filepath.Join(AviraBinaryPath, "savapi"))
	return hash
}
