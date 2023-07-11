package helper

import (
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	TaskQueue       *util.Queue           // scan task queue
	ScanTaskWg      *sync.WaitGroup       // wait for all task processed before db update
	DBFileUpdateWg  *sync.WaitGroup       // stop processing requests during db update
	BroadcastServer *util.BroadcastServer // notify all db update and config modified event to services
)

// GetDownloadDBPath vuln,clamav,avira db file store path. all db files store in host directory
// func GetDownloadDBPath() string {
// 	return filepath.Join(global.MountPathInContainer, global.WorkingDir, "db")
// }

// GetDownloadVulnDBPath /host/var/lib/tensor/db/vuln
// func GetDownloadVulnDBPath() string {
// 	return filepath.Join(GetDownloadDBPath(), "vuln")
// }
//
// GetDownloadVulnDBFilePath return db file name in newly downloaded dir(/host/var/lib/tensor/db/vuln/202203141500/trivy/trivy.db)
// func GetDownloadVulnDBFilePath(dir string) string {
// 	return filepath.Join(dir, "trivy/trivy.db")
// }

// func GetDownloadVulnDBVersionPath(dir string) string {
// 	return filepath.Join(dir, "trivy/version")
// }

// func GetDownloadVulnDBVersion(dir string) (string, error) {
// 	version := &imagesec.OfflineVulnDBVersion{}
// 	data, err := os.ReadFile(GetDownloadVulnDBVersionPath(dir))
// 	if err != nil {
// 		return "", err
// 	}
// 	err = json.Unmarshal(data, version)
// 	if err != nil {
// 		return "", err
// 	}
// 	return version.TrivyVersion.Version, nil
// }

// func GetWorkingVulnDBFilePath() string {
// 	return filepath.Join(global.WorkingDir, "cache/db/trivy.db")
// }

// func GetWorkingVulnDBVersionFilePath() string {
// 	return filepath.Join(global.WorkingDir, "cache/db/version")
// }

// func GetWorkingVulnDBVersion() (string, error) {
// 	version := &imagesec.OfflineVulnDBVersion{}
// 	data, err := os.ReadFile(GetWorkingVulnDBVersionFilePath())
// 	if err != nil {
// 		return "", err
// 	}
// 	err = json.Unmarshal(data, version)
// 	if err != nil {
// 		return "", err
// 	}
// 	return version.TrivyVersion.Version, nil
// }
//
// func IsDBVersionNewer(newVersion, curVersion string) bool {
// 	newTime, _ := time.Parse(consts.VulnDBVersionLayout, newVersion)
// 	curTime, _ := time.Parse(consts.VulnDBVersionLayout, curVersion)
//
// 	return newTime.After(curTime)
// }

func init() {
	TaskQueue = util.NewQueue()
	DBFileUpdateWg = &sync.WaitGroup{}
	ScanTaskWg = &sync.WaitGroup{}
	BroadcastServer = util.NewBroadcastServer()
}
