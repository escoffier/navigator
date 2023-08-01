package component

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy"
	trivylog "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	TrivyService *TrivyServer
	once         sync.Once
	initOnce     sync.Once
	initRes      bool
)

type TrivyServer struct {
	Trivy  *trivy.Scanner
	Update *vulnupdata.UpdataService
}

func MustGetTrivyServer() *TrivyServer {
	for {
		if TrivyService != nil {
			return TrivyService
		}
		time.Sleep(2 * time.Second)
	}
}

func InitTrivyDb(vulnPath string) bool {
	initOnce.Do(func() {
		nowFp := filepath.Join(vulnPath, scannermodel.TrivyDBPath)
		if util.FileExists(nowFp) {
			initRes = true
			return
		}
		oldFp := filepath.Join(vulnPath, "init_trivy.db")
		oldCustom := filepath.Join("vulnPath", "init_custom.db")
		offlineFp := filepath.Join(vulnPath, "offline", "init_trivy.db")
		offlineCustom := filepath.Join(vulnPath, "offline", "init_custom.db")
		if util.FileExists(offlineFp) {
			oldCustom = offlineCustom
			oldFp = offlineFp
		}
		if !util.PathExists(filepath.Join(vulnPath, scannermodel.TrivyDB)) {
			err := os.Mkdir(filepath.Join(vulnPath, scannermodel.TrivyDB), 0666)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("mkdir trivy error")
				initRes = false
				return
			}
		}

		nowCuston := filepath.Join(vulnPath, scannermodel.CustomDBPath)
		cmd := exec.Command("cp", "-f", oldFp, nowFp)
		err := cmd.Run()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("cp initDB error %v", cmd.Args)
			initRes = false
			return
		}

		cmd = exec.Command("cp", "-f", oldCustom, nowCuston)
		err = cmd.Run()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("cp initDB error %v", cmd.Args)
			initRes = false
			return
		}
		defaultVer := scannermodel.VulnDBVersion{ComPressDBVersion: "0", TrivyVersion: scannermodel.DBMateData{Version: "0", Comment: "default version"},
			CustomDBVersion: scannermodel.DBMateData{Version: "0", Comment: "default version"}}
		verByte, err := json.Marshal(defaultVer)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("marshal default ver error")
			initRes = false
			return
		}
		versionPath := filepath.Join(vulnPath, scannermodel.VulnVersionPath)
		err = os.WriteFile(versionPath, verByte, 0777)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("write default ver error")
			initRes = false
			return
		}
		initRes = true
	})
	return initRes
}

func NewTrivyServer(redis redis.Client, vulnpath string) (*TrivyServer, error) {
	once.Do(func() {
		_ = trivylog.InitLogger(true, false)
		ch := make(chan scannermodel.UpdateResult)
		u := &vulnupdata.UpdataService{}
		if InitTrivyDb(vulnpath) {
			u = vulnupdata.NewUpdataService(filepath.Join(vulnpath, "trivy"), ch)
			u.IsOld = false
		} else {
			u = vulnupdata.NewUpdataService(vulnpath, ch)
			u.IsOld = true
		}
		dbPath, err := u.GenerateDir(u.VolumePath)
		if err != nil {
			logging.GetLogger().Err(err).Msg("failed to generate db dir")
		}
		t, err := trivy.NewScannerWithRedis(redis, dbPath)
		if err != nil {
			panic(fmt.Sprintf("init db scannert failed, err: %v\n", err))
		}
		TrivyService = &TrivyServer{
			Trivy:  t,
			Update: u,
		}
	})

	return TrivyService, nil
}

func (t *TrivyServer) Scan(ctx context.Context, image string) (*report.Report, error) {
	return t.Trivy.Scan(ctx, image)
}

func (t *TrivyServer) Run(ctx context.Context) error {
	go func() {
		for path := range t.Update.Ch {
			logging.GetLogger().Info().Msgf("get ch Path :%v", path)
			if err := t.Trivy.SetBoltDB(path.DBPath); err != nil {
				path.Result <- false
				logging.GetLogger().Err(err).Msg("update scannert db error")
				continue
			}
			path.Result <- true
			logging.GetLogger().Info().Msg("scannert updata DB success")
		}
	}()

	// 检查vuln db version
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("SyncAllImage recover")
			}
		}()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			<-ticker.C
			// only sub cluster
			isMaster := strings.TrimSpace(os.Getenv("IS_MAIN_CLUSTER"))
			if isMaster == consts.TrueString || isMaster == "" {
				logging.GetLogger().Info().Str("IS_MAIN_CLUSTER", isMaster).Msg("TrivyServer is master cluster")
				continue
			}

			if global.VulnDBVersion == nil {
				url := global.ScannerOpts.HTTPListenAddr
				if !strings.Contains(url, "http") {
					url = "http://localhost" + url
				}
				getVersionURL := fmt.Sprintf("%s%s", url, "/api/v1/ci/tidb/version")
				version, err := t.Update.GetVulnDBVersion(ctx, getVersionURL)
				if err != nil {
					logging.GetLogger().Err(err).Str("url", getVersionURL).Msg("TrivyServer GetVulnDBVersion")
					continue
				}
				if version.VulnVersion.TrivyVersion.Version == "" {
					logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
					continue
				}
				global.VulnDBVersion = &version
				logging.GetLogger().Info().Str("url", getVersionURL).Msgf("TrivyServer update global vuln version %v", version)
			} else {
				consoleURL := os.Getenv("CONSOLE_EXTERNAL_URL")
				if consoleURL == "" {
					logging.GetLogger().Err(fmt.Errorf("not get CONSOLE_EXTERNAL_URL")).Msg("TrivyServer GetVulnDBVersion")
					continue
				}
				getVersionURL := fmt.Sprintf("%s%s", consoleURL, "/api/openapi/scanner/ci/tidb/version")
				version, err := t.Update.GetVulnDBVersion(ctx, getVersionURL)
				if err != nil {
					logging.GetLogger().Err(err).Msg("TrivyServer GetVulnDBVersion")
					continue
				}
				if version.VulnVersion.TrivyVersion.Version == "" {
					logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
					continue
				}
				logging.GetLogger().Info().Msg("TrivyServer GetVulnDBVersion success")
				if global.VulnDBVersion != nil && global.VulnDBVersion.VulnVersion.Same(version.VulnVersion) {
					logging.GetLogger().Info().Msgf("TrivyServer VulnDBVersion is same %v", global.VulnDBVersion)
				} else {
					logging.GetLogger().Info().Msgf("TrivyServer VulnDBVersion change %v", version)
					if err := t.Update.UploadVulnDb(ctx); err != nil {
						logging.GetLogger().Err(err).Msg("TrivyServer UploadVulnDb")
					} else {
						global.VulnDBVersion = &version
						logging.GetLogger().Info().Msg("TrivyServer UploadVulnDb success")
					}
				}
			}
		}
	}()

	return nil
}
