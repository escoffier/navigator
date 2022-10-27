package component

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy"
	trivylog "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/log"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	TrivyService *TrivyServer
	once         sync.Once
)

type TrivyServer struct {
	Trivy  *trivy.Scanner
	Update *vulnupdata.UpdataService
}

func NewTrivyServer(redis redis.Client, vulnpath string) (*TrivyServer, error) {
	once.Do(func() {
		_ = trivylog.InitLogger(true, false)
		ch := make(chan string)
		u := vulnupdata.NewUpdataService(vulnpath, ch)
		u.InitUpdateSvc()
		t, err := trivy.NewScannerWithRedis(redis, filepath.Join(vulnpath, "init_db"))
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
	go t.Update.Run(false, t.Update.VolumePath, t.Update.Ch)
	go func() {
		for path := range t.Update.Ch {
			logging.GetLogger().Info().Msgf("get ch Path :%v", path)
			if path == "err" {
				continue
			}
			if err := t.Trivy.SetBoltDB(path); err != nil {
				logging.GetLogger().Err(err).Msg("update scannert db error")
				continue
			}
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
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			// only sub cluster
			isMaster := strings.TrimSpace(os.Getenv("IS_MAIN_CLUSTER"))
			if isMaster == consts.TrueString || isMaster == "" {
				logging.GetLogger().Info().Str("IS_MAIN_CLUSTER", isMaster).Msg("TrivyServer is master cluster")
				continue
			}

			if global.VulnDBVersion == "" {
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
				if version == "" {
					logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
					continue
				}
				global.VulnDBVersion = version
				logging.GetLogger().Info().Str("url", getVersionURL).Str("version", version).Msg("TrivyServer update global vuln version")
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
				if version == "" {
					logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
					continue
				}
				logging.GetLogger().Info().Str("version", version).Msg("TrivyServer GetVulnDBVersion success")
				if global.VulnDBVersion != "" && global.VulnDBVersion == version {
					logging.GetLogger().Info().Str("global.VulnDBVersion", global.VulnDBVersion).Msg("TrivyServer VulnDBVersion is same")
				} else {
					logging.GetLogger().Info().Str("version", version).Str("global.VulnDBVersion", global.VulnDBVersion).Msg("TrivyServer VulnDBVersion change")
					if err := t.Update.UploadVulnDb(ctx); err != nil {
						logging.GetLogger().Err(err).Msg("TrivyServer UploadVulnDb")
					} else {
						global.VulnDBVersion = version
						logging.GetLogger().Info().Msg("TrivyServer UploadVulnDb success")
					}
				}
			}
		}
	}()

	return nil
}
