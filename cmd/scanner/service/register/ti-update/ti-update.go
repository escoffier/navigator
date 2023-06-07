// Package ti_update update all thread intelligent database file where they are ready
package tiupdate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

const (
	serviceName = "ti-update"
)

type TiUpdate struct {
	vulnSrv *vulnupdata.UpdataService
}

func (s *TiUpdate) Update(ctx context.Context) error {
	time.Sleep(time.Duration(23) * time.Second)
	logging.GetLogger().Info().Msg("Suspending all task during DB update")
	global.TiDbUpdateWg.Add(1)
	defer global.TiDbUpdateWg.Done()

	logging.GetLogger().Info().Msg("Waiting for all task to be processed before DB update...")
	global.TaskWg.Wait()

	// pretend update
	time.Sleep(time.Duration(20) * time.Second)

	// todo: update db,set flag and timestamp,so task cronjob can generate new task

	logging.GetLogger().Info().Msg("ti update end")
	return nil
}

func (s *TiUpdate) UpdateVulnDB(ctx context.Context) error {
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
			version, err := s.vulnSrv.GetVulnDBVersion(ctx, getVersionURL)
			if err != nil {
				logging.GetLogger().Err(err).Str("url", getVersionURL).Msg("TrivyServer GetVulnDBVersion")
				continue
			}
			if version.VulnVersion.GetVersion(scannermodel.TrivyDB) <= 0 {
				logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
				continue
			}
			global.VulnDBVersion.VulnVersion = version.VulnVersion
			logging.GetLogger().Info().Str("url", getVersionURL).Msgf("TrivyServer update global vuln version %v", version)
		} else {
			consoleURL := os.Getenv("CONSOLE_EXTERNAL_URL")
			if consoleURL == "" {
				logging.GetLogger().Err(fmt.Errorf("not get CONSOLE_EXTERNAL_URL")).Msg("TrivyServer GetVulnDBVersion")
				continue
			}
			getVersionURL := fmt.Sprintf("%s%s", consoleURL, "/api/openapi/scanner/ci/tidb/version")
			version, err := s.vulnSrv.GetVulnDBVersion(ctx, getVersionURL)
			if err != nil {
				logging.GetLogger().Err(err).Msg("TrivyServer GetVulnDBVersion")
				continue
			}
			if version.VulnVersion.GetVersion(scannermodel.TrivyDB) <= 0 {
				logging.GetLogger().Info().Str("url", getVersionURL).Msg("TrivyServer not get vuln db version")
				continue
			}
			logging.GetLogger().Info().Msg("TrivyServer GetVulnDBVersion success")
			if global.VulnDBVersion != nil && global.VulnDBVersion.VulnVersion.Same(version.VulnVersion) {
				logging.GetLogger().Info().Msgf("TrivyServer VulnDBVersion is same %v", global.VulnDBVersion)
			} else {
				logging.GetLogger().Info().Msgf("TrivyServer VulnDBVersion change %v", version)
				if err := s.vulnSrv.UploadVulnDb(ctx); err != nil {
					logging.GetLogger().Err(err).Msg("TrivyServer UploadVulnDb")
				} else {
					global.VulnDBVersion.VulnVersion = version.VulnVersion
					logging.GetLogger().Info().Msg("TrivyServer UploadVulnDb success")
				}
			}
		}
	}
}

func (s *TiUpdate) Start(ctx context.Context) error {
	s.vulnSrv = vulnupdata.GetVulnUpdataService()
	go s.UpdateVulnDB(ctx)
	return nil
}

func (s *TiUpdate) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	t := &TiUpdate{} //TrivySrv的初始化在这个阶段，为了避免顺序混乱我们在start时再获取服务

	return t, nil
}
