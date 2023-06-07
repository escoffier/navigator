package avira

import (
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/utils/strings/slices"
	"os/exec"
	"runtime/debug"
	"sync"
)

type SavServer struct {
	DownloadAviraDBPath       string // to update db file path.e.g./host/var/lib/tensor/db/avira
	WorkingAviraDBVersionFile string // avira version file. e.g. /usr/local/savapi-sdk-linux64/bin/version
	WorkingPath               string // avira sav api binary path. /usr/local/savapi-sdk-linux64/
	scanTaskWg                *sync.WaitGroup
	dbFileUpdateWg            *sync.WaitGroup
	subscribeChan             <-chan interface{}
	nodeImageConfig           imagesec2.NodeImageConfig // dynamic config synced from console
	nodeImageConfigLock       sync.RWMutex
	initConfig                config.Config // init config loaded from yaml
}

func init() {
	err := services.RegisterService(&SavServer{
		DownloadAviraDBPath:       helper.GetDownloadAviraDBPath(),
		WorkingAviraDBVersionFile: helper.GetWorkingAviraDBVersionFilePath(),
		WorkingPath:               avira.DefaultSavApiPath,
		dbFileUpdateWg:            helper.DBFileUpdateWg,
		scanTaskWg:                helper.ScanTaskWg,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register avira sav server service")
	} else {
		logging.Get().Info().Msg("register avira sav server service ok")
	}
}

func (s *SavServer) Type() services.ServiceType {
	return services.TypeServiceAvira
}

func (s *SavServer) updateNodeImageConfig(cfg imagesec2.NodeImageConfig) {
	s.nodeImageConfigLock.Lock()
	defer s.nodeImageConfigLock.Unlock()
	s.nodeImageConfig = cfg
}

func (s *SavServer) deepScanEnabled() bool {
	s.nodeImageConfigLock.Lock()
	defer s.nodeImageConfigLock.Unlock()
	return s.nodeImageConfig.DeepScan
}

func (s *SavServer) handleConfigModifiedEvent(server *avira.SavServer, event types.NotifyEvent) error {
	// copy config
	s.updateNodeImageConfig(event.NodeImageConfig)

	// enabled deep scan, start sav server
	if s.deepScanEnabled() {
		// check if sav server alive
		alive, err := server.IsSavServerRunning()
		if err != nil {
			logging.Get().Err(err).Msg("failed to check sav server alive")
			return err
		}

		// if alive,do nothing
		if alive {
			logging.Get().Info().Msg("handle config event: deep-scan enabled and server alive,do nothing")
			return nil
		}

		// not alive,start server
		logging.Get().Info().Msg("handle config event: deep-scan enabled, starting server")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			server.Run()
		}()
		return nil
	}

	// deep scan disabled. stop sav server
	// check if sav server alive
	alive, err := server.IsSavServerRunning()
	if err != nil {
		logging.Get().Err(err).Msg("failed to check sav server alive")
		return err
	}
	if !alive {
		logging.Get().Info().Msg("handle config event: deep-scan disabled,and server not running,do nothing")
		return nil
	}

	// notify to stop server
	server.NotifyStop()
	logging.Get().Debug().Msg("notify sav server stop")

	// wait server end
	<-server.EndChan()
	logging.Get().Debug().Msg("sav server end")

	return nil
}

// handleAviraDBUpdateEvent update avira db file
func (s *SavServer) handleAviraDBUpdateEvent(server *avira.SavServer, _ types.NotifyEvent) error {
	// first check if needing update by compare version
	needUpdate, tmpDir := s.NeedUpdate()
	if !needUpdate {
		logging.Get().Debug().Msg("not need to update avira db file")
		return nil
	}

	// get lock for updating
	s.dbFileUpdateWg.Add(1)
	defer s.dbFileUpdateWg.Done()

	// wait all scan task finished
	s.scanTaskWg.Wait()

	// check if sav server alive
	alive, err := server.IsSavServerRunning()
	if err != nil {
		logging.Get().Err(err).Msg("failed to check sav server alive")
		return err
	}
	if !alive {
		// not alive,just copy file
		if err := s.Flush(tmpDir); err != nil {
			logging.Get().Err(err).Msg("failed to flush avira db file")
			return err
		}
		logging.Get().Info().Msg("server not running,flush avira db file ok")
		return nil
	}

	// alive, first stop server
	server.NotifyStop()
	logging.Get().Debug().Msg("notify sav server stop")

	// wait server end
	<-server.EndChan()
	logging.Get().Debug().Msg("sav server end")

	// copy db file
	if err := s.Flush(tmpDir); err != nil {
		// just log,still restart server
		logging.Get().Err(err).Msg("failed to flush avira db file")
	} else {
		logging.Get().Info().Msg("flush avira db file ok")
	}

	// restart server
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		server.Run()
	}()

	return nil
}

func (s *SavServer) NeedUpdate() (bool, string) {
	// get newest version
	newVersion, err := helper.GetDownloadAviraDBVersion()
	if err != nil {
		logging.Get().Err(err).Msg("failed to parse new version")
		return false, ""
	}

	// get current version
	curVersion, err := helper.GetWorkingAviraDBVersion()
	if err != nil {
		logging.Get().Err(err).Msg("failed to parse cur version")
		return false, ""
	}

	// compare version
	shouldUpdate := helper.IsDBVersionNewer(newVersion, curVersion)
	if shouldUpdate {
		logging.Get().Debug().Str("newVersion", newVersion).Str("curVersion", curVersion).Msg("need update avira db")
		return true, s.DownloadAviraDBPath
	}

	logging.Get().Debug().Str("newVersion", newVersion).Str("curVersion", curVersion).Msg("not need update avira db")

	return false, ""
}

func (s *SavServer) Flush(srcDir string) error {
	// copy all db files
	cpCmdStr := fmt.Sprintf("cp -r %s %s", srcDir, s.WorkingPath)
	logging.Get().Debug().Str("cmd", cpCmdStr).Msg("flush avira db cmd")

	cmd := exec.Command("sh", "-c", cpCmdStr)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (s *SavServer) PreRun(cfg config.Config, nc imagesec2.NodeImageConfig, bs *util.BroadcastServer) error {
	// make copy of config
	s.nodeImageConfig = nc
	s.initConfig = cfg

	s.subscribeChan = bs.Subscribe(string(services.TypeServiceAvira))
	return nil
}

func (s *SavServer) shouldStartSav() bool {
	return slices.Contains(s.initConfig.DeepScanConfig.Types, config.DeepScanTypesAvira)
}

func (s *SavServer) Run() error {

	// create sav server instance
	savServer, _ := avira.NewSavServer(avira.WithListenPort(s.initConfig.AviraConfig.ListenPort))

	// first run,check if deep-scan enabled
	if s.nodeImageConfig.DeepScan && s.shouldStartSav() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			savServer.Run()
		}()
	}

	// wait notify event
	for {
		select {
		case item := <-s.subscribeChan:
			switch typed := item.(type) {
			case types.NotifyEvent:
				event := item.(types.NotifyEvent)
				if event.Type == types.NotifyEventTypeConfigModified {
					logging.Get().Debug().Interface("event", event).Msg("recv config modified event")
					_ = s.handleConfigModifiedEvent(savServer, event)
					continue
				}
				if event.Type == types.NotifyEventTypeAviraDBUpdate {
					logging.Get().Debug().Interface("event", event).Msg("recv avira db update event")
					_ = s.handleAviraDBUpdateEvent(savServer, event)
					continue
				}
				logging.Get().Debug().Interface("event", event).Msg("avira ignore irrelevant event")
			default:
				logging.Get().Error().Msgf("subscribe msg type err.%v", typed)
			}
		}
	}
}
