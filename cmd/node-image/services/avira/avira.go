package avira

import (
	"context"
	"fmt"
	"os/exec"
	"runtime/debug"
	"sync"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/utils/strings/slices"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SavServer struct {
	scanTaskWg          *sync.WaitGroup
	dbFileUpdateWg      *sync.WaitGroup
	subscribeChan       <-chan interface{}
	nodeImageConfig     imagesecModel.NodeImageConfig // dynamic config synced from console
	nodeImageConfigLock sync.RWMutex
	initConfig          config.Config // init config loaded from yaml
	AviraDBPathInfo     types.DBPathInfo
}

func init() {
	err := services.RegisterService(&SavServer{
		dbFileUpdateWg:      helper.DBFileUpdateWg,
		scanTaskWg:          helper.ScanTaskWg,
		AviraDBPathInfo:     helper.GetAviraDBPathInfo(),
		nodeImageConfigLock: sync.RWMutex{},
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register avira avira server service")
		return
	}
	logging.Get().Info().Msg("register avira avira server service ok")
}

func (s *SavServer) Type() consts.ServiceType {
	return imagesecModel.DBMetaTypeAvira
}

func (s *SavServer) Run() error {
	// create avira server instance
	savServer := avira.NewSavServer(avira.WithListenPort(s.initConfig.AviraConfig.ListenPort))

	// first run,check if deep-scan enabled
	if s.nodeImageConfig.DeepScan && s.shouldStartSav() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			savServer.StartServer()
			logging.Get().Info().Msg("start avira server succeed")
		}()
	}
	// 持续等待接受事件
	s.notifyEvent(context.Background(), savServer)

	return nil
}

func (s *SavServer) PreRun(cfg config.Config, nc imagesecModel.NodeImageConfig, bs *util.BroadcastServer) error {
	// make copy of config
	s.nodeImageConfig = nc
	s.initConfig = cfg

	s.subscribeChan = bs.Subscribe(string(consts.TypeServiceAvira))
	return nil
}

// handleAviraDBUpdateEvent update avira db file
func (s *SavServer) handleAviraDBUpdateEvent(server *avira.SavServer, _ types.NotifyEvent) error {
	dbVersionInfo := helper.GetAviraDBVersion()
	if !dbVersionInfo.NeedUpdate() {
		logging.Get().Debug().Msg("not need to update avira db file")
		return nil
	}

	// get lock for updating
	s.dbFileUpdateWg.Add(1)
	defer s.dbFileUpdateWg.Done()

	// wait all scan task finished 在tasks.go中增加的任务
	s.scanTaskWg.Wait()

	if err := server.KillServer(); err != nil {
		logging.Get().Err(err).Msg("failed to kill avira server")
		return err
	}
	if err := s.reloadAviraDB(); err != nil {
		logging.Get().Err(err).Msg("failed to flush avira db file")
		return err
	}

	server.StartServer()
	logging.Get().Info().Msg("reload avira server db file ok")

	return nil
}

func (s *SavServer) updateNodeImageConfig(cfg imagesecModel.NodeImageConfig) {
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

	// enabled deep scan, start avira server
	if s.deepScanEnabled() {
		logging.Get().Info().Msg("deep scan enable start avira server")

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("panic : %v. stack: %s", r, debug.Stack())
				}
			}()
			server.ShouldStop = false
			server.StartServer()
			logging.Get().Info().Msg("deep scan enable and start avira server")
		}()
	}

	if !s.deepScanEnabled() {
		// 等待所有的任务执行完成
		s.scanTaskWg.Wait()

		if err := server.KillServer(); err != nil {
			logging.Get().Err(err).Msg("do not stop avira server")
			return err
		}
		logging.Get().Info().Msg("deep scan not enable and stop avira server")
	}

	return nil
}

func (s *SavServer) reloadAviraDB() error {
	// copy all db files
	cpCmdStr := fmt.Sprintf("cp -r %s %s", s.AviraDBPathInfo.UpdateUnZipPath, s.AviraDBPathInfo.WorkPath)
	logging.Get().Debug().Str("cmd", cpCmdStr).Msg("reloadAviraDB avira db cmd")

	cmd := exec.Command("sh", "-c", cpCmdStr)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (s *SavServer) shouldStartSav() bool {
	return slices.Contains(s.initConfig.DeepScanConfig.Types, config.DeepScanTypesAvira)
}

func (s *SavServer) notifyEvent(ctx context.Context, savServer *avira.SavServer) {
	// wait notify event
	for {
		select {
		case item := <-s.subscribeChan:
			switch typed := item.(type) {
			case types.NotifyEvent:
				event := item.(types.NotifyEvent)
				if event.Type == consts.NotifyEventTypeConfigModified {
					logging.Get().Debug().Interface("event", event).Msg("receive config modified event")
					_ = s.handleConfigModifiedEvent(savServer, event)
					continue
				}
				if event.Type == consts.NotifyEventTypeAviraDBUpdate {
					logging.Get().Debug().Interface("event", event).Msg("receive avira db update event")
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
