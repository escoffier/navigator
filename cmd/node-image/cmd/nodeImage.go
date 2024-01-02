package cmd

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/cmd/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Scanner struct {
	ScanConfig *imagesecModel.ImageScanConfig
	NodeConfig *config.Config

	Config          *config.Config
	nodeImageConfig *imagesecModel.ImageScanConfig
	Log             scannerUtils.LogEvent
}

// checkEnabled for debug,enabled node image scan by a local file
func (s *Scanner) checkEnabled() bool {
	enabledEnv := os.Getenv("NODE_IMAGE_ENABLED")
	return enabledEnv == consts.TrueString
}

func (s *Scanner) Run() func() {

	if os.Getenv("NODE_IMAGE_ENABLED") != consts.TrueString {
		logging.Get().Warn().Msg("node Image disabled")
		for {
			time.Sleep(99999 * time.Second) // dry run
		}
	}

	s.Log.Info().Msg("node image enabled,starting")

	// load last synced node image Config
	nc, err := config.LoadNodeImageConfigFromFile(config.GetDefaultNodeImageConfigFilePath())
	if err != nil {
		s.nodeImageConfig = config.GetNodeImageConfig()
		logging.Get().Warn().Interface("nodeImageConfig", s.nodeImageConfig).Msg("failed to load Config from file,use default Config")
	} else {
		s.nodeImageConfig = nc
		logging.Get().Debug().Interface("nodeImageConfig", s.nodeImageConfig).Msg("load Config from file ok")
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v. stack: %s", r, debug.Stack())
			}
		}()
		helper.BroadcastServer.Serve(context.Background())
	}()

	// run all services
	err = services.RunServices(s.Config, s.nodeImageConfig)
	if err != nil {
		logging.Get().Err(err).Msg("failed to run services")
	}

	return func() {
		logging.Get().Info().Msg("node image scanner stopped")
	}
}

func NewScanner(cfg *config.Config) (*Scanner, error) {
	m := &Scanner{
		Config: cfg,
	}
	return m, nil
}
