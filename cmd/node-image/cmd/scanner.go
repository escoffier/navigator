package cmd

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/all"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Scanner struct {
	config          *config.Config
	nodeImageConfig *imagesecModel.ImageScanConfig
}

// checkEnabled for debug,enabled node image scan by a local file
func (s *Scanner) checkEnabled() bool {
	enabledEnv := os.Getenv("NODE_IMAGE_ENABLED")
	if enabledEnv == "true" {
		return true
	}
	return false
}

func (s *Scanner) Run() func() {

	if s.checkEnabled() {
		logging.Get().Info().Msg("node image enabled,starting")

		// load last synced node image config
		nc, err := config.LoadNodeImageConfigFromFile(config.GetDefaultNodeImageConfigFilePath())
		if err != nil {
			s.nodeImageConfig = config.GetNodeImageConfig()
			logging.Get().Warn().Interface("nodeImageConfig", s.nodeImageConfig).Msg("failed to load config from file,use default config")
		} else {
			s.nodeImageConfig = nc
			logging.Get().Debug().Interface("nodeImageConfig", s.nodeImageConfig).Msg("load config from file ok")
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
		err = services.RunServices(s.config, s.nodeImageConfig)
		if err != nil {
			logging.Get().Err(err).Msg("failed to run services")
		}
	} else {
		logging.Get().Warn().Msg("node Image disabled")
		// dry run
		for {
			time.Sleep(99999 * time.Second)
		}
	}

	return func() {
		logging.Get().Info().Msg("node image scanner stopped")
	}
}

func NewScanner(cfg *config.Config) (*Scanner, error) {
	m := &Scanner{
		config: cfg,
	}
	return m, nil
}
