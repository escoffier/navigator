package cmd

import (
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/opt"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"strings"
)

// initConfig parse config from yaml file
func initConfig(configFile string) (*config.Config, error) {
	// default config
	cfg := config.NewDefaultConfig()

	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logging.Get().Err(err).Msgf("config file %q not found", configFile)
			return cfg, err
		}
		// err,return default cfg
		return cfg, fmt.Errorf("config file %q loading error: %s", configFile, err)
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return cfg, err
	}
	logging.Get().Info().Interface("config", cfg).Msgf("Loaded %s", configFile)

	return cfg, nil
}

func initLogLevel(cfg *config.Config) {
	logLevel := strings.ToLower(strings.TrimSpace(cfg.LogLevel))

	// default info level
	var zlogLevel zerolog.Level
	switch logLevel {
	case "debug":
		zlogLevel = zerolog.DebugLevel
	case "info":
		zlogLevel = zerolog.InfoLevel
	case "error":
		zlogLevel = zerolog.ErrorLevel
	case "warn":
		zlogLevel = zerolog.WarnLevel
	default:
		zlogLevel = zerolog.InfoLevel
	}

	logging.Get().SetLevel(zlogLevel)
}

func NewRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "node-image-scanner",
		Short: "scan node's image",
		RunE: func(cmd *cobra.Command, args []string) error {
			// read config file
			option := opt.GetOptionByViper()
			cfg, err := initConfig(option.ConfigFile)
			if err != nil {
				return err
			}

			// record to global config which will be used for hot update
			config.SetGlobalConfig(cfg)

			// set log level
			initLogLevel(cfg)

			// new instance
			scanner, err := NewScanner(cfg)
			if err != nil {
				logging.Get().Err(err).Msg("failed to create enforcer")
				return err
			}
			lifecycle.NewApplication(
				scanner,
			).Run()
			return nil
		},
	}

	opt.AddNodeImageOpts(rootCmd)

	// add subcommand
	rootCmd.AddCommand(NewVersionCmd())

	return rootCmd
}
