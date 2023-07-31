package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/pkg/leaderelection"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	loggingOptions *logging.Options
)

func NewClusterManagerCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:  "cluster-manager",
		Long: "cluster manager",
		Run: func(cmd *cobra.Command, args []string) {
			if errs := loggingOptions.Validate(); len(errs) > 0 {
				logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("日志配置错误")
			}

			// 建议移除verbose
			// 使用log-level调节日志输出等级
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				loggingOptions.Level = int(zerolog.DebugLevel)
			}

			loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
			logging.ReplaceLogger(loggingOptions)

			logLevel := zerolog.InfoLevel
			logLevelStr := os.Getenv("LOGGING_LEVEL")
			if logLevelStr != "" {
				ll, err := strconv.ParseInt(logLevelStr, 10, 8)
				if err == nil {
					logLevel = zerolog.Level(ll)
				}
			}
			logging.Get().SetLevel(logLevel)

			elect := os.Getenv("ENABLE_LEADER_ELECTION")
			if elect == "true" {
				enableLeaderElection = true
			}

			run := func(context.Context) {
				server, err := NewServer()
				if err != nil {
					logging.Get().Err(err).Msg("failed to create server")
					return
				}
				err = server.Run()
				if err != nil {
					logging.Get().Err(err).Msg("error occurred when server running")
					return
				}
			}

			if enableLeaderElection {
				elector, err := leaderelection.New(run)
				if err != nil {
					logging.Get().Err(err).Msg("error occurred when server running")
					return
				}
				elector.Run(context.TODO())
				logging.Get().Info().Msg("lost lease")
				return
			}
			run(context.TODO())
		},
	}

	cmd.AddCommand(versionCmd)
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")
	AddFlags(cmd.Flags(), cmd)

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(cmd.Flags())
	return cmd
}
