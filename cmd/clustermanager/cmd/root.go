package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	flag2 "gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/leaderelection"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/klog/v2"
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
			// verbose, _ := cmd.Flags().GetBool("verbose")
			// if verbose {
			// 	loggingOptions.Level = int(zerolog.DebugLevel)
			// }

			// loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
			// logging.ReplaceLogger(loggingOptions)

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
			electionOpts := flag2.GetElectionOpts(cmd)
			logging.Get().Info().
				Str("easeDuration", electionOpts.LeaseDuration.String()).
				Str("renewDeadline", electionOpts.RenewDeadline.String()).
				Str("retryPeriod", electionOpts.RetryPeriod.String()).
				Msg("Election options")
			server, err := NewServer()
			if err != nil {
				logging.Get().Err(err).Msg("failed to create server")
				return
			}

			var stopCh <-chan struct{}

			run := func(context.Context) {
				server.Run(stopCh)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				stopCh = SetupSignalHandler()
				<-stopCh
				cancel()
			}()

			if enableLeaderElection {
				elector, err := leaderelection.New(run, electionOpts)
				if err != nil {
					logging.Get().Err(err).Msg("error occurred when server running")
					return
				}
				elector.Run(ctx)
				logging.Get().Info().Msg("lost lease")
				return
			}
			run(context.TODO())
		},
	}

	cmd.Flags().SortFlags = false
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlag(flag.CommandLine.Lookup("v"))

	cmd.AddCommand(versionCmd)
	// cmd.PersistentFlags().Int32P("v", "", 3, "log level")
	AddFlags(cmd.Flags(), cmd)
	flag2.AddElectionFlags(cmd)
	// klog.InitFlags(nil)
	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(cmd.Flags())
	// flag.Parse()

	return cmd
}
