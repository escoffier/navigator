package cmd

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
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
		},
	}

	cmd.AddCommand(versionCmd)
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")
	AddFlags(cmd.Flags(), cmd)

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(cmd.Flags())
	return cmd
}
