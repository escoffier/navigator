// Package cmd is for all the Cobra commands
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
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/klog/v2"

	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service"
	flag3 "gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/leaderelection"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "a cloud native devsecops tool",
	RunE: func(cmd *cobra.Command, args []string) error {

		ScannerRunOpts := flag2.GetScannerOpts(cmd)
		global.ScannerOpts = ScannerRunOpts

		// 建议改为loggingOptions用法
		// 目前由于log-level参数名称冲突
		if ScannerRunOpts.LogLevel == "debug" {
			logging.Get().Logger = logging.Get().Logger.Level(zerolog.DebugLevel)
		}

		logLevel := zerolog.InfoLevel
		logLevelStr := os.Getenv("LOGGING_LEVEL")
		if logLevelStr != "" {
			ll, err := strconv.ParseInt(logLevelStr, 10, 8)
			if err == nil {
				logLevel = zerolog.Level(ll)
			}
		}
		logging.Get().SetLevel(logLevel)

		scanner, err := service.NewScanner(ScannerRunOpts)
		if err != nil {
			return err
		}
		global.ScannerPodID = scanner.PodID
		global.ScannerInstance = scanner.ScannerInstance
		global.ClusterName = scanner.ClusterName
		global.ClusterKey = scanner.ClusterKey
		global.PVCPath = ScannerRunOpts.PvcPath
		vv := scannermodel.ScannerDBVersion{
			VulnVersion: scannermodel.VulnDBVersion{
				TrivyVersion:    scannermodel.DBMateData{Version: "123"},
				CustomDBVersion: scannermodel.DBMateData{Version: "345"},
			},
		}

		global.VulnDBVersion = &vv

		logging.Get().Info().
			Str("version", Version).
			Str("ScannerInstance", global.ScannerInstance).
			Interface("opts", ScannerRunOpts).
			Interface("ScannerPodID", global.ScannerPodID).
			Msg("starting scanner")

		electionOpts := flag3.GetElectionOpts(cmd)
		logging.Get().Info().
			Str("easeDuration", electionOpts.LeaseDuration.String()).
			Str("renewDeadline", electionOpts.RenewDeadline.String()).
			Str("retryPeriod", electionOpts.RetryPeriod.String()).
			Msg("Election options")
		elect := os.Getenv("ENABLE_LEADER_ELECTION")
		if elect == "true" {
			flag2.EnableLeaderElection = true
		}
		if flag2.EnableLeaderElection {
			elector, err := leaderelection.New(func(ctx context.Context) {
				lifecycle.NewApplication(
					scanner,
				).Run()
			}, electionOpts)
			if err != nil {
				logging.Get().Err(err).Msg("error occurred when server running")
				return err
			}
			elector.Run(context.TODO())
			logging.Get().Info().Msg("lost lease")
			return fmt.Errorf("lost lease")
		}

		lifecycle.NewApplication(
			scanner,
		).Run()
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logging.Get().Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().SortFlags = false
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlag(flag.CommandLine.Lookup("v"))

	flag2.AddScannerFlags(rootCmd)
	flag3.AddElectionFlags(rootCmd)
	flag3.ConfigViper()
}
