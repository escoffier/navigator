// Package cmd is for all the Cobra commands
package cmd

import (
	"context"
	flag2 "flag"
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"

	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/leaderelection"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm/logger"
	"k8s.io/klog/v2"
)

var (
	loggingOptions       *logging.Options
	rdbOptions           *databases.Options
	enableLeaderElection bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "console",
	Short: "The centralized server",
	Long:  `The centralized server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if errs := loggingOptions.Validate(); len(errs) > 0 {
			return fmt.Errorf("%v", errs)
		}
		if errs := rdbOptions.Validate(); len(errs) > 0 {
			return fmt.Errorf("%v", errs)
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

		logging.Get().Info().
			Str("version", Version).
			Msg("starting Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.Get().Info().
			Str("listen", httpOpts.HTTPListen).
			Str("webhooklisten", httpOpts.HTTPWebHookListen).
			Msg("HTTP options")

		rdbOpts := flag.GetRDBOpts(cmd)
		logging.Get().Info().
			Str("pvc", rdbOpts.PVC).
			Str("pod", rdbOpts.Pod).
			Str("dataPath", rdbOpts.DataPath).
			Msg("Postgres options")

		scannerOpts := flag.GetVegetaScannerOpts(cmd)
		logging.Get().Info().
			Str("host", scannerOpts.Host).
			Int("port", scannerOpts.Port).
			Msg("Scanner options")

		exporterOpts := flag.GetExporterOpts(cmd)

		logging.Get().Info().
			Str("host", exporterOpts.Host).
			Int("port", exporterOpts.Port).
			Msg("exporter options")

		scapOpts := flag.GetScapOpts(cmd)
		logging.Get().Info().
			Int32("policy-counts", scapOpts.PolicyCounts).
			Msg("Scap options")

		harborOpts := flag.GetHarborOpts(cmd)
		logging.Get().Info().
			Str("harbor-url", harborOpts.URL).
			Str("harbor-username", harborOpts.Username).
			Bool("harbor-skiptlsverify", harborOpts.SkipTLSVerify).
			Msg("Harbor REST client options")

		elasticOpts := flag.GetElasticOpts(cmd)
		logging.Get().Info().
			Str("host", elasticOpts.Host).
			Str("port", elasticOpts.Port).
			Str("index", elasticOpts.Index).
			Str("username", elasticOpts.Username).
			Msg("Elastic options")
		electionOpts := flag.GetElectionOpts(cmd)
		logging.Get().Info().
			Str("easeDuration", electionOpts.LeaseDuration.String()).
			Str("renewDeadline", electionOpts.RenewDeadline.String()).
			Str("retryPeriod", electionOpts.RetryPeriod.String()).
			Msg("Election options")

		run := func(ctx context.Context) {
			console, err := service.NewConsole(httpOpts, rdbOpts, scannerOpts, exporterOpts, scapOpts, elasticOpts, rdbOptions)
			if err != nil {
				logging.Get().Err(err)
				return
			}

			lifecycle.NewApplication(
				console,
			).Run()
		}

		elect := os.Getenv("ENABLE_LEADER_ELECTION")
		if elect == "true" {
			enableLeaderElection = true
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if enableLeaderElection {
			elector, err := leaderelection.New(run, cancel, electionOpts)
			if err != nil {
				return err
			}
			elector.Run(ctx)
			return fmt.Errorf("lost lease")
		}

		run(ctx)
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
	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(rootCmd.Flags())

	rdbLogLevelStr := os.Getenv("RDB_LOGGING_LEVEL")
	rdbLogLevel := int(logger.Error)
	if len(rdbLogLevelStr) > 0 {
		var parseErr error
		rdbLogLevel, parseErr = strconv.Atoi(rdbLogLevelStr)
		if parseErr != nil {
			rdbLogLevel = int(logger.Error)
		}
	}
	rootCmd.Flags().SortFlags = false
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlag(flag2.CommandLine.Lookup("v"))

	rootCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for console. "+
			"Enabling this will ensure there is only one active console.")

	rdbOptions = databases.NewRDBOptions(
		databases.SetDefaultRdbLogLevel(logger.LogLevel(rdbLogLevel)),
		databases.SetDefaultRdbHost("192.168.3.10"),
		databases.SetDefaultRdbReadonlyHost("192.168.3.10"),
		databases.SetDefaultRdbPort(30036),
		databases.SetDefaultRdbDbname("ivan"))
	rdbOptions.AddFlags(rootCmd.Flags())

	flag.AddHTTPFlags(rootCmd)
	flag.AddRDBFlags(rootCmd)
	flag.AddVegetaScannerFlags(rootCmd)
	flag.AddExporterPort(rootCmd)
	flag.AddScapFlags(rootCmd)
	flag.AddRedisFlags(rootCmd)
	flag.AddElasticFlags(rootCmd)
	flag.AddHarborFlags(rootCmd)
	flag.AddSecProfilesOpts(rootCmd)
	flag.AddClusterManagerFlags(rootCmd)
	flag.AddWebHookFlags(rootCmd)
	flag.AddElectionFlags(rootCmd)

	flag.ConfigViper()
}
