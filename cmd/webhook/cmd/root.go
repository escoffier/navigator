package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd/webhook"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	webHookConfig = &webhook.Config{
		Timeout:     6,
		Concurrency: 100,
	}
	loggingOptions *logging.Options
)

func NewWebhookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if errs := loggingOptions.Validate(); len(errs) > 0 {
				return fmt.Errorf("%v", errs)
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

			loadConfigFromEnv()
			server, err := webhook.NewWebHookServer(webHookConfig)
			if err != nil {
				logging.Get().Err(err).Msg("failed to create webhook server")
				return err
			}

			// start inject server in new routine
			server.Start()
			logging.Get().Info().Msg("Server started")
			return nil
		},
	}
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")
	cmd.Flags().IntVar(&webHookConfig.Port, "port", 9443, "The port of inject server to listen.")
	cmd.Flags().StringVar(&webHookConfig.CertFile, "tlsCertPath", "/etc/webhook/certs/tls.crt", "The path of tls cert")
	cmd.Flags().StringVar(&webHookConfig.KeyFile, "tlsKeyPath", "/etc/webhook/certs/tls.key", "The path of tls key")
	cmd.Flags().StringSliceVar(&webHookConfig.IgnoredNameSpaces, "IgnoredNameSpaces", []string{"kube-system", "tensorsec"}, "The ignored namespaces for image checking")
	cmd.Flags().StringSliceVar(&webHookConfig.Validators, "validators", nil, "The enabled validators")
	cmd.Flags().StringSliceVar(&webHookConfig.Mutators, "mutators", nil, "The enabled mutators")

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(cmd.Flags())

	cmd.AddCommand(NewProxyCmd())
	return cmd
}

func loadConfigFromEnv() {
	validators := os.Getenv("VALIDATORS")
	if validators != "" {
		vs := strings.Split(validators, ",")
		webHookConfig.Validators = vs
	}

	mutators := os.Getenv("MUTATORS")
	if mutators != "" {
		ms := strings.Split(mutators, ",")
		webHookConfig.Mutators = ms
	}
	timeOut := os.Getenv("TIMEOUT")
	if timeOut != "" {
		t, err := strconv.ParseInt(timeOut, 10, 32)
		if err != nil {
			logging.Get().Err(err).Msgf("parse timeout :%s err", timeOut)
		} else {
			webHookConfig.Timeout = int32(t)
		}
	}

	concurrency := os.Getenv("CONCURRENCY")
	if concurrency != "" {
		t, err := strconv.ParseInt(concurrency, 10, 32)
		if err != nil {
			logging.Get().Err(err).Msgf("parse concurrency :%s err", concurrency)
		} else {
			webHookConfig.Concurrency = int32(t)
		}
	}
}
