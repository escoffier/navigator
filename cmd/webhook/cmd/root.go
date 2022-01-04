package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd/webhook"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"os"
	"strings"
)

var webHookConfig = &webhook.Config{}

func NewWebhookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				logging.SetVerbose()
			}

			loadConfigFromEnv()
			server, err := webhook.NewWebHookServer(webHookConfig)
			if err != nil {
				logging.GetLogger().Err(err).Msg("failed to create webhook server")
				return err
			}

			// start inject server in new routine
			server.Start()
			logging.GetLogger().Info().Msg("Server started")
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
}
