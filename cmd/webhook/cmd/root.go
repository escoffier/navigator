package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd/webhook"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
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
	cmd.Flags().StringVar(&webHookConfig.CertFile, "tlsCertPath", "/etc/tensorsec/certs/tls.crt", "The path of tls cert")
	cmd.Flags().StringVar(&webHookConfig.KeyFile, "tlsKeyPath", "/etc/tensorsec/certs/tls.key", "The path of tls key")
	//cmd.Flags().StringVar(&webHookConfig.ImageValidateServer, "validateserver", "127.0.0.1:80", "The URL of tls image checking server")
	cmd.Flags().StringSliceVar(&webHookConfig.IgnoredNameSpaces, "IgnoredNameSpaces", []string{"kube-system", "tensorsec"}, "The ignored namespaces for image checking")
	cmd.Flags().StringSliceVar(&webHookConfig.Validators, "validators", nil, "The enabled validators")
	cmd.Flags().StringSliceVar(&webHookConfig.Mutators, "mutators", nil, "The enabled mutators")

	cmd.AddCommand(NewProxyCmd())
	return cmd
}
