package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/image-validate/cmd/webhook"
)

var webHookConfig = &webhook.Config{}

func NewWebhookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			server, err := webhook.NewWebHookServer(webHookConfig)
			if err != nil {
				log.Errorf("failed to create webhook server : %v", err)
				return err
			}

			// start inject server in new routine
			server.Start()
			log.Info("Server started")
			return nil
		},
	}

	cmd.Flags().IntVar(&webHookConfig.Port, "port", 9443, "The port of inject server to listen.")
	cmd.Flags().StringVar(&webHookConfig.CertFile, "tlsCertPath", "/etc/tensorsec/certs/tls.crt", "The path of tls cert")
	cmd.Flags().StringVar(&webHookConfig.KeyFile, "tlsKeyPath", "/etc/tensorsec/certs/tls.key", "The path of tls key")
	cmd.Flags().StringVar(&webHookConfig.ImageValidateServer, "validateserver", "", "The URL of tls image checking server")
	cmd.Flags().StringSliceVar(&webHookConfig.IgnoredNameSpaces, "IgnoredNameSpaces", []string{"kube-system", "tensorsec"}, "The ignored namespaces for image checking")
	return cmd
}
