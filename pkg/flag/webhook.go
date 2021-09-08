package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	webhookHost = "webhook-host"
	webhookPort = "webhook-port"
)

type WebHookOpts struct {
	Host string
	Port int
}

func NewDefaultWebHookOpts() *WebHookOpts {
	return &WebHookOpts{
		Host: "tensorsec-webhook",
		Port: 443,
	}
}

func GetWebHookOpts(cmd *cobra.Command) *WebHookOpts {
	return &WebHookOpts{
		Host: viper.GetString(webhookHost),
		Port: viper.GetInt(webhookPort),
	}
}

func AddWebHookFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultWebHookOpts()
	cmd.Flags().String(webhookHost, defaultOps.Host, "webhook service host")
	cmd.Flags().Int(webhookPort, defaultOps.Port, "webhook service port")

	for _, flag := range []string{
		webhookHost,
		webhookPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
