package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	exporterHost = "exporter-host"
	exporterPort = "exporter-port"
)

type ExporterOpts struct {
	Host string
	Port int
}

func NewDefaultExporterOpts() *ExporterOpts {
	return &ExporterOpts{
		Host: "exporter",
		Port: 8080,
	}
}

func GetExporterOpts(cmd *cobra.Command) *ExporterOpts {
	return &ExporterOpts{
		Host: viper.GetString(exporterHost),
		Port: viper.GetInt(exporterPort),
	}
}

func AddExporterPort(cmd *cobra.Command) {
	defaultOps := NewDefaultExporterOpts()
	cmd.Flags().String(exporterHost, defaultOps.Host, "exporter host")
	cmd.Flags().Int(exporterPort, defaultOps.Port, "exporter port")

	for _, flag := range []string{
		exporterHost,
		exporterPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
