package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	microsegHost = "microseg-host"
	microsegPort = "microseg-port"
)

// Microsegmentation
type MicrosegOpts struct {
	Host string
	Port int
}

// NewDefaultMicrosegmentation
func NewDefaultMicrosegOpts() *MicrosegOpts {
	return &MicrosegOpts{
		Host: "tensorsec-microseg",
		Port: 8090,
	}
}

// GetMicrosegmentation
func GetMicrosegOpts(cmd *cobra.Command) *MicrosegOpts {
	return &MicrosegOpts{
		Host: viper.GetString(microsegHost),
		Port: viper.GetInt(microsegPort),
	}
}

// AddMicrosegmentationFlags
func AddMicrosegmentationFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultMicrosegOpts()
	cmd.Flags().String(microsegHost, defaultOps.Host, "microsegmentation core service host")
	cmd.Flags().Int(microsegPort, defaultOps.Port, "microsegmentation core service port")

	for _, flag := range []string{
		microsegHost,
		microsegPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
