package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	microsegmentationHost = "microsegmentation-host"
	microsegmentationPort = "microsegmentation-port"
)

// Microsegmentation
type MicrosegmentationOpts struct {
	Host string
	Port int
}

// NewDefaultMicrosegmentation
func NewDefaultMicrosegmentationOpts() *MicrosegmentationOpts {
	return &MicrosegmentationOpts{
		Host: "tensorsec-calico-core",
		Port: 2137,
	}
}

// GetMicrosegmentation
func GetMicrosegmentationOpts(cmd *cobra.Command) *MicrosegmentationOpts {
	return &MicrosegmentationOpts{
		Host: viper.GetString(microsegmentationHost),
		Port: viper.GetInt(microsegmentationPort),
	}
}

// AddMicrosegmentationFlags
func AddMicrosegmentationFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultMicrosegmentationOpts()
	cmd.Flags().String(microsegmentationHost, defaultOps.Host, "microsegmentation core service host")
	cmd.Flags().Int(microsegmentationPort, defaultOps.Port, "microsegmentation core service port")

	for _, flag := range []string{
		microsegmentationHost,
		microsegmentationPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
