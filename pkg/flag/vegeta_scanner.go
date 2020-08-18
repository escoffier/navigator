package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	vegetaScannerHost = "vegeta-scanner-host"
	vegetaScannerPort = "vegeta-scanner-port"
)

// VegetaScannerOpts the vegeta scanner options
type VegetaScannerOpts struct {
	Host string
	Port int
}

// NewDefaultVegetaScannerOpts the new default vegetaScanner options.
func NewDefaultVegetaScannerOpts() *VegetaScannerOpts {
	return &VegetaScannerOpts{
		Host: "scanner",
		Port: 8080,
	}
}

// GetVegetaScannerOpts parses the cobra.Command and returns the EtcdOpts.
func GetVegetaScannerOpts(cmd *cobra.Command) *VegetaScannerOpts {
	return &VegetaScannerOpts{
		Host: viper.GetString(vegetaScannerHost),
		Port: viper.GetInt(vegetaScannerPort),
	}
}

// AddVegetaScannerFlags adds the vegeta scanner configuration command line options.
func AddVegetaScannerFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultVegetaScannerOpts()
	cmd.Flags().String(vegetaScannerHost, defaultOps.Host, "vegeta scanner host")
	cmd.Flags().Int(vegetaScannerPort, defaultOps.Port, "vegeta scanner port")

	for _, flag := range []string{
		vegetaScannerHost,
		vegetaScannerPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
