package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	secProfilesHost = "security-profiles-host"
	secProfilesPort = "security-profiles-port"
)

// SecProfilesOpts
type SecProfilesOpts struct {
	Host string
	Port int
}

// NewSecProfilesOpts
func NewDefaultSecProfilesOpts() *SecProfilesOpts {
	return &SecProfilesOpts{
		Host: "tensorsec-sec-prof-man",
		Port: 8887,
	}
}

// GetSecProfilesOpts
func GetSecProfilesOpts(cmd *cobra.Command) *SecProfilesOpts {
	return &SecProfilesOpts{
		Host: viper.GetString(secProfilesHost),
		Port: viper.GetInt(secProfilesPort),
	}
}

// AddSecProfilesOpts
func AddSecProfilesOpts(cmd *cobra.Command) {
	defaultOps := NewDefaultSecProfilesOpts()
	cmd.Flags().String(secProfilesHost, defaultOps.Host, "security profiles core service host")
	cmd.Flags().Int(secProfilesPort, defaultOps.Port, "security profiles core service port")

	for _, flag := range []string{
		secProfilesHost,
		secProfilesPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
