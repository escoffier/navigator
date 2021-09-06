package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	stanClusterID = "stan-cluster-id"
	stanClientID  = "stan-client-id"
	stanURL       = "stan-url"
)

// StanOpts the Stan options.
type StanOpts struct {
	ClusterID string
	ClientID  string
	URL       string
}

// NewDefaultStanOpts returns a new default Stan options.
func NewDefaultStanOpts() *StanOpts {
	return &StanOpts{
		ClusterID: "stan",
		ClientID:  "app",
		URL:       "nats://localhost:4222",
	}
}

// GetStanOpts parses the cobra.Command and returns the StanOpts.
func GetStanOpts(cmd *cobra.Command) *StanOpts {
	return &StanOpts{
		ClusterID: viper.GetString(stanClusterID),
		ClientID:  viper.GetString(stanClientID),
		URL:       viper.GetString(stanURL),
	}
}

// AddStanFlags adds the Stan-specific command line arguments to the cobra.Command.
func AddStanFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultStanOpts()
	cmd.PersistentFlags().String(stanClusterID, defaultOpts.ClusterID, "Stan cluster id")
	cmd.PersistentFlags().String(stanClientID, defaultOpts.ClientID, "Stan client id")
	cmd.PersistentFlags().String(stanURL, defaultOpts.URL, "Stan server URL")
	for _, flag := range []string{stanClusterID, stanClientID, stanURL} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
