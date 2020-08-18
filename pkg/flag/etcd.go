package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	etcdEndpoints = "etcd-endpoints"
	etcdUsername  = "etcd-username"
	etcdPassword  = "etcd-password"
)

// EtcdOpts the etcd options.
type EtcdOpts struct {
	Endpoints []string
	Username  string
	Password  string
}

// NewDefaultEtcdOpts returns a new default etcd options.
func NewDefaultEtcdOpts() *EtcdOpts {
	return &EtcdOpts{
		Endpoints: []string{"http://localhost:2379"},
		Username:  "",
		Password:  "",
	}
}

// GetEtcdOpts parses the cobra.Command and returns the EtcdOpts.
func GetEtcdOpts(cmd *cobra.Command) *EtcdOpts {
	return &EtcdOpts{
		Endpoints: viper.GetStringSlice(etcdEndpoints),
		Username:  viper.GetString(etcdUsername),
		Password:  viper.GetString(etcdPassword),
	}
}

// AddEtcdFlags adds the etcd-specific command line arguments to the cobra.Command.
func AddEtcdFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultEtcdOpts()
	cmd.Flags().StringSlice(etcdEndpoints, defaultOpts.Endpoints, "etcd endpoints")
	cmd.Flags().String(etcdUsername, defaultOpts.Username, "etcd username")
	cmd.Flags().String(etcdPassword, defaultOpts.Password, "etcd password")
	for _, flag := range []string{etcdEndpoints, etcdUsername, etcdPassword} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
