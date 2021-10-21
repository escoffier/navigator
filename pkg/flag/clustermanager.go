package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	clusterManagerHost = "clustermanager-host"
	clusterManagerPort = "clustermanager-port"
)

// Microsegmentation
type ClusterManagerOpts struct {
	Host string
	Port int
}

// NewDefaultMicrosegmentation
func NewDefaultClusterManagerOpts() *ClusterManagerOpts {
	return &ClusterManagerOpts{
		Host: "tensorsec-cluster-manager",
		Port: 9443,
	}
}

// GetMicrosegmentation
func GetClusterManagerOpts(cmd *cobra.Command) *ClusterManagerOpts {
	return &ClusterManagerOpts{
		Host: viper.GetString(clusterManagerHost),
		Port: viper.GetInt(clusterManagerPort),
	}
}

// AddClusterManagerFlags
func AddClusterManagerFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultClusterManagerOpts()
	cmd.Flags().String(clusterManagerHost, defaultOps.Host, "clustermanager core service host")
	cmd.Flags().Int(clusterManagerPort, defaultOps.Port, "clustermanager core service port")

	for _, flag := range []string{
		clusterManagerHost,
		clusterManagerPort,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
