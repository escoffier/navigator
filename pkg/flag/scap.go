package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

const (
	policyCounts = "policy-counts"
)

type ScapOpts struct {
	PolicyCounts int32
	ClusterAddr  string
}

func NewDefaultScapOpts() *ScapOpts {
	return &ScapOpts{
		PolicyCounts: 285,
		ClusterAddr:  "",
	}
}

func GetScapOpts(cmd *cobra.Command) *ScapOpts {
	return &ScapOpts{
		PolicyCounts: viper.GetInt32(policyCounts),
		ClusterAddr:  os.Getenv("CLUSTER_MANAGER_URL"),
	}
}

func AddScapFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultScapOpts()
	cmd.Flags().Int32(policyCounts, defaultOps.PolicyCounts, "policy counts")

	for _, flag := range []string{
		policyCounts,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
