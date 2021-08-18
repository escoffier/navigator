package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	scapJobRepo     = "scap-job-repo"
	scapJobImageTag = "scap-job-tag"
	policyCounts    = "policy-counts"
)

type ScapOpts struct {
	HostPort     string
	ImageTag     string
	PolicyCounts int32
}

func NewDefaultScapOpts() *ScapOpts {
	return &ScapOpts{
		HostPort:     "localhost",
		ImageTag:     "latest",
		PolicyCounts: 285,
	}
}

func GetScapOpts(cmd *cobra.Command) *ScapOpts {
	return &ScapOpts{
		HostPort:     viper.GetString(scapJobRepo),
		ImageTag:     viper.GetString(scapJobImageTag),
		PolicyCounts: viper.GetInt32(policyCounts),
	}
}

func AddScapFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultScapOpts()
	cmd.Flags().String(scapJobRepo, defaultOps.HostPort, "scap jobs docker repository address (host:port)")
	cmd.Flags().String(scapJobImageTag, defaultOps.ImageTag, "scap jobs image tag")
	cmd.Flags().Int32(policyCounts, defaultOps.PolicyCounts, "policy counts")

	for _, flag := range []string{
		scapJobRepo,
		scapJobImageTag,
		policyCounts,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
