package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	scapJobRepo     = "scap-job-repo"
	scapJobImageTag = "scap-job-tag"
)

type ScapOpts struct {
	HostPort string
	ImageTag string
}

func NewDefaultScapOpts() *ScapOpts {
	return &ScapOpts{
		HostPort: "localhost",
		ImageTag: "latest",
	}
}

func GetScapOpts(cmd *cobra.Command) *ScapOpts {
	return &ScapOpts{
		HostPort: viper.GetString(scapJobRepo),
		ImageTag: viper.GetString(scapJobImageTag),
	}
}

func AddScapFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultScapOpts()
	cmd.Flags().String(scapJobRepo, defaultOps.HostPort, "scap jobs docker repository address (host:port)")
	cmd.Flags().String(scapJobImageTag, defaultOps.ImageTag, "scap jobs image tag")

	for _, flag := range []string{
		scapJobRepo,
		scapJobImageTag,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
