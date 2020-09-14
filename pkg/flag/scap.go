package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	scapJobRepo = "scap-job-repo"
)

type ScapOpts struct {
	HostPort string
}

func NewDefaultScapOpts() *ScapOpts {
	return &ScapOpts{
		HostPort: "localhost",
	}
}

func GetScapOpts(cmd *cobra.Command) *ScapOpts {
	return &ScapOpts{
		HostPort: viper.GetString(scapJobRepo),
	}
}

func AddScapFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultScapOpts()
	cmd.Flags().String(scapJobRepo, defaultOps.HostPort, "scap jobs docker repository address (host:port)")

	for _, flag := range []string{
		scapJobRepo,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
