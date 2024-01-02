package opt

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	FlagConfigFile = "config"
)

type Option struct {
	ConfigFile string
}

func GetOptionByViper() Option {
	return Option{
		ConfigFile: viper.GetString(FlagConfigFile),
	}
}

func AddNodeImageOpts(nodeImageCmd *cobra.Command) {
	nodeImageCmd.Flags().StringP(FlagConfigFile, "c", "node-image.yaml", "config file")

	// bind viper
	for _, flag := range []string{
		FlagConfigFile,
	} {
		err := viper.BindPFlag(flag, nodeImageCmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}

	// set env binding.if flag value not set,will get value from env
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}
