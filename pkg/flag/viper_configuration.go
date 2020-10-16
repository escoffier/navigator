package flag

import (
	"strings"

	"github.com/spf13/viper"
)

func ConfigViper() {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("TENSORSEC")
	viper.AutomaticEnv()
}
