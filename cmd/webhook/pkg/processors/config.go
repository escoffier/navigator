package processors

import (
	flag "github.com/spf13/pflag"
	"path/filepath"
)

const (
	DefaultBasePath = "/etc/tensorsec/config"
)

var ConfigBasePath string

type ValidatorConfig struct {
	ImageValidateServer string
}

func GetConfigFullPath(configFile string) string {
	return filepath.Join(ConfigBasePath, configFile)
}

func init() {
	flag.StringVar(&ConfigBasePath, "config base path", DefaultBasePath, "The path of tls cert")
}
