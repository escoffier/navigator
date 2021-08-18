package processors

import (
	flag "github.com/spf13/pflag"
	"path/filepath"
)

const (
	ConfigBasePath = "/etc/tensorsec/config"
)

var configBasePath string

type ValidatorConfig struct {
	ImageValidateServer string
}

func GetConfigFullPath(configFile string) string {
	return filepath.Join(configBasePath, configFile)
	//return configBasePath + configFile
}

func init() {
	flag.StringVar(&configBasePath, "config base path", ConfigBasePath, "The path of tls cert")
}
