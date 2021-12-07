package processors

import (
	"path/filepath"

	flag "github.com/spf13/pflag"
	"gorm.io/gorm"
)

const (
	DefaultBasePath = "/etc/webhook/config"
)

var ConfigBasePath string

type WebHookConfig struct {
	RDB *gorm.DB
}

func GetConfigFullPath(configFile string) string {
	return filepath.Join(ConfigBasePath, configFile)
}

func init() {
	flag.StringVar(&ConfigBasePath, "config base path", DefaultBasePath, "The path of tls cert")
}
