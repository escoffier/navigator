package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gopkg.in/yaml.v2"
)

// File represents a YAML configuration file that namespaces all scanner
// configuration under the top-level "scanner" key.
type File struct {
	Scanner Config `yaml:"scanner"`
}

// Config is the global configuration for an instance of scanner.
type Config struct {
	Registry   registry.RegistrableComponentConfig
	RegistryID int64
}

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		Registry: registry.RegistrableComponentConfig{
			Type: "harbor-v2.0",
		},
	}
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config *Config, err error) {
	var cfgFile File
	cfgFile.Scanner = DefaultConfig()
	if path == "" {
		return &cfgFile.Scanner, nil
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.Scanner

	return
}

func LoadConfigFromDb(psql *component.ScannerDB) (*Config, error) {
	var config Config
	tmpMap := make(map[string]interface{})
	tmpRegistry := psql.FindRegistryAll() //单仓库
	tmpMap["url"] = tmpRegistry.Url
	tmpMap["username"] = tmpRegistry.Username
	key := []byte("talkerss")
	decryPass, err := util.DesDecrypt(tmpRegistry.Password, key)
	if err != nil {
		return nil, fmt.Errorf("Can't parse passwd")
	}
	tmpMap["password"] = string(decryPass)
	tmpMap["skiptlsverify"] = true
	config.Registry.Type = tmpRegistry.ApiVersion
	config.Registry.Options = tmpMap
	config.RegistryID = int64(tmpRegistry.ID)
	return &config, nil
}
