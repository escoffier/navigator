package register

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// File represents a YAML configuration file that namespaces all scanner
// configuration under the top-level "scanner" key.
type File struct {
	Scanner []Config `yaml:"scanner"`
}

// Config is the global configuration for an instance of scanner.
type Config struct {
	Registry   RegistrableComponentConfig `yaml:"registry"`
	RegistryID int64
}

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() []Config {
	tmp := Config{
		Registry: RegistrableComponentConfig{
			Type: "cnvd",
		},
	}
	var defaultConfig []Config
	defaultConfig = append(defaultConfig, tmp)
	return defaultConfig
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config []Config, err error) {
	var cfgFile File
	cfgFile.Scanner = DefaultConfig()
	if path == "" {
		return cfgFile.Scanner, nil
	}

	f, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	config = cfgFile.Scanner
	fmt.Printf("Config为: %v", config)
	return
}
