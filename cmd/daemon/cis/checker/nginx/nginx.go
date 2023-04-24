package nginx

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	CheckerName     = "Nginx"
	definitionsPath = "/cis/nginx/definitions.yaml"
	configPath      = "/cis/nginx/config.yaml"
)

type NginxChecker struct {
	testYamlBytes    []byte
	nginxConfigPaths map[string][]string
}

type confData struct {
	NginxConfigPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"nginx-config-file"`
	NginxBinPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"nginx-bin-path"`
	NginxEtcPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"nginx-etc-path"`
	NginxLogPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"nginx-log-path"`
}

func setCheckEnvs(
	foundPath map[string]string,
	containerPath string) []string {
	var envs []string
	for key, value := range foundPath {
		envs = append(envs, fmt.Sprintf("%s=%s", strings.ReplaceAll(key, "-", "_"), value))
	}
	return envs
}

func getDetectPaths(hostPath string, nginxConfigPaths map[string][]string) (map[string]string, error) {
	foundPath := make(map[string]string)
	for key, value := range nginxConfigPaths {
		for _, p := range value {
			if _, err := os.Stat(hostPath + p); err == nil {
				foundPath[key] = hostPath + p
			}
		}
	}
	if len(foundPath) == 0 {
		return nil, fmt.Errorf("no config file found in %s", hostPath)
	}
	if _, ok := foundPath["nginx-config-file"]; !ok {
		return nil, fmt.Errorf("no nginx bin file found in %s", hostPath)
	}
	if _, ok := foundPath["nginx-etc-path"]; !ok {
		return nil, fmt.Errorf("no nginx etc file found in %s", hostPath)
	}
	if _, ok := foundPath["nginx-log-path"]; !ok {
		foundPath["nginx-log-path"] = "/var/log/nginx"
	}
	if _, ok := foundPath["nginx-bin-path"]; !ok {
		foundPath["nginx-bin-path"] = "/usr/sbin/nginx"
	}

	return foundPath, nil
}

func (c *NginxChecker) Start(ctx context.Context) error {
	return nil
}

func (c *NginxChecker) RunChecks(ctx context.Context, path string) (check.Controller, error) {
	foundPath, err := getDetectPaths(path, c.nginxConfigPaths)
	if err != nil {
		return nil, err
	}
	envs := setCheckEnvs(foundPath, path)
	control := c.getControls([]string{}, "1.0")
	runner := check.NewRunner()
	filter, err := check.NewRunFilter(check.FilterOpts{
		Scored:   true,
		Unscored: true,
	})
	if err != nil {
		return nil, err
	}
	control.RunChecksWithEnvs(runner, filter, utils.ParseSkipIds(""), envs)
	checker.WriteOutput(control.(*check.Controls))
	return control, nil
}

func (c *NginxChecker) CheckerType() string {
	return checker.ContainerType
}

func (c *NginxChecker) Name() string {
	return CheckerName
}

func loadConfig() (confData, []byte, error) {
	var conf confData
	in, err := os.ReadFile(configPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("failed to read config file: %s", configPath)
		return conf, nil, err
	}
	err = yaml.Unmarshal(in, &conf)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("failed to unmarshal config file: %s", configPath)
		return conf, nil, err
	}
	testYamlBytes, err := os.ReadFile(definitionsPath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("failed to read test yaml file: %s", definitionsPath)
		return conf, nil, err
	}
	return conf, testYamlBytes, nil
}

func newChecker(config checker.CheckerServiceConfig) (checker.CheckerService, error) {
	conf, testYamlBytes, err := loadConfig()
	if err != nil {
		return nil, err
	}
	nginxConfigPaths := make(map[string][]string)
	nginxConfigPaths["nginx-config-file"] = conf.NginxConfigPath.Dirs
	nginxConfigPaths["nginx-bin-path"] = conf.NginxBinPath.Dirs
	nginxConfigPaths["nginx-etc-path"] = conf.NginxEtcPath.Dirs
	nginxConfigPaths["nginx-log-path"] = conf.NginxLogPath.Dirs
	return &NginxChecker{
		nginxConfigPaths: nginxConfigPaths,
		testYamlBytes:    testYamlBytes,
	}, nil
}

func init() {
	err := checker.Register(CheckerName, newChecker)
	if err != nil {
		panic(err)
	}
}

func (c *NginxChecker) getControls(constraints []string, detectedVersion string) check.Controller {

	controls, err := check.NewControls("", c.testYamlBytes, detectedVersion, constraints)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("error setting up controls")
	}

	return controls
}
