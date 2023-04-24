package ssh

import (
	"context"
	"fmt"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	CheckerName     = "SSH"
	definitionsPath = "/cis/ssh/definitions.yaml"
	configPath      = "/cis/ssh/config.yaml"
)

var (
	sshConfigPath = "/etc/ssh/sshd_config"
)

type SSHChecker struct {
	testYamlBytes  []byte
	sshConfigPaths []string
}

func (c *SSHChecker) Start(ctx context.Context) error {
	return nil
}

type confData struct {
	SSHConfigPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"sshd-config-file"`
}

func getDetectPath(hostPath string, configFiles []string) string {
	for _, p := range configFiles {
		logging.GetLogger().Info().Msgf("check ssh config file: %s", hostPath+p)
		if _, err := os.Stat(hostPath + p); err == nil {
			return hostPath + p
		}
	}
	return ""
}

func (c *SSHChecker) RunChecks(ctx context.Context, path string) (check.Controller, error) {

	sshCfgPath := getDetectPath(path, c.sshConfigPaths)
	if len(sshCfgPath) == 0 {
		logging.GetLogger().Warn().Msgf("no ssh config file found in %s", sshConfigPath)
		return nil, fmt.Errorf("no config file found in %s", sshConfigPath)
	}

	envs := []string{
		fmt.Sprintf("sshd_config_file=%s", sshCfgPath),
	}

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

func (c *SSHChecker) CheckerType() string {
	return checker.HostType
}

func (C *SSHChecker) Name() string {
	return CheckerName
}

func loadConfig() (confData, []byte, error) {
	var conf confData
	in, err := os.ReadFile(configPath)
	if err != nil {
		utils.ExitWithError(fmt.Errorf("error opening %s config file: %v", configPath, err))
		return conf, nil, err
	}
	err = yaml.Unmarshal(in, &conf)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("unmarshal config fail")
		return conf, nil, err
	}

	testYamlBytes, err := os.ReadFile(definitionsPath)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("read definitions fail")
	}

	return conf, testYamlBytes, err
}

func newChecker(config checker.CheckerServiceConfig) (checker.CheckerService, error) {

	var configPaths []string
	conf, testYamlBytes, err := loadConfig()
	if err == nil {
		configPaths = conf.SSHConfigPath.Dirs
	} else {
		logging.GetLogger().Warn().Err(err).Msg("load config fail")
		configPaths = []string{sshConfigPath}
	}

	return &SSHChecker{
		testYamlBytes:  testYamlBytes,
		sshConfigPaths: configPaths,
	}, nil
}

func init() {
	err := checker.Register(CheckerName, newChecker)
	if err != nil {
		panic(err)
	}
}

func (c *SSHChecker) getControls(constraints []string, detectedVersion string) check.Controller {

	controls, err := check.NewControls("", c.testYamlBytes, detectedVersion, constraints)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("error setting up controls")
	}

	return controls
}
