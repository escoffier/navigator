package redis

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
	CheckerName     = "Redis"
	definitionsPath = "/cis/redis/definitions.yaml"
	configPath      = "/cis/redis/config.yaml"
)

var (
	redisConfigPath = "/redis-master/redis.conf"
)

type RedisChecker struct {
	testYamlBytes    []byte
	redisConfigPaths []string
}

func (c *RedisChecker) Start(ctx context.Context) error {
	return nil
}

type confData struct {
	RedisConfigPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"redis-config-file"`
}

func getDetectPath(hostPath string, configFiles []string) string {
	for _, p := range configFiles {
		if _, err := os.Stat(hostPath + p); err == nil {
			return hostPath + p
		}
	}
	return ""
}

func (c *RedisChecker) RunChecks(ctx context.Context, path string) (check.Controller, error) {

	redisCfgPath := getDetectPath(path, c.redisConfigPaths)
	if len(redisCfgPath) == 0 {
		return nil, fmt.Errorf("no config file found in %s", path)
	}

	envs := []string{
		fmt.Sprintf("redis_config_file=%s", redisCfgPath),
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
	logging.GetLogger().Info().Str("redis config path", redisCfgPath).Msg("redis config path")
	control.RunChecksWithEnvs(runner, filter, utils.ParseSkipIds(""), envs)
	checker.WriteOutput(control.(*check.Controls))
	return control, nil
}

func (c *RedisChecker) CheckerType() string {
	return checker.ContainerType
}

func (c *RedisChecker) Name() string {
	return CheckerName
}

func loadConfig() (confData, []byte, error) {
	var conf confData
	in, err := os.ReadFile(configPath)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("read config fail")
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
	// control := getControls(definitionsPath, []string{}, "1.0")

	var configPaths []string
	conf, testYamlBytes, err := loadConfig()
	if err == nil {
		configPaths = conf.RedisConfigPath.Dirs
	} else {
		logging.GetLogger().Warn().Err(err).Msg("load config fail")
		configPaths = []string{redisConfigPath}
	}

	return &RedisChecker{
		testYamlBytes:    testYamlBytes,
		redisConfigPaths: configPaths,
	}, nil
}

func init() {
	err := checker.Register(CheckerName, newChecker)
	if err != nil {
		panic(err)
	}
}

func (c *RedisChecker) getControls(constraints []string, detectedVersion string) check.Controller {

	controls, err := check.NewControls("", c.testYamlBytes, detectedVersion, constraints)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("error setting up controls")
	}

	return controls
}
