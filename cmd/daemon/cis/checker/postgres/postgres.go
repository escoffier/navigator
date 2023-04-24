package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	CheckerName     = "Postgres"
	definitionsPath = "/cis/postgres/definitions.yaml"
	configPath      = "/cis/postgres/config.yaml"
)

type PostgresChecker struct {
	testYamlBytes       []byte
	postgresConfigPaths map[string][]string
}

type confData struct {
	PostgresConfigFileTemplate struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"postgres-config-file"`
	PostgresConfigPath struct {
		Dirs []string `yaml:"dirs"`
	} `yaml:"postgres-config-path"`
	PostgresConfigName []string `yaml:"postgres-config-name"`
}

func (c *PostgresChecker) Start(ctx context.Context) error {
	return nil
}

func getAllConfigFilesInDir(dir string) ([]string, error) {
	files := []string{}
	visit := func(path string, di fs.DirEntry, err error) error {
		// fmt.Printf("Visited: %s\n", path)
		if err != nil {
			return err
		}
		if di.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}
	err := filepath.WalkDir(dir, visit)
	return files, err

}

func getDetectPath(hostPath string, configFiles map[string][]string) string {
	for _, p := range configFiles["path"] {
		verifyPgPath := ""
		hostPgConfigPath := hostPath + p
		logging.GetLogger().Info().Msgf("check path: %s", hostPgConfigPath)
		if _, err := os.Stat(hostPgConfigPath); err == nil {
			verifyPgPath = hostPgConfigPath
		}

		if len(verifyPgPath) == 0 {
			logging.GetLogger().Warn().Msgf("no path %s", hostPgConfigPath)
			continue
		}

		files, err := getAllConfigFilesInDir(verifyPgPath)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("failed to read config file: %s", verifyPgPath)
			continue
		}
		if len(files) == 0 {
			logging.GetLogger().Warn().Msgf("no config file found in %s", verifyPgPath)
			continue
		}
		for _, f := range files {
			for _, n := range configFiles["name"] {
				if n == filepath.Base(f) {
					return f
				}
			}
		}
	}
	return ""
}

func (c *PostgresChecker) RunChecks(ctx context.Context, path string) (check.Controller, error) {
	postgresCfgPath := getDetectPath(path, c.postgresConfigPaths)
	if len(postgresCfgPath) == 0 {
		return nil, fmt.Errorf("no config file found in %s", path)
	}

	envs := []string{
		fmt.Sprintf("postgresql_config_file=%s", postgresCfgPath),
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

func (c *PostgresChecker) CheckerType() string {
	return checker.ContainerType
}

func (C *PostgresChecker) Name() string {
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

	postgresConfigPaths := make(map[string][]string)
	postgresConfigPaths["template"] = conf.PostgresConfigFileTemplate.Dirs
	postgresConfigPaths["path"] = conf.PostgresConfigPath.Dirs
	postgresConfigPaths["name"] = conf.PostgresConfigName
	return &PostgresChecker{
		testYamlBytes:       testYamlBytes,
		postgresConfigPaths: postgresConfigPaths,
	}, nil
}

func init() {
	err := checker.Register(CheckerName, newChecker)
	if err != nil {
		panic(err)
	}
}

func (c *PostgresChecker) getControls(constraints []string, detectedVersion string) check.Controller {

	controls, err := check.NewControls("", c.testYamlBytes, detectedVersion, constraints)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("error setting up controls")
	}

	return controls
}
