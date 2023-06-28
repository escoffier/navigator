package cri

import (
	"path/filepath"

	"github.com/spf13/viper"
	"gitlab.com/security-rd/go-pkg/cis/conf"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	TypeMap = map[string][]string{
		"storage": {"storages", "defaultstorage"},
		"config":  {"confs", "defaultconf"},
		"log":     {"logs", "defaultlog"},
	}
)

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func (c *Cri) loadConfig(file string) (string, error) {
	path, err := conf.GetConfigFilePath(c.opts.benchmarkVersion, c.opts.cfgDir, file)
	if err != nil {
		logging.Get().Warn().Msgf("can't find controls file in %s: %v", c.opts.cfgDir, err)
		return "", nil
	}

	// Merge version-specific config if any.
	if err = conf.MergeConfig(path); err != nil {
		return "", err
	}

	return filepath.Join(path, file), nil
}

// getFiles finds which of the set of candidate files exist
func getFiles(v *viper.Viper, fileType, pathPrefix string) (map[string]string, error) {
	m, err := conf.GetFiles(v, TypeMap, fileType, pathPrefix)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("getFiles error")
		return nil, err
	}

	return m, nil
}
