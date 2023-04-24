package cis

import (
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func loadConfig(file, benchmarkVersion, cfgDir string) string {
	path, err := conf.GetConfigFilePath(benchmarkVersion, cfgDir, file)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("failed to get config file path")
	}

	// Merge version-specific config if any.
	conf.MergeConfig(path)

	return filepath.Join(path, file)
}
