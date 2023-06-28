package host

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-version"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/conf"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/logging"
)

func getCisVersion(stringVersion string, v *viper.Viper) (string, error) {
	if v == nil {
		return "", fmt.Errorf("viper not found")
	}

	hostVersion, err := version.NewVersion(stringVersion)
	if err != nil {
		return "", err
	}

	hostToBenchmarkMap, err := conf.LoadVersionMapping(v)
	if err != nil {
		return "", err
	}

	for benchVersion, hostConstraints := range hostToBenchmarkMap {
		currConstraints, err := version.NewConstraint(hostConstraints)
		if err != nil {
			return "", err
		}
		if currConstraints.Check(hostVersion) {
			logging.Get().Info().Msgf("host version %s satisfies constraints %s", hostVersion, currConstraints)
			return benchVersion, nil
		}
	}

	if defaultBenchVersion := v.GetString("default_cis_version"); defaultBenchVersion != "" {
		return defaultBenchVersion, nil
	}

	return "", fmt.Errorf("no suitable CIS version has been found for host version %s", stringVersion)
}

// getBenchmarkVersion returns final benchmark version to use.
func getBenchmarkVersion(benchmarkVersion string, platform Platform, v *viper.Viper) (string, error) {
	var err error

	if util.IsEmpty(benchmarkVersion) {
		benchmarkVersion, err = getCisVersion(platform.Version, v.Sub(platform.Name))
		if err != nil {
			logging.Get().Info().Msgf("默认cis基线版扫描 cis-centos-7,%v",
				fmt.Errorf("Failed to get a valid CIS benchmark version for Host version %v: %v", platform, err))
			benchmarkVersion = "cis-centos-7"
		}
	}

	return benchmarkVersion, nil
}

func (h *Host) writeOutput(controls *check.Controls) error {
	err := h.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  "host",
		TaskID:     h.opts.taskID,
		Hostname:   h.opts.nodeName,
		ClusterKey: h.opts.clusterID,
		Payload: map[string]interface{}{
			"control": controls,
		},
	})
	if err != nil {
		return fmt.Errorf("host output scan result failed,  %v", err)
	}

	logging.Get().Info().Msg("host output scan result success")
	return nil
}

func (h *Host) writeFailed(msg string) error {
	err := h.Outputter.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  "host",
		TaskID:     h.opts.taskID,
		Hostname:   h.opts.nodeName,
		ClusterKey: h.opts.clusterID,
		Payload: map[string]interface{}{
			"status":  1,
			"message": msg,
		},
	})
	if err != nil {
		logging.Get().Error().Msgf("host output scan result failed,  %v", err)
		return err
	}

	logging.Get().Info().Msgf("host output scan result success")
	return nil
}

func (h *Host) runChecks(controls check.Controller) error {
	runner := check.NewRunner(check.NewCommandFunc(nc))

	filter, err := check.NewRunFilter(h.opts.filterOpts)
	if err != nil {
		return fmt.Errorf("error setting up run filter: %v", err)
	}

	controls.RunChecks(runner, filter, check.ParseSkipIds(h.opts.skipIds))
	return nil
}

func getControls(testYamlFile string, constraints []string, detectedVersion string) (check.Controller, error) {
	in, err := os.ReadFile(testYamlFile)
	if err != nil {
		return nil, fmt.Errorf("error opening %s test file: %v", testYamlFile, err)
	}

	logging.Get().Info().Msg(fmt.Sprintf("Using test file: %s\n", testYamlFile))

	controls, err := check.NewControls("", in, detectedVersion, constraints)
	if err != nil {
		return nil, fmt.Errorf("error setting up controls: %v", err)
	}

	return controls, nil
}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func (h *Host) loadConfig(file string) (string, error) {
	path, err := conf.GetConfigFilePath(h.opts.benchmarkVersion, h.opts.cfgDir, file)
	if err != nil {
		return "", fmt.Errorf("can't find controls file in %s: %v", h.opts.cfgDir, err)
	}

	// Merge version-specific config if any.
	if err = conf.MergeConfig(path); err != nil {
		return "", err
	}

	return filepath.Join(path, file), nil
}

func getConstraints() (constraints []string, err error) {
	boot, err := getBootLoader()
	if err != nil {
		logging.Get().Warn().Msgf("Failed to get boot loader, %s", err)
	}

	syslog, err := getSystemLogManager()
	if err != nil {
		logging.Get().Warn().Msgf("Failed to get syslog tool, %s", err)
	}

	lsm, err := getLSM()
	if err != nil {
		logging.Get().Warn().Msgf("Failed to get lsm, %s", err)
	}

	nft, err := getNftables()
	if err != nil {
		logging.Get().Warn().Msgf("Failed to get lsm, %s", err)
	}

	constraints = append(constraints,
		fmt.Sprintf("boot=%s", boot),
		fmt.Sprintf("syslog=%s", syslog),
		fmt.Sprintf("lsm=%s", lsm),
		fmt.Sprintf("nft=%s", nft),
	)

	logging.Get().Info().Msgf("The constraints are:, %s", constraints)
	return constraints, nil
}
