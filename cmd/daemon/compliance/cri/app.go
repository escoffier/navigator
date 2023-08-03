package cri

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/conf"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/logging"
)

// getBenchmarkVersion returns final benchmark version to use.
func getBenchmarkVersion(benchmarkVersion string, platform Platform, v *viper.Viper) (string, error) {
	var err error

	if utils.IsEmpty(benchmarkVersion) {
		// Set appropriate  CIS benchmark version according to docker version
		benchmarkVersion, err = getCriCisVersion(platform, v)
		if err != nil {
			return "", fmt.Errorf("failed to get a valid CIS benchmark version for CRI version %s: %v", platform.String(), err)
		}

		if platform.Name == RuntimeDocker {
			// fixed benchmark version
			logging.Get().Info().Msgf("替换cis基线版本为 %s=>cis-1.2", benchmarkVersion)
			benchmarkVersion = "cis-1.2"
		}
	}

	return benchmarkVersion, nil
}

func (c *Cri) runChecks(controls check.Controller) error {
	runner := check.NewRunner(check.NewCommandFunc(nc))
	filter, err := check.NewRunFilter(c.opts.filterOpts)
	if err != nil {
		return fmt.Errorf("error setting up run filter: %v", err)
	}

	controls.RunChecks(runner, filter, check.ParseSkipIds(c.opts.skipIds))
	return nil
}

func (c *Cri) writeOutput(controls *check.Controls) error {
	err := c.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  string(model.ComplianceCheckTargetTypeCRI),
		TaskID:     c.opts.taskID,
		Hostname:   c.opts.nodeName,
		ClusterKey: c.opts.clusterID,
		Payload: map[string]interface{}{
			"control": controls,
		},
	})
	if err != nil {
		return fmt.Errorf("output scan result failed,  %v", err)
	}

	logging.Get().Info().Msg("output scan result success")
	return nil
}

func (c *Cri) writeFailed(msg string) error {
	err := c.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  "cri",
		TaskID:     c.opts.taskID,
		Hostname:   c.opts.nodeName,
		ClusterKey: c.opts.clusterID,
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

func (c *Cri) getControls(testYamlFile string, constraints []string) (check.Controller, error) {
	in, err := os.ReadFile(testYamlFile)
	if err != nil {
		return nil, fmt.Errorf("error opening %s test file: %v", testYamlFile, err)
	}

	logging.Get().Info().Msg(fmt.Sprintf("Using test file: %s\n", testYamlFile))

	storagemap, _ := getFiles(c.v, "storage", c.chroot)
	runstoragemap, _ := getFiles(c.v, "runstorage", c.chroot)
	logmap, _ := getFiles(c.v, "log", c.chroot)
	confmap, _ := getFiles(c.v, "config", c.chroot)

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s, _ = conf.MakeSubstitutions(s, "storage", storagemap)
	s, _ = conf.MakeSubstitutions(s, "runstorage", runstoragemap)
	s, _ = conf.MakeSubstitutions(s, "conf", confmap)
	s, _ = conf.MakeSubstitutions(s, "log", logmap)

	controls, err := check.NewControls("", []byte(s), c.detectedCriVersion, constraints)
	if err != nil {
		return nil, fmt.Errorf("error setting up controls: %v", err)
	}

	return controls, nil
}

func getConstraints() (constraints []string, err error) {
	swarmStatus, err := getDockerSwarm()
	if err != nil {
		logging.Get().Info().Msg(fmt.Sprintf("Failed to get docker swarm status, %s", err))
	}

	constraints = append(constraints,
		fmt.Sprintf("docker-swarm=%s", swarmStatus),
	)

	logging.Get().Info().Msgf("The constraints are:, %s", constraints)
	return constraints, nil
}

func getCriCisVersion(platform Platform, v *viper.Viper) (string, error) {
	criVersion, err := trimVersion(platform.Version)

	if err != nil {
		return "", err
	}

	criToBenchmarkMap, err := conf.LoadVersionMapping(v, platform.Name)
	if err != nil {
		return "", err
	}

	for benchVersion, criConstraints := range criToBenchmarkMap {
		currConstraints, err := version.NewConstraint(criConstraints)
		if err != nil {
			return "", err
		}
		if currConstraints.Check(criVersion) {
			logging.Get().Info().Msgf("cri version %s satisfies constraints %s", platform.String(), currConstraints)
			return benchVersion, nil
		}
	}

	if platform.Name == RuntimeDocker {
		tooOldVersion, err := version.NewConstraint("< 1.13.0")
		if err != nil {
			return "", err
		}

		// Vesions before 1.13.0 are not supported by CIS.
		if tooOldVersion.Check(criVersion) {
			return "", fmt.Errorf("docker version %s is too old", criVersion)
		}
	}

	return "", fmt.Errorf("no suitable CIS version has been found for docker version %s", criVersion)
}

// TrimVersion function remove all Matadate or  Prerelease parts
// because constraints.Check() can't handle comparison with it.
func trimVersion(stringVersion string) (*version.Version, error) {
	currVersion, err := version.NewVersion(stringVersion)
	if err != nil {
		return nil, err
	}

	if currVersion.Metadata() != "" || currVersion.Prerelease() != "" {
		tempStrVersion := strings.Trim(strings.Replace(fmt.Sprint(currVersion.Segments()), " ", ".", -1), "[]")
		currVersion, err = version.NewVersion(tempStrVersion)
		if err != nil {
			return nil, err
		}
	}

	return currVersion, nil
}
