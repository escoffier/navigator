package kube

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/conf"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/logging"
)

func (k *Kube) runChecks(nodetype check.NodeType, testYamlFile string) error {
	in, err := os.ReadFile(testYamlFile)
	if err != nil {
		logging.Get().Error().Msgf("error opening %s test file: %v", testYamlFile, err)
		return err
	}

	logging.Get().Info().Msg(fmt.Sprintf("Using test file: %s\n", testYamlFile))

	// Get the viper config for this section of tests
	typeConf := k.v.Sub(string(nodetype))
	if typeConf == nil {
		return fmt.Errorf("No config settings for %s\n", string(nodetype))
	}

	// Get the set of executables we need for this section of the tests
	binmap, err := getBinariesFunc(typeConf, nodetype)
	// Checks that the executables we need for the section are running.
	if err != nil {
		logging.Get().Warn().Msg(fmt.Sprintf("failed to get a set of executables needed for tests: %v", err))
	}

	confmap, _ := getFiles(typeConf, "config", k.chroot)
	svcmap, _ := getFiles(typeConf, "service", k.chroot)
	kubeconfmap, _ := getFiles(typeConf, "kubeconfig", k.chroot)
	cafilemap, _ := getFiles(typeConf, "ca", k.chroot)

	// add after fork
	getVariateValue("bin", k.autoVariate, binmap)
	getVariateValue("conf", k.autoVariate, confmap)
	getVariateValue("svc", k.autoVariate, svcmap)
	getVariateValue("kubeconfig", k.autoVariate, kubeconfmap)
	getVariateValue("cafile", k.autoVariate, cafilemap)

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s, binSubs := conf.MakeSubstitutions(s, "bin", binmap)
	s, _ = conf.MakeSubstitutions(s, "conf", confmap)
	s, _ = conf.MakeSubstitutions(s, "svc", svcmap)
	s, _ = conf.MakeSubstitutions(s, "kubeconfig", kubeconfmap)
	s, _ = conf.MakeSubstitutions(s, "cafile", cafilemap)

	controls, err := check.NewControls(nodetype, []byte(s), k.detectedKubeVersion, nil)
	if err != nil {
		logging.Get().Error().Msgf("error setting up %s controls: %v", nodetype, err)
		return err
	}

	runner := check.NewRunner(check.NewCommandFunc(nc))
	filter, err := check.NewRunFilter(k.opts.FilterOpts)
	if err != nil {
		logging.Get().Error().Msgf("error setting up run filter: %v", err)
		return err
	}

	generateDefaultEnvAudit(controls.(*check.Controls), binSubs)

	controls.RunChecks(runner, filter, check.ParseSkipIds(k.opts.SkipIds))
	k.controlsCollection = append(k.controlsCollection, controls.(*check.Controls))
	return nil
}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func (k *Kube) loadConfig(nodetype check.NodeType) (string, error) {
	var file string

	switch nodetype {
	case check.MASTER:
		file = k.opts.MasterFile
	case check.NODE:
		file = k.opts.NodeFile
	case check.CONTROLPLANE:
		file = k.opts.ControlplaneFile
	case check.ETCD:
		file = k.opts.EtcdFile
	case check.POLICIES:
		file = k.opts.PoliciesFile
	case check.MANAGEDSERVICES:
		file = k.opts.ManagedservicesFile
	}

	path, err := conf.GetConfigFilePath(k.opts.BenchmarkVersion, k.opts.CfgDir, file)
	if err != nil {
		logging.Get().Warn().Msgf("can't find %s controls file in %s: %v", nodetype, k.opts.CfgDir, err)
		return "", err
	}

	// Merge version-specific config if any.
	if err = conf.MergeConfig(k.v, path); err != nil {
		return "", err
	}

	return filepath.Join(path, file), nil
}

func (k *Kube) writeSuccess(controlsCollection []*check.Controls) error {
	sort.Slice(controlsCollection, func(i, j int) bool {
		iid, _ := strconv.Atoi(controlsCollection[i].ID)
		jid, _ := strconv.Atoi(controlsCollection[j].ID)
		return iid < jid
	})

	err := k.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  "kube",
		TaskID:     k.opts.TaskID,
		Hostname:   k.opts.NodeName,
		ClusterKey: k.opts.ClusterID,
		Payload: map[string]interface{}{
			"autoVariate": k.autoVariate,
			"controls":    k.controlsCollection,
			"totals":      getSummaryTotals(controlsCollection),
		},
	})
	if err != nil {
		logging.Get().Error().Msgf("kube output scan result failed,  %v", err)
		return err
	}

	logging.Get().Info().Msgf("kube output scan result success")
	return nil
}

func (k *Kube) writeFailed(msg string) error {
	err := k.Output(outputter.JSONFormat, &outputter.ScanResult{
		Status:     0,
		Message:    "success",
		CheckType:  "kube",
		TaskID:     k.opts.TaskID,
		Hostname:   k.opts.NodeName,
		ClusterKey: k.opts.ClusterID,
		Payload: map[string]interface{}{
			"status":  1,
			"message": msg,
		},
	})
	if err != nil {
		logging.Get().Error().Msgf("kube output scan result failed,  %v", err)
		return err
	}

	logging.Get().Info().Msgf("kube output scan result success")
	return nil
}

func generateDefaultEnvAudit(controls *check.Controls, binSubs []string) {
	for _, group := range controls.Groups {
		for _, checkItem := range group.Checks {
			if checkItem.Tests != nil && !checkItem.DisableEnvTesting {
				for _, test := range checkItem.Tests.TestItems {
					if test.Env != "" && checkItem.AuditEnv == "" {
						binPath := ""

						if len(binSubs) == 1 {
							binPath = binSubs[0]
						} else {
							logging.Get().Warn().Msgf("AuditEnv not explicit for check (%s), where bin path cannot be determined", checkItem.ID)
						}

						if test.Env != "" && checkItem.AuditEnv == "" {
							checkItem.AuditEnv = fmt.Sprintf("cat \"/proc/$(/bin/ps -C %s -o pid= | tr -d ' ')/environ\" | tr '\\0' '\\n'", binPath)
						}
					}
				}
			}
		}
	}
}

func mapToBenchmarkVersion(kubeToBenchmarkMap map[string]string, kv string) (string, error) {
	kvOriginal := kv
	cisVersion, found := kubeToBenchmarkMap[kv]
	logging.Get().Info().Msg(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	for !found && (kv != defaultKubeVersion && !util.IsEmpty(kv)) {
		kv = decrementVersion(kv)
		cisVersion, found = kubeToBenchmarkMap[kv]
		logging.Get().Info().Msg(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	}

	if !found {
		logging.Get().Warn().Msg(fmt.Sprintf("mapToBenchmarkVersion unable to find a match for: %q", kvOriginal))
		logging.Get().Debug().Msg(fmt.Sprintf("mapToBenchmarkVersion kubeToBenchmarkMap: %#v", kubeToBenchmarkMap))
		return "", fmt.Errorf("unable to find a matching Benchmark Version match for kubernetes version: %s", kvOriginal)
	}

	return cisVersion, nil
}

func loadTargetMapping(v *viper.Viper) (map[string][]string, error) {
	benchmarkVersionToTargetsMap := v.GetStringMapStringSlice("target_mapping")
	if len(benchmarkVersionToTargetsMap) == 0 {
		return nil, fmt.Errorf("config file is missing 'target_mapping' section")
	}

	return benchmarkVersionToTargetsMap, nil
}

func getBenchmarkVersion(kubeVersion, benchmarkVersion string, platform Platform, v *viper.Viper) (bv string, err error) {
	if !util.IsEmpty(kubeVersion) && !util.IsEmpty(benchmarkVersion) {
		return "", fmt.Errorf("It is an error to specify both --version and --benchmark flags")
	}

	if util.IsEmpty(benchmarkVersion) && util.IsEmpty(kubeVersion) && !util.IsEmpty(platform.Name) {
		benchmarkVersion = getPlatformBenchmarkVersion(platform)
	}

	if util.IsEmpty(benchmarkVersion) {
		if util.IsEmpty(kubeVersion) {
			kubeVersion = platform.Version
		}

		kubeToBenchmarkMap, err := conf.LoadVersionMapping(v)
		if err != nil {
			return "", err
		}

		benchmarkVersion, err = mapToBenchmarkVersion(kubeToBenchmarkMap, kubeVersion)
		if err != nil {
			return "", err
		}

		// TODO: fixed benchmark version
		logging.Get().Warn().Msgf("替换cis基线版本为 %s=>cis-1.3", benchmarkVersion)
		benchmarkVersion = "cis-1.3"

		logging.Get().Info().Msg(fmt.Sprintf("Mapped Kubernetes version: %s to Benchmark version: %s", kubeVersion, benchmarkVersion))
	}

	logging.Get().Info().Msg(fmt.Sprintf("Kubernetes version: %q to Benchmark version: %q", kubeVersion, benchmarkVersion))
	return benchmarkVersion, nil
}

// isMaster verify if master components are running on the node.
func isMaster(v *viper.Viper) bool {
	return isThisNodeRunning(check.MASTER, v)
}

// isEtcd verify if etcd components are running on the node.
func isEtcd(v *viper.Viper) bool {
	return isThisNodeRunning(check.ETCD, v)
}

func isThisNodeRunning(nodeType check.NodeType, v *viper.Viper) bool {
	logging.Get().Debug().Msgf("Checking if the current node is running %s components", nodeType)
	nodeTypeConf := v.Sub(string(nodeType))
	if nodeTypeConf == nil {
		logging.Get().Info().Msgf("No config for %s components found", nodeType)
		return false
	}

	components, err := getBinariesFunc(nodeTypeConf, nodeType)
	if err != nil {
		logging.Get().Info().Msgf("Failed to find %s binaries: %v", nodeType, err)
		return false
	}
	if len(components) == 0 {
		logging.Get().Info().Msgf("No %s binaries specified", nodeType)
		return false
	}

	logging.Get().Info().Msgf("Node is running %s components", nodeType)
	return true
}

// validTargets helps determine if the targets
// are legitimate for the benchmarkVersion.
func validTargets(benchmarkVersion string, targets []string, v *viper.Viper) (bool, error) {
	benchmarkVersionToTargetsMap, err := loadTargetMapping(v)
	if err != nil {
		return false, err
	}
	providedTargets, found := benchmarkVersionToTargetsMap[benchmarkVersion]
	if !found {
		return false, fmt.Errorf("No targets configured for %s", benchmarkVersion)
	}

	for _, pt := range targets {
		f := false
		for _, t := range providedTargets {
			if pt == strings.ToLower(t) {
				f = true
				break
			}
		}

		if !f {
			return false, nil
		}
	}

	return true, nil
}
