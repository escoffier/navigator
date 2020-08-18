package kubebench

import (
	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/viper"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/scap"
)

var (
	log *logging.Logger

	defaultKubeVersion = "1.11"
	kubeVersion        string
	benchmarkVersion   string
	cfgDir             = "./cfg/"
	junitFmt           bool
	masterFile         = "master.yaml"
	nodeFile           = "node.yaml"
	etcdFile           = "etcd.yaml"
	controlplaneFile   = "controlplane.yaml"
	policiesFile       = "policies.yaml"
	noResults          bool
	noSummary          bool
	noRemediations     bool
	filterOpts         FilterOpts
	includeTestOutput  bool
	outputFile         string
)

//FilterOpts filter options
type FilterOpts struct {
	CheckList string
	GroupList string
	Scored    bool
	Unscored  bool
}

func init() {
	log = logging.GetLogger()
	scap.RegisterChecker("kubebench_master", &Kubebench{checkType: check.MASTER})
	scap.RegisterChecker("kubebench_node", &Kubebench{checkType: check.NODE})
	scap.RegisterChecker("kubebench_all", &Kubebench{})
}

//Kubebench Kube bench data Structure
type Kubebench struct {
	checkType check.NodeType
}

//InitializeChecker Initialize Checker
func (c *Kubebench) InitializeChecker(t *model.ScapTask) (err error) {
	if t.Config.ConfigFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(t.Config.ConfigFile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(cfgDir)
	}

	if t.Config.Version == "" {
		if env := viper.Get("version"); env != nil {
			kubeVersion = env.(string)
		}
	} else {
		kubeVersion = t.Config.Version
	}

	if kubeVersion == "" {
		kubeVersion = "1.13"
	}

	benchmarkVersion, ok := t.Config.Options["benchmark"].(string)

	if !ok || benchmarkVersion == "" {
		benchmarkVersion, err = getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
		if err != nil {
			return
		}
	}

	cfgDir = t.Config.ConfigDirectory

	log.Info().Msgf("Checker %s Configuration\n kube version: %s, benchmark version: %s\n",
		t.ScannerType, kubeVersion, benchmarkVersion)

	return nil
}

//Check Check item for kube-bench
func (c *Kubebench) Check() (interface{}, error) {
	result := make([]*check.Controls, 0)

	if c.checkType == check.MASTER {
		controls, err := runChecks(check.MASTER, loadConfig(check.MASTER))
		if err != nil {
			return nil, err
		}
		result = append(result, controls)
		return result, nil
	} else if c.checkType == check.NODE {
		controls, err := runChecks(check.NODE, loadConfig(check.NODE))
		if err != nil {
			return nil, err
		}
		result = append(result, controls)
		return result, nil
	}

	benchmarkVersion, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
	if err != nil {
		log.Error().Msgf("unable to determine benchmark version: %v", err)
		return nil, err
	}

	if isMaster() {
		log.Info().Msg("== Running master checks ==\n")
		controls, err := runChecks(check.MASTER, loadConfig(check.MASTER))
		if err != nil {
			log.Error().Msgf("%v", err)
			return nil, err
		}
		result = append(result, controls)
		// Control Plane is only valid for CIS 1.5 and later,
		// this a gatekeeper for previous versions
		if validTargets(benchmarkVersion, []string{string(check.CONTROLPLANE)}) {
			log.Info().Msg("== Running control plane checks ==\n")
			controlPlaneControls, err := runChecks(check.CONTROLPLANE, loadConfig(check.CONTROLPLANE))
			if err != nil {
				log.Error().Msgf("%v", err)
				return nil, err
			}
			result = append(result, controlPlaneControls)
		}
	}

	// Etcd is only valid for CIS 1.5 and later,
	// this a gatekeeper for previous versions.
	if validTargets(benchmarkVersion, []string{string(check.ETCD)}) && isEtcd() {
		log.Info().Msg("== Running etcd checks ==\n")
		controls, err := runChecks(check.ETCD, loadConfig(check.ETCD))
		if err != nil {
			log.Error().Msgf("%v", err)
			return nil, err
		}
		result = append(result, controls)
	}

	log.Info().Msg("== Running node checks ==\n")
	controls, err := runChecks(check.NODE, loadConfig(check.NODE))
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}
	result = append(result, controls)

	// Policies is only valid for CIS 1.5 and later,
	// this a gatekeeper for previous versions.
	if validTargets(benchmarkVersion, []string{string(check.POLICIES)}) {
		log.Info().Msg("== Running policies checks ==\n")
		policiesControls, err := runChecks(check.POLICIES, loadConfig(check.POLICIES))
		if err != nil {
			log.Error().Msgf("%v", err)
			return nil, err
		}
		result = append(result, policiesControls)
	}

	return result, nil
}
