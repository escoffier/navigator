package kube

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

var (
	defaultKubeVersion = "1.18"
)

type kubeOptions struct {
	TaskID              string
	NodeName            string
	ClusterID           string
	KubeVersion         string
	BenchmarkVersion    string
	CfgFile             string
	CfgDir              string
	MasterFile          string
	NodeFile            string
	EtcdFile            string
	ControlplaneFile    string
	PoliciesFile        string
	ManagedservicesFile string
	FilterOpts          check.FilterOpts
	SkipIds             string

	mqWriter mq.Writer
}

type KubeOption func(*kubeOptions)

func CheckList(checkList []string) KubeOption {
	return func(o *kubeOptions) {
		logging.Get().Debug().Strs("checkList", checkList).Msg("CheckList options set")
		o.FilterOpts.CheckList = checkList
	}
}

func NewKubeOptions(taskID, clusterID, nodeName string, mqWriter mq.Writer, opts ...KubeOption) *kubeOptions {
	o := &kubeOptions{
		TaskID:              taskID,
		NodeName:            nodeName,
		ClusterID:           clusterID,
		KubeVersion:         "",
		BenchmarkVersion:    "",
		CfgFile:             "",
		CfgDir:              "/cis/kube",
		MasterFile:          "master.yaml",
		NodeFile:            "node.yaml",
		EtcdFile:            "etcd.yaml",
		ControlplaneFile:    "controlplane.yaml",
		PoliciesFile:        "policies.yaml",
		ManagedservicesFile: "managedservices.yaml",
		FilterOpts: check.FilterOpts{
			Scored:   true,
			Unscored: true,
		},
		SkipIds:  "",
		mqWriter: mqWriter,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

type Kube struct {
	opts                *kubeOptions
	chroot              string
	autoVariate         map[string]string
	detectedKubeVersion string
	controlsCollection  []*check.Controls
	outputter.Outputter
	v *viper.Viper
}

func NewKube(opts *kubeOptions) *Kube {
	return &Kube{
		opts:                opts,
		autoVariate:         map[string]string{},
		detectedKubeVersion: "",
		controlsCollection:  nil,
		Outputter:           outputter.NewKafka(opts.mqWriter),
		v:                   viper.New(),
	}
}

// InitConfig reads in config file.
func (k *Kube) InitConfig() error {
	if k.opts.CfgFile != "" { // enable ability to specify config file via flag
		k.v.SetConfigFile(k.opts.CfgFile)
	} else {
		k.v.SetConfigName("config")      // name of config file (without extension)
		k.v.AddConfigPath(k.opts.CfgDir) // adding ./cfg as first search path
	}

	// If a config file is found, read it in.
	if err := k.v.ReadInConfig(); err != nil {
		return fmt.Errorf("Failed to read config file: %v\n", err)
	}

	k.chroot = k.v.GetString("chroot")
	if k.chroot != "" {
		nc = func() *exec.Cmd {
			ctx, _ := context.WithTimeout(context.Background(), time.Minute*3)
			cmd := exec.CommandContext(ctx, "sh")
			cmd.WaitDelay = time.Second
			cmd.Dir = "/"
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: k.chroot}
			return cmd
		}
	}

	logging.Get().Debug().Str("chroot", k.chroot).Msg("")

	return nil
}

func (k *Kube) MappingBenchmarkVersion() error {
	platform := getPlatformInfo()
	bv, err := getBenchmarkVersion(k.opts.KubeVersion, k.opts.BenchmarkVersion, platform, k.v)
	if err != nil {
		logging.Get().Error().Msgf("unable to determine benchmark version: %v", err)
		return err
	}

	logging.Get().Info().Msgf("Running checks for benchmark %v", bv)

	k.opts.BenchmarkVersion = bv
	k.detectedKubeVersion = platform.String()
	return nil
}

func (k *Kube) Run() error {
	if isMaster(k.v) {
		logging.Get().Info().Msg("== Running master checks ==")
		testYamlFile, err := k.loadConfig(check.MASTER)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
		if err = k.runChecks(check.MASTER, testYamlFile); err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}

		// Control Plane is only valid for CIS 1.5 and later,
		// this a gatekeeper for previous versions
		valid, err := validTargets(k.opts.BenchmarkVersion, []string{string(check.CONTROLPLANE)}, k.v)
		if err != nil {
			logging.Get().Error().Msgf("error validating targets: %v", err)
			return err
		}
		if valid {
			logging.Get().Info().Msg("== Running control plane checks ==")

			testYamlFile, err = k.loadConfig(check.CONTROLPLANE)
			if err != nil {
				logging.Get().Error().Err(err).Msg("")
				return k.writeFailed(err.Error())
			}
			if err = k.runChecks(check.CONTROLPLANE, testYamlFile); err != nil {
				logging.Get().Error().Err(err).Msg("")
				return k.writeFailed(err.Error())
			}
		}
	} else {
		logging.Get().Info().Msg("== Skipping master checks ==")
	}

	// Etcd is only valid for CIS 1.5 and later,
	// this a gatekeeper for previous versions.
	valid, err := validTargets(k.opts.BenchmarkVersion, []string{string(check.ETCD)}, k.v)
	if err != nil {
		logging.Get().Error().Msgf("error validating targets: %v", err)
		return err
	}
	if valid && isEtcd(k.v) {
		logging.Get().Info().Msg("== Running etcd checks ==")

		testYamlFile, err := k.loadConfig(check.ETCD)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
		if err = k.runChecks(check.ETCD, testYamlFile); err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
	} else {
		logging.Get().Info().Msg("== Skipping etcd checks ==")
	}

	logging.Get().Info().Msg("== Running node checks ==")
	testYamlFile, err := k.loadConfig(check.NODE)
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return k.writeFailed(err.Error())
	}
	if err = k.runChecks(check.NODE, testYamlFile); err != nil {
		logging.Get().Error().Err(err).Msg("")
		return k.writeFailed(err.Error())
	}

	// Policies are only valid for CIS 1.5 and later,
	// this a gatekeeper for previous versions.
	valid, err = validTargets(k.opts.BenchmarkVersion, []string{string(check.POLICIES)}, k.v)
	if err != nil {
		logging.Get().Error().Msgf("error validating targets: %v", err)
		return err
	}
	if valid {
		logging.Get().Info().Msg("== Running policies checks ==")

		testYamlFile, err = k.loadConfig(check.POLICIES)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
		if err = k.runChecks(check.POLICIES, testYamlFile); err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
	} else {
		logging.Get().Info().Msg("== Skipping policies checks ==")
	}

	// Managedservices is only valid for GKE 1.0 and later,
	// this a gatekeeper for previous versions.
	valid, err = validTargets(k.opts.BenchmarkVersion, []string{string(check.MANAGEDSERVICES)}, k.v)
	if err != nil {
		logging.Get().Error().Msgf("error validating targets: %v", err)
		return nil
	}
	if valid {
		logging.Get().Info().Msg("== Running managed services checks ==")
		testYamlFile, err = k.loadConfig(check.MANAGEDSERVICES)
		if err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
		if err = k.runChecks(check.MANAGEDSERVICES, testYamlFile); err != nil {
			logging.Get().Error().Err(err).Msg("")
			return k.writeFailed(err.Error())
		}
	} else {
		logging.Get().Info().Msg("== Skipping managed services checks ==")
	}

	logging.Get().Info().Msgf("kube runChecks completion")
	return k.writeSuccess(k.controlsCollection)
}
