package host

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/spf13/viper"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

type hostOptions struct {
	taskID           string
	nodeName         string
	clusterID        string
	skipIds          string
	filterOpts       check.FilterOpts
	cfgDir           string
	cfgFile          string
	benchmarkVersion string

	mqWriter mq.Writer
}

type HostOption func(*hostOptions)

func CheckList(checkList []string) HostOption {
	return func(o *hostOptions) {
		o.filterOpts.CheckList = checkList
	}
}

func NewHostOptions(taskID, clusterID, nodeName string, mqWriter mq.Writer, opts ...HostOption) *hostOptions {
	o := &hostOptions{
		taskID:    taskID,
		nodeName:  nodeName,
		clusterID: clusterID,
		skipIds:   "",
		filterOpts: check.FilterOpts{
			Scored:   true,
			Unscored: true,
		},
		cfgDir:           "/cis/host",
		benchmarkVersion: "",
		mqWriter:         mqWriter,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

type Host struct {
	opts            *hostOptions
	detectedVersion string
	outputter.Outputter
	v *viper.Viper
}

func NewHost(opts *hostOptions) *Host {
	return &Host{
		opts:      opts,
		Outputter: outputter.NewKafka(opts.mqWriter),
		v:         viper.New(),
	}
}

// InitConfig reads in config file.
func (c *Host) InitConfig() error {
	if c.opts.cfgFile != "" { // enable ability to specify config file via flag
		c.v.SetConfigFile(c.opts.cfgFile)
	} else {
		c.v.SetConfigName("config")      // name of config file (without extension)
		c.v.AddConfigPath(c.opts.cfgDir) // adding ./cfg as first search path
	}

	// If a config file is found, read it in.
	if err := c.v.ReadInConfig(); err != nil {
		return fmt.Errorf("Failed to read config file: %v\n", err)
	}

	chroot := c.v.GetString("chroot")
	if chroot != "" {
		nc = func() *exec.Cmd {
			cmd := exec.Command("sh")
			cmd.Dir = "/"
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: chroot}
			return cmd
		}
	}

	return nil
}

func (h *Host) MappingBenchmarkVersion() error {
	platform := getPlatformInfo()
	logging.Get().Info().Msgf("platform was detected: %v", platform)

	bv, err := getBenchmarkVersion(h.opts.benchmarkVersion, platform, h.v)
	if err != nil {
		return fmt.Errorf("unable to determine benchmark version: %v", err)
	}

	logging.Get().Info().Msgf("Running checks for benchmark %v", bv)
	h.opts.benchmarkVersion = bv
	h.detectedVersion = platform.String()
	return nil
}

func (h *Host) Run() error {
	constraints, err := getConstraints()
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return h.writeFailed(err.Error())
	}

	testYamlFile, err := h.loadConfig("definitions.yaml")
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return h.writeFailed(err.Error())
	}

	controls, err := getControls(testYamlFile, constraints, h.detectedVersion)
	if err != nil {
		logging.Get().Error().Msgf("error setting up controls: %v", err)
		return h.writeFailed(err.Error())
	}

	if err = h.runChecks(controls); err != nil {
		logging.Get().Error().Err(err).Msg("")
		return h.writeFailed(err.Error())
	}

	logging.Get().Info().Msgf("host runChecks completion")
	return h.writeOutput(controls.(*check.Controls))
}
