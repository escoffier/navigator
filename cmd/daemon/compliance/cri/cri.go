package cri

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

type criOptions struct {
	taskID           string
	nodeName         string
	clusterID        string
	runtimeName      string
	runtimeVersion   string
	benchmarkVersion string
	cfgDir           string
	cfgFile          string
	skipIds          string
	filterOpts       check.FilterOpts

	mqWriter mq.Writer
}

type CriOption func(*criOptions)

func CheckList(checkList []string) CriOption {
	return func(o *criOptions) {
		o.filterOpts.CheckList = checkList
	}
}

func NewCriOptions(taskID, clusterID, nodeName string, mqWriter mq.Writer, runtimeName, runtimeVersion string, opts ...CriOption) *criOptions {
	o := &criOptions{
		taskID:           taskID,
		nodeName:         nodeName,
		clusterID:        clusterID,
		runtimeName:      runtimeName,
		runtimeVersion:   runtimeVersion,
		benchmarkVersion: "",
		cfgDir:           "/cis/cri/",
		cfgFile:          "",
		skipIds:          "",
		filterOpts: check.FilterOpts{
			Scored:   true,
			Unscored: true,
		},
		mqWriter: mqWriter,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

type Cri struct {
	opts               *criOptions
	chroot             string
	detectedCriVersion string
	outputter.Outputter
	v *viper.Viper
}

func NewCri(opts *criOptions) *Cri {
	return &Cri{
		opts:      opts,
		Outputter: outputter.NewKafka(opts.mqWriter),
		v:         viper.New(),
	}
}

// InitConfig reads in config file.
func (c *Cri) InitConfig() error {
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

	c.chroot = c.v.GetString("chroot")
	if c.chroot != "" {
		nc = func() *exec.Cmd {
			ctx, _ := context.WithTimeout(context.Background(), time.Minute*3)
			cmd := exec.CommandContext(ctx, "sh")
			cmd.WaitDelay = time.Second
			cmd.Dir = "/"
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: c.chroot}
			return cmd
		}
	}

	return nil
}

func (c *Cri) MappingBenchmarkVersion() error {
	platform := Platform{}
	if c.opts.runtimeName != "" && c.opts.runtimeVersion != "" {
		platform.Name = c.opts.runtimeName
		platform.Version = c.opts.runtimeVersion
	} else {
		platform = getPlatformInfo()
	}
	bv, err := getBenchmarkVersion(c.opts.benchmarkVersion, platform, c.v)
	if err != nil {
		return fmt.Errorf("unable to determine benchmark version: %v", err)
	}

	logging.Get().Info().Msgf("Running checks for benchmark %v", bv)
	c.opts.benchmarkVersion = bv
	c.detectedCriVersion = platform.String()
	return nil
}

func (c *Cri) Run() error {
	constraints, err := getConstraints()
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return c.writeFailed(err.Error())
	}

	testYamlFile, err := c.loadConfig("definitions.yaml")
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return c.writeFailed(err.Error())
	}

	controls, err := c.getControls(testYamlFile, constraints)
	if err != nil {
		logging.Get().Error().Msgf("error setting up controls: %v", err)
		return c.writeFailed(err.Error())
	}

	if err = c.runChecks(controls); err != nil {
		logging.Get().Error().Err(err).Msg("")
		return c.writeFailed(err.Error())
	}

	logging.Get().Info().Msgf("cri runChecks completion")
	return c.writeOutput(controls.(*check.Controls))
}
