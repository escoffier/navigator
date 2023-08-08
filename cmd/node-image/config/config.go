package config

import (
	json "github.com/json-iterator/go"
	"os"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

const (
	defaultTaskParallelNum          = 5
	defaultScanTimeout              = 1800 // second
	defaultMountPrefix              = "/host"
	defaultReportInterval           = 600
	defaultMqTimeout                = 5
	defaultImageSendBatchSize       = 50
	defaultExcludeImageScope        = "tensorsec.*"
	defaultAviraSavServerListenPort = 9200
	defaultAviraSavClientNum        = 10
	defaultNodeImageConfigFile      = "node-image-config.json"
	defaultSwitchDeepScan           = false // disabled deep scan by default
	DeepScanTypesAvira              = "avira"
	DeepScanTypesWebshell           = "tws"
	DeepScanTypesClamAV             = "clamav"
	defaultSlowMode                 = true
)

var (
	globalConfig    *Config                        // config loaded from yaml
	nodeImageConfig *imagesecModel.NodeImageConfig // config sync from console
)

// Config define content int node-image.yaml
// e.g. node-image.yaml:
//
//	  log_level: debug
//	  task:
//		   parallel_num: 5
//	  scan:
//		   scan_timeout: 1800
type Config struct {
	LogLevel       string         `mapstructure:"log_level"`
	TaskConfig     TaskConfig     `mapstructure:"task"`
	ScanConfig     ScanConfig     `mapstructure:"scan"`
	IreneConfig    IreneConfig    `mapstructure:"irene"`
	DeepScanConfig DeepScanConfig `mapstructure:"deep_scan"`
	ReportConfig   ReportConfig   `mapstructure:"report"`
	AviraConfig    AviraConfig    `mapstructure:"avira"`
	WebshellConfig WebshellConfig `mapstructure:"webshell"`
}

type TaskConfig struct {
	ParallelNum int64 `mapstructure:"parallel_num"`
}

type ScanConfig struct {
	ScanTimeout int64  `mapstructure:"scan_timeout"`
	MountPrefix string `mapstructure:"mount_prefix"`
	RealTimeLog bool   `mapstructure:"real_time_log"`
}

type IreneConfig struct {
	LogLevel    string `mapstructure:"log_level"`
	DeeperDebug bool   `mapstructure:"deeper_debug"`
	Slow        bool   `mapstructure:"slow"`
}

type DeepScanConfig struct {
	Types []string `mapstructure:"types"`
}

type ReportConfig struct {
	Interval     int64    `mapstructure:"interval"`
	MqTimeout    int64    `mapstructure:"mq_timeout"`
	ExcludeImage []string `mapstructure:"exclude_image"`
	BatchSize    int64    `mapstructure:"batch_size"`
}

type AviraConfig struct {
	ListenPort int64 `mapstructure:"listen_port"`
	ClientNum  int64 `mapstructure:"client_num"`
}

type WebshellConfig struct {
	IncludeTypes []string `mapstructure:"include_types"`
}

// NewDefaultConfig when vip.unmarshall(config_file),default value would be return for missing field
func NewDefaultConfig() *Config {
	c := &Config{
		LogLevel: "info",
		TaskConfig: TaskConfig{
			ParallelNum: defaultTaskParallelNum,
		},
		ScanConfig: ScanConfig{
			ScanTimeout: defaultScanTimeout,
			MountPrefix: defaultMountPrefix,
			RealTimeLog: false,
		},
		DeepScanConfig: DeepScanConfig{
			Types: []string{"tws", "avira"},
		},
		IreneConfig: IreneConfig{
			LogLevel:    "debug",
			DeeperDebug: false,
			Slow:        defaultSlowMode,
		},
		ReportConfig: ReportConfig{
			Interval:     defaultReportInterval,
			MqTimeout:    defaultMqTimeout,
			ExcludeImage: []string{defaultExcludeImageScope},
			BatchSize:    defaultImageSendBatchSize,
		},
		AviraConfig: AviraConfig{
			ListenPort: defaultAviraSavServerListenPort,
			ClientNum:  defaultAviraSavClientNum,
		},
	}
	return c
}

func SetGlobalConfig(cfg *Config) {
	globalConfig = cfg
}

func GetNodeImageConfig() *imagesecModel.NodeImageConfig {
	return nodeImageConfig
}

func UpdateNodeImageConfig(config *imagesecModel.NodeImageConfig) {
	nodeImageConfig.DeepScan = config.DeepScan
	nodeImageConfig.SyncInterval = config.SyncInterval
	nodeImageConfig.ScanTimeout = config.ScanTimeout
}

func FlushNodeImageConfigToFile() error {
	data, err := json.Marshal(nodeImageConfig)
	if err != nil {
		return err
	}
	if err = os.WriteFile(GetDefaultNodeImageConfigFilePath(), data, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func NewDefaultNodeImageConfig() *imagesecModel.NodeImageConfig {
	c := &imagesecModel.NodeImageConfig{
		DeepScan:     defaultSwitchDeepScan,
		SyncInterval: defaultReportInterval,
		ScanTimeout:  defaultScanTimeout,
	}
	return c
}

func GetDefaultNodeImageConfigFilePath() string {
	return filepath.Join(global.WorkingDir, defaultNodeImageConfigFile)
}

func LoadNodeImageConfigFromFile(cfgFile string) (*imagesecModel.NodeImageConfig, error) {
	nc := &imagesecModel.NodeImageConfig{}
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, nc)
	if err != nil {
		return nil, err
	}
	return nc, nil
}

func init() {
	nodeImageConfig = NewDefaultNodeImageConfig()
}
