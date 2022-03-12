package flag

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ScannerRunOpts ScannerOpts

const (
	httpListenAddr       = "http-listen-addr"
	redisEndpoint        = "redis-endpoint"
	parallelTaskNum      = "parallel-task-num"
	parallelSubtaskNum   = "parallel-subtask-num"
	logLevel             = "log-level"
	webShellServerAddr   = "web-shell-server-addr"
	imageCacheServerIP   = "image-cache-server-ip"
	imageCacheServerPort = "image-cache-server-port"
	pvcPath              = "pvc-path"
)

// ScannerOpts the scanner options
type ScannerOpts struct {
	HTTPListenAddr       string
	RedisEndpoint        string
	RedisPassword        string
	ParallelTaskNum      int
	ParallelSubTaskNum   int
	LogLevel             string
	WebShellServerAddr   string
	ImageCacheServerIP   string
	ImageCacheServerPort int
	PvcPath              string
}

// NewDefaultScannerOpts the new default clair options.
func NewDefaultScannerOpts() *ScannerOpts {
	return &ScannerOpts{
		HTTPListenAddr:       ":8080",
		RedisEndpoint:        "tensorsec-redis-ha-announce-0:26379,tensorsec-redis-ha-announce-1:26379,tensorsec-redis-ha-announce-2:26379",
		RedisPassword:        "12345",
		ParallelTaskNum:      2,
		ParallelSubTaskNum:   2,
		LogLevel:             "info",
		WebShellServerAddr:   fmt.Sprintf("%s/v1/php/detector", "0.0.0.0:7777"),
		ImageCacheServerIP:   "0.0.0.0",
		ImageCacheServerPort: 9278,
		PvcPath:              "/root/testdb",
	}
}

// GetScannerOpts parses the cobra.Command and returns the scanner opts.
func GetScannerOpts(cmd *cobra.Command) *ScannerOpts {
	return &ScannerOpts{
		HTTPListenAddr:       viper.GetString(httpListenAddr),
		RedisEndpoint:        os.Getenv("REDIS_CLUSTER_URL"),
		RedisPassword:        os.Getenv("REDIS_PASSWORD"),
		ParallelTaskNum:      viper.GetInt(parallelTaskNum),
		ParallelSubTaskNum:   viper.GetInt(parallelSubtaskNum),
		LogLevel:             viper.GetString(logLevel),
		WebShellServerAddr:   os.Getenv("WEBSHELL_SERVER_URL"),
		ImageCacheServerIP:   viper.GetString(imageCacheServerIP),
		ImageCacheServerPort: viper.GetInt(imageCacheServerPort),
		PvcPath:              viper.GetString(pvcPath),
	}
}

// AddScannerFlags adds the scanner configuration command line options.
func AddScannerFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultScannerOpts()
	cmd.Flags().String(httpListenAddr, defaultOps.HTTPListenAddr, "http listen address")
	cmd.Flags().String(redisEndpoint, defaultOps.RedisEndpoint, "redis remote address")
	cmd.Flags().Int(parallelTaskNum, defaultOps.ParallelTaskNum, "parallel task num")
	cmd.Flags().Int(parallelSubtaskNum, defaultOps.ParallelSubTaskNum, "parallel subtask num")
	cmd.Flags().String(logLevel, defaultOps.LogLevel, "log level")
	cmd.Flags().String(webShellServerAddr, defaultOps.WebShellServerAddr, "web shell server addr")
	cmd.Flags().String(imageCacheServerIP, defaultOps.ImageCacheServerIP, "image cache server ip")
	cmd.Flags().Int(imageCacheServerPort, defaultOps.ImageCacheServerPort, "image cache server port")
	cmd.Flags().String(pvcPath, defaultOps.PvcPath, "pvc path")

	for _, flag := range []string{
		httpListenAddr,
		redisEndpoint,
		parallelTaskNum,
		parallelSubtaskNum,
		logLevel,
		webShellServerAddr,
		imageCacheServerIP,
		imageCacheServerPort,
		pvcPath,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
