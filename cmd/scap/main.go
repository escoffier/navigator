package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"gitlab.com/piccolo_su/vegeta/cmd/scap/service"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	_ "gitlab.com/piccolo_su/vegeta/pkg/scap/dockerbench"
	_ "gitlab.com/piccolo_su/vegeta/pkg/scap/host"
	_ "gitlab.com/piccolo_su/vegeta/pkg/scap/kubebench"
)

var (
	envVarsPrefix    = "VBENCH"
	cfgDir           = "configs/scap/kubebench"
	cfgFile          = "config"
	kubebencTask     = "all"
	hostFile         = "node.yaml"
	dockerbenchFile  = "etcd.yaml"
	objVersion       string
	benchmarkVersion string
	jsonFmt          bool
	outputFile       string
	log              *logging.Logger
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   os.Args[0],
	Short: "Run CIS Benchmarks checks against a Kubernetes deployment",
	Long:  `This tool runs the CIS Kubernetes Benchmark`,
	Run: func(cmd *cobra.Command, args []string) {
		mongoOpts := flag.GetMongoOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", mongoOpts.Endpoint).
			Str("username", mongoOpts.Username).
			Msg("Mongo options")
		log.Info().Msg("Choose kubebench/dockerbench/hostbench and continue")
	},
}

var kubebenchCmd = &cobra.Command{
	Use:   "kubebench",
	Short: "Run Kubernetes benchmark ",
	Long:  `Run Kubernetes benchmark.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msgf("\nKube bench: \n Config: %s: %s\n ==== Running %s Check",
			cfgDir, cfgFile, kubebencTask)

		conf := model.CheckerConfig{
			Version: objVersion,
			Options: map[string]interface{}{
				"benchmark": benchmarkVersion,
			},
			ConfigDirectory: cfgDir,
		}

		taskName := fmt.Sprintf("kubebench_%s", kubebencTask)
		service.Run(taskName, conf, cmd)
	},
}

var dockerbenchCmd = &cobra.Command{
	Use:   "dockerbench",
	Short: "Run Docker benchmark ",
	Long:  `Run Docker benchmark.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msgf("\n Docker bench: \n Config: %s: %s\n ==== Running %s Check",
			cfgDir, cfgFile, "docker")

		conf := model.CheckerConfig{
			Version: objVersion,
			Options: make(map[string]interface{}),
		}

		service.Run("docker", conf, cmd)
	},
}

var hostCmd = &cobra.Command{
	Use:   "hostbench",
	Short: "Run Host benchmark ",
	Long:  `Run Host benchmark.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msgf("\n Host bench: \n Config: %s: %s\n ==== Running %s Check",
			cfgDir, cfgFile, "host")

		conf := model.CheckerConfig{
			Version: objVersion,
			Options: map[string]interface{}{},
		}

		service.Run("host", conf, cmd)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Output control
	RootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false,
		"Prints the results as JSON")
	RootCmd.PersistentFlags().StringVar(&outputFile, "output-file", "",
		"Writes the JSON results to output file")
	RootCmd.PersistentFlags().StringVarP(&cfgDir, "config-dir",
		"D", cfgDir, "config directory")
	RootCmd.PersistentFlags().StringVarP(&cfgFile,
		"config",
		"c",
		"",
		"YAML file for config checks",
	)
	RootCmd.PersistentFlags().StringVar(&objVersion, "target-version", "",
		"Manually specify Entities version, automatically detected if unset")

	kubebenchCmd.PersistentFlags().StringVar(&benchmarkVersion, "benchmark-version", "",
		"Manually specify CIS benchmark version. It would be an error to "+
			"specify both --version and --benchmark flags")

	kubebenchCmd.PersistentFlags().StringVarP(
		&kubebencTask,
		"task",
		"t",
		"all",
		"running master/node/all task",
	)

	kubebenchCmd.PersistentFlags().StringVarP(&dockerbenchFile,
		"file",
		"f",
		"configs/scap/master.yaml",
		"YAML file for Dockerbench checks",
	)

	dockerbenchCmd.PersistentFlags().StringVarP(&dockerbenchFile,
		"file",
		"f",
		"configs/scap/dockconfig.yaml",
		"YAML file for Dockerbench checks",
	)

	hostCmd.PersistentFlags().StringVarP(&hostFile,
		"file",
		"f",
		"configs/scap/hostconfig.yaml",
		"YAML file for Host checks",
	)

	RootCmd.AddCommand(kubebenchCmd)
	RootCmd.AddCommand(dockerbenchCmd)
	RootCmd.AddCommand(hostCmd)

	flag.AddMongoFlags(RootCmd)
	//flag.AddMongoFlags(kubebenchCmd)
	//flag.AddMongoFlags(dockerbenchCmd)
	//flag.AddMongoFlags(hostCmd)

	// initialize the logger
	log = logging.GetLogger()
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Error().Msgf("%v", err)
		os.Exit(-1)
	}
}

// initKubeConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config") // name of config file (without extension)
		viper.AddConfigPath(cfgDir)   // adding ./cfg as first search path
	}

	viper.AddConfigPath(cfgDir) // adding ./cfg as first search path
	// Read flag values from environment variables.
	// Precedence: Command line flags take precedence over environment variables.
	viper.SetEnvPrefix(envVarsPrefix)
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error for now to prevent commands
			// which don't need the config file exiting.
			log.Info().Msgf("%v", err)
		} else {
			log.Info().Msgf("failed to read config %v", err)
			// Config file was found but another error was produced
			os.Exit(1)
		}
	}
}

func main() {
	Execute()
}
