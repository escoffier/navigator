package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	elasticHost     = "elastic-host"
	elasticPort     = "elastic-port"
	elasticIndex    = "elastic-index"
	elasticUsername = "elastic-username"
	elasticPassword = "elastic-password"
	elasticPVC      = "elastic-pvc"
	elasticPod      = "elastic-pod"
	elasticDataPath = "elastic-data-path"
)

// ElasticOpts the Elastic options.
type ElasticOpts struct {
	Host     string
	Port     string
	Index    string
	Username string
	Password string
	PVC      string
	Pod      string
	DataPath string
}

// NewDefaultElasticOpts returns a new default elastic options.
func NewDefaultElasticOpts() *ElasticOpts {
	return &ElasticOpts{
		Host:     "localhost",
		Port:     "9200",
		Index:    "index",
		Username: "elastic",
		Password: "12345",
		PVC:      "tensorsec-elastic-pvc",
		Pod:      "tensorsec-elastic-pod",
		DataPath: "/data",
	}
}

// GetElasticOpts parses the cobra.Command and returns the ElasticOpts.
func GetElasticOpts(cmd *cobra.Command) *ElasticOpts {
	return &ElasticOpts{
		Host:     viper.GetString(elasticHost),
		Port:     viper.GetString(elasticPort),
		Index:    viper.GetString(elasticIndex),
		Username: viper.GetString(elasticUsername),
		Password: viper.GetString(elasticPassword),
		PVC:      viper.GetString(elasticPVC),
		Pod:      viper.GetString(elasticPod),
		DataPath: viper.GetString(elasticDataPath),
	}
}

// AddElasticFlags adds the Elastic-specific command line arguments to the cobra.Command.
func AddElasticFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultElasticOpts()
	cmd.PersistentFlags().String(elasticHost, defaultOpts.Host, "Elastic host")
	cmd.PersistentFlags().String(elasticPort, defaultOpts.Port, "Elastic port")
	cmd.PersistentFlags().String(elasticIndex, defaultOpts.Index, "Elastic index")
	cmd.PersistentFlags().String(elasticUsername, defaultOpts.Username, "Elastic username")
	cmd.PersistentFlags().String(elasticPassword, defaultOpts.Password, "Elastic password")
	cmd.PersistentFlags().String(elasticPVC, defaultOpts.PVC, "Elastic kubernetes PVC")
	cmd.PersistentFlags().String(elasticPod, defaultOpts.Pod, "Elastic kubernetes Pod")
	cmd.PersistentFlags().String(elasticDataPath, defaultOpts.DataPath, "Elastic data path")

	for _, flag := range []string{elasticHost, elasticPort, elasticIndex, elasticUsername, elasticPassword, elasticPVC, elasticPod, elasticDataPath} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
