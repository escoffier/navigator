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
)

// ElasticOpts the Elastic options.
type ElasticOpts struct {
	Host     string
	Port     string
	Index    string
	Username string
	Password string
}

// NewDefaultElasticOpts returns a new default elastic options.
func NewDefaultElasticOpts() *ElasticOpts {
	return &ElasticOpts{
		Host:     "localhost",
		Port:     "9200",
		Index:    "index",
		Username: "elastic",
		Password: "12345",
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

	for _, flag := range []string{elasticHost, elasticPort, elasticIndex, elasticUsername, elasticPassword} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
