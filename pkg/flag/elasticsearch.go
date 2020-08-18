// Package flag can help in making the command line arguments more consistent by having the
// arguments in one place for different thirdparty libraries:
// e.g. elasticsearch, mongo, and etcd
package flag

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	esURLs     = "es-urls"
	esAPIKey   = "es-apikey"
	esUsername = "es-username"
	esPassword = "es-password"
)

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

// ElasticSearchOpts the elasticsearch options.
type ElasticSearchOpts struct {
	URLs     []string
	Username string
	Password string
	APIKey   string
}

// NewDefaultElasticSearchOpts returns a new default elasticsearch options.
func NewDefaultElasticSearchOpts() *ElasticSearchOpts {
	return &ElasticSearchOpts{
		URLs:     []string{"http://localhost:9200"},
		Username: "",
		Password: "",
		APIKey:   "",
	}
}

// GetElasticSearchOpts parses the cobra.Command and returns the ElasticSearchOpts.
func GetElasticSearchOpts(cmd *cobra.Command) *ElasticSearchOpts {
	return &ElasticSearchOpts{
		URLs:     viper.GetStringSlice(esURLs),
		Username: viper.GetString(esUsername),
		Password: viper.GetString(esPassword),
		APIKey:   viper.GetString(esAPIKey),
	}
}

// AddElasticSearchFlags adds the elasticsearch-specific command line arguments to the
// cobra.Command.
func AddElasticSearchFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultElasticSearchOpts()
	cmd.Flags().StringSlice(esURLs, defaultOpts.URLs, "ElasticSearch URLs")
	cmd.Flags().String(esUsername, defaultOpts.Username, "ElasticSearch username")
	cmd.Flags().String(esPassword, defaultOpts.Password, "ElasticSearch password")
	cmd.Flags().String(esAPIKey, defaultOpts.APIKey, "ElasticSearch API key")

	for _, flag := range []string{esURLs, esUsername, esPassword, esAPIKey} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
