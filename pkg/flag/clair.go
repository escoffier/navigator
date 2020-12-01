package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	clairEndpointAddress          = "clair-address"
	clairEndpointPort             = "clair-port"
	clairRemoteAddress            = "clair-remote-address"
	clairRemotePort               = "clair-remote-port"
	clairSecretPattern            = "clair-secretpattern"
	redclairSkipRegistryTLSVerify = "redclair-skipregistrytlsverify"
	redclairNumWorkers            = "redclair-numworkers"
	postgresConnectionString      = "clair-postgresconnectionstring"
)

// ClairOpts the clair options
type ClairOpts struct {
	EndpointAddress          string
	EndpointClairPort        int
	RemoteClairAddress       string
	RemoteClairPort          int
	SecretPattern            string
	SkipRegistryTLSVerify    bool
	NumWorkers               int
	PostgresConnectionString string
}

// NewDefaultClairOpts the new default clair options.
func NewDefaultClairOpts() *ClairOpts {
	return &ClairOpts{
		// Scanner creates a local HTTP server that serves container layers.
		// When scan request comes in, Scanner splits image into layers and then sends
		// many requests to remote Clair process with URI paths on this local server.
		// Clair will pull layers for analysis from this server and respond.
		// Why not just send those layers to remote Clair process? I think this is because
		// initially the layer was being shared via mounted /tmp dir, but this is not
		// a good idea in microservice environment I guess. Unless we want to have
		// Scanner and Clair services in the same pod, which maybe isn't such a bad idea.??
		// Anyways, this should be address that is accessible from outside (e.g. K8s service address)
		EndpointAddress:   "localhost",
		EndpointClairPort: 9278,
		// Address of Clair service.
		RemoteClairAddress:       "localhost",
		RemoteClairPort:          6060,
		SecretPattern:            string("configs/scanner/patterns.json"),
		SkipRegistryTLSVerify:    false,
		NumWorkers:               4,
		PostgresConnectionString: "postgres://postgres:postgres@localhost:5432/postgres",
	}
}

// GetClairOpts parses the cobra.Command and returns the EtcdOpts.
func GetClairOpts(cmd *cobra.Command) *ClairOpts {
	return &ClairOpts{
		EndpointAddress:          viper.GetString(clairEndpointAddress),
		EndpointClairPort:        viper.GetInt(clairEndpointPort),
		RemoteClairAddress:       viper.GetString(clairRemoteAddress),
		RemoteClairPort:          viper.GetInt(clairRemotePort),
		SecretPattern:            viper.GetString(clairSecretPattern),
		SkipRegistryTLSVerify:    viper.GetBool(redclairSkipRegistryTLSVerify),
		NumWorkers:               viper.GetInt(redclairNumWorkers),
		PostgresConnectionString: viper.GetString(postgresConnectionString),
	}
}

// AddClairFlags adds the clair configuration command line options.
func AddClairFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultClairOpts()
	cmd.Flags().String(clairEndpointAddress, defaultOps.EndpointAddress, "clair scanner address")
	cmd.Flags().Int(clairEndpointPort, defaultOps.EndpointClairPort, "clair scanner port")
	cmd.Flags().String(clairRemoteAddress, defaultOps.RemoteClairAddress, "clair remote address")
	cmd.Flags().Int(clairRemotePort, defaultOps.RemoteClairPort, "clair remote port")
	cmd.Flags().String(clairSecretPattern, defaultOps.SecretPattern, "clair secret pattern file")
	cmd.Flags().Bool(redclairSkipRegistryTLSVerify, defaultOps.SkipRegistryTLSVerify, "skip TLS cert verification step for remote docker registries")
	cmd.Flags().Int(redclairNumWorkers, defaultOps.NumWorkers, "num scanner workers")
	cmd.Flags().String(postgresConnectionString, defaultOps.PostgresConnectionString, "clair DB connection string")

	for _, flag := range []string{
		clairEndpointAddress,
		clairEndpointPort,
		clairRemoteAddress,
		clairRemotePort,
		clairSecretPattern,
		redclairSkipRegistryTLSVerify,
		redclairNumWorkers,
		postgresConnectionString,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
