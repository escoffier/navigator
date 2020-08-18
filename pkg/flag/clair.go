package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	clairEndpointAddress = "clair-address"
	clairEndpointPort    = "clair-port"
	clairRemoteAddress   = "clair-remote-address"
	clairRemotePort      = "clair-remote-port"
	clairIgnoreFileName  = "clair-ignorefile"
	clairIgnorePackage   = "clair-ignorepackage"
	clairCVEWhitelist    = "clair-cvewhite"
	clairSecretPattern   = "clair-secretpattern"
)

// ClairOpts the clair options
type ClairOpts struct {
	EndpointAddress    string
	EndpointClairPort  int
	RemoteClairAddress string
	RemoteClairPort    int
	IgnoreFileList     string
	IgnorePackageList  string
	CVEWhitelist       string
	SecretPattern      string
}

// NewDefaultClairOpts the new default clair options.
func NewDefaultClairOpts() *ClairOpts {
	return &ClairOpts{
		EndpointAddress:    "localhost",
		EndpointClairPort:  9278,
		RemoteClairAddress: "localhost",
		RemoteClairPort:    6060,
		IgnoreFileList:     string("configs/scanner/ignore_files.json"),
		IgnorePackageList:  string("configs/scanner/ignore_packages.json"),
		CVEWhitelist:       string("configs/scanner/white_cve.json"),
		SecretPattern:      string("configs/scanner/patterns.json"),
	}
}

// GetClairOpts parses the cobra.Command and returns the EtcdOpts.
func GetClairOpts(cmd *cobra.Command) *ClairOpts {
	return &ClairOpts{
		EndpointAddress:    viper.GetString(clairEndpointAddress),
		EndpointClairPort:  viper.GetInt(clairEndpointPort),
		RemoteClairAddress: viper.GetString(clairRemoteAddress),
		RemoteClairPort:    viper.GetInt(clairRemotePort),
		IgnoreFileList:     viper.GetString(clairIgnoreFileName),
		IgnorePackageList:  viper.GetString(clairIgnorePackage),
		CVEWhitelist:       viper.GetString(clairCVEWhitelist),
		SecretPattern:      viper.GetString(clairSecretPattern),
	}
}

// AddClairFlags adds the clair configuration command line options.
func AddClairFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultClairOpts()
	cmd.Flags().String(clairEndpointAddress, defaultOps.EndpointAddress, "clair scanner address")
	cmd.Flags().Int(clairEndpointPort, defaultOps.EndpointClairPort, "clair scanner port")
	cmd.Flags().String(clairRemoteAddress, defaultOps.RemoteClairAddress, "clair remote address")
	cmd.Flags().Int(clairRemotePort, defaultOps.RemoteClairPort, "clair remote port")
	cmd.Flags().String(clairIgnoreFileName, defaultOps.IgnoreFileList,
		"clair ignore file list file")
	cmd.Flags().String(clairIgnorePackage, defaultOps.IgnorePackageList,
		"clair ignore package list file")
	cmd.Flags().String(clairCVEWhitelist, defaultOps.CVEWhitelist, "clair cve white list file")
	cmd.Flags().String(clairSecretPattern, defaultOps.SecretPattern, "clair secret pattern file")

	for _, flag := range []string{
		clairEndpointAddress,
		clairEndpointPort,
		clairRemoteAddress,
		clairRemotePort,
		clairIgnoreFileName,
		clairIgnorePackage,
		clairSecretPattern,
		clairCVEWhitelist,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
