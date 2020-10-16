package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	harborURL                   = "harbor-url"
	harborUsername              = "harbor-username"
	harborPassword              = "harbor-password"
	harborSkipRegistryTLSVerify = "harbor-skipregistrytlsverify"
)

// HarborOpts ...
type HarborOpts struct {
	URL                   string
	Username              string
	Password              string
	SkipRegistryTLSVerify bool
}

// NewDefaultHarborOpts ...
func NewDefaultHarborOpts() *HarborOpts {
	return &HarborOpts{
		URL: "https://localhost:30003",
		// Default Harbor username/password
		Username:              "admin",
		Password:              "Harbor12345",
		SkipRegistryTLSVerify: false,
	}
}

// GetHarborOpts ...
func GetHarborOpts(cmd *cobra.Command) *HarborOpts {
	return &HarborOpts{
		URL:                   viper.GetString(harborURL),
		Username:              viper.GetString(harborUsername),
		Password:              viper.GetString(harborPassword),
		SkipRegistryTLSVerify: viper.GetBool(harborSkipRegistryTLSVerify),
	}
}

// AddHarborFlags ...
func AddHarborFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultHarborOpts()
	cmd.Flags().String(harborURL, defaultOps.URL, "harbor url")
	cmd.Flags().String(harborUsername, defaultOps.Username, "harbor username")
	cmd.Flags().String(harborPassword, defaultOps.Password, "harbor password !!!NOTE: prefer passing this as env injected via k8s secret!!!")
	cmd.Flags().Bool(harborSkipRegistryTLSVerify, defaultOps.SkipRegistryTLSVerify, "skip TLS cert verification step for harbor API")

	for _, flag := range []string{
		harborURL,
		harborUsername,
		harborPassword,
		harborSkipRegistryTLSVerify,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
