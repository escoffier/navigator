package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	harborURL           = "harbor-url"
	harborUsername      = "harbor-username"
	harborPassword      = "harbor-password"
	harborSkipTLSVerify = "harbor-skiptlsverify"
	harborType          = "harbor-type"
	harborSyncInterval  = "harbor-syncInterval"
	harborConfigPath    = "harbor-configPath"
)

// HarborOpts ...
type HarborOpts struct {
	URL           string
	Username      string
	Password      string
	SkipTLSVerify bool
	Type          string
	ConfigPath    string
	SyncInterval  int
}

// NewDefaultHarborOpts ...
func NewDefaultHarborOpts() *HarborOpts {
	return &HarborOpts{
		URL: "https://localhost:30003",
		// Default Harbor username/password
		Username:      "admin",
		Password:      "Harbor12345",
		SkipTLSVerify: false,
		Type:          "harbor-v2.0",
		ConfigPath:    "/configs/scanner/default.yaml",
		SyncInterval:  300,
	}
}

// GetHarborOpts ...
func GetHarborOpts(cmd *cobra.Command) *HarborOpts {
	return &HarborOpts{
		URL:           viper.GetString(harborURL),
		Username:      viper.GetString(harborUsername),
		Password:      viper.GetString(harborPassword),
		SkipTLSVerify: viper.GetBool(harborSkipTLSVerify),
		ConfigPath:    viper.GetString(harborConfigPath),
		Type:          viper.GetString(harborType),
		SyncInterval:  viper.GetInt(harborSyncInterval),
	}
}

// AddHarborFlags ...
func AddHarborFlags(cmd *cobra.Command) {
	defaultOps := NewDefaultHarborOpts()
	cmd.Flags().String(harborURL, defaultOps.URL, "harbor url")
	cmd.Flags().String(harborUsername, defaultOps.Username, "harbor username")
	cmd.Flags().String(harborPassword, defaultOps.Password, "harbor password !!!NOTE: prefer passing this as env injected via k8s secret!!!")
	cmd.Flags().Bool(harborSkipTLSVerify, defaultOps.SkipTLSVerify, "skip TLS cert verification step for harbor API")
	cmd.Flags().String(harborType, defaultOps.Type, "registry Type")
	cmd.Flags().String(harborConfigPath, defaultOps.ConfigPath, "all registry config")
	cmd.Flags().Int(harborSyncInterval, defaultOps.SyncInterval, "registry sync Interval")
	for _, flag := range []string{
		harborURL,
		harborUsername,
		harborPassword,
		harborSkipTLSVerify,
		harborConfigPath,
		harborType,
		harborSyncInterval,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
