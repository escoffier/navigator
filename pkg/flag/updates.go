package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	offlineMode = "offline-mode"
)

// UpdateOpts
type UpdateOpts struct {
	OfflineMode bool
}

// NewDefaultUpdateOpts
func NewDefaultUpdateOpts() *UpdateOpts {
	return &UpdateOpts{
		OfflineMode: false,
	}
}

// GetUpdateOpts
func GetUpdateOpts(cmd *cobra.Command) *UpdateOpts {
	return &UpdateOpts{
		OfflineMode: viper.GetBool(offlineMode),
	}
}

// AddUpdateFlags
func AddUpdateFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultUpdateOpts()
	cmd.PersistentFlags().Bool(offlineMode, defaultOpts.OfflineMode, "Offline mode (won't access Internet)")

	for _, flag := range []string{offlineMode} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
