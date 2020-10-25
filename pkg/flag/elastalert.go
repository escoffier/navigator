package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	availableRulesFolder = "elastalert-available"
	appliedRulesFolder   = "elastalert-applied"
)

// ElastalertOpts the Elastalert options.
type ElastalertOpts struct {
	AvailableRulesFolder string
	AppliedRulesFolder   string
}

// NewDefaultElastalertOpts returns a new default elastalert options.
func NewDefaultElastalertOpts() *ElastalertOpts {
	return &ElastalertOpts{
		AvailableRulesFolder: "/rules-available",
		AppliedRulesFolder:   "/rules-applied",
	}
}

// GetElastalertOpts parses the cobra.Command and returns the ElastalertOpts.
func GetElastalertOpts(cmd *cobra.Command) *ElastalertOpts {
	return &ElastalertOpts{
		AvailableRulesFolder: viper.GetString(availableRulesFolder),
		AppliedRulesFolder:   viper.GetString(appliedRulesFolder),
	}
}

// AddElastalertFlags adds the Elastalert-specific command line arguments to the cobra.Command.
func AddElastalertFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultElastalertOpts()
	cmd.PersistentFlags().String(availableRulesFolder, defaultOpts.AvailableRulesFolder, "Elastalert available rules folder")
	cmd.PersistentFlags().String(appliedRulesFolder, defaultOpts.AppliedRulesFolder, "Elastalert applied rules folder")

	for _, flag := range []string{availableRulesFolder, appliedRulesFolder} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
