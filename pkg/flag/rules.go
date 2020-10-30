package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	availableRulesFolder = "available-rules-folder"
)

// RulesOpts the Rules options.
type RulesOpts struct {
	AvailableRulesFolder string
}

// NewDefaultRulesOpts returns a new default Rules options.
func NewDefaultRulesOpts() *RulesOpts {
	return &RulesOpts{
		AvailableRulesFolder: "/rules-available",
	}
}

// GetRulesOpts parses the cobra.Command and returns the RulesOpts.
func GetRulesOpts(cmd *cobra.Command) *RulesOpts {
	return &RulesOpts{
		AvailableRulesFolder: viper.GetString(availableRulesFolder),
	}
}

// AddRulesFlags adds the Rules-specific command line arguments to the cobra.Command.
func AddRulesFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultRulesOpts()
	cmd.PersistentFlags().String(availableRulesFolder, defaultOpts.AvailableRulesFolder, "Rules available rules folder")

	for _, flag := range []string{availableRulesFolder} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
