package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	agentID = "agent-id"
)

// AgentOpts the Vegeta Agent options.
type AgentOpts struct {
	AgentID string
}

// NewDefaultAgentOpts returns a new default Agent options.
func NewDefaultAgentOpts() *AgentOpts {
	return &AgentOpts{
		AgentID: "agentID",
	}
}

// GetAgentOpts parses the cobra.Command and returns the AgentOpts.
func GetAgentOpts(cmd *cobra.Command) *AgentOpts {
	return &AgentOpts{
		AgentID: viper.GetString(agentID),
	}
}

// AddAgentFlags adds the Agent-specific command line arguments to the cobra.Command.
func AddAgentFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultAgentOpts()
	cmd.Flags().String(agentID, defaultOpts.AgentID, "Agent ID")
	for _, flag := range []string{agentID} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
