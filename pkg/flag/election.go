package flag

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gitlab.com/security-rd/go-pkg/leaderelection"
)

const (
	leaderElect   = "leader-elect"
	leaseDuration = "leader-elect-lease-duration"
	renewDeadline = "leader-elect-renew-deadline"
	retryPeriod   = "leader-elect-retry-period"
)

// NewDefaultHTTPOpts returns a new default http options.
func NewDefaultElectionOpts() *leaderelection.ElectionOpts {
	return &leaderelection.ElectionOpts{
		LeaseDuration: 15 * time.Second,
		RenewDeadline: 12 * time.Second,
		RetryPeriod:   2 * time.Second,
	}
}

// GetHTTPOpts parses the cobra.Command and returns the HTTPOpts.
func GetElectionOpts(cmd *cobra.Command) *leaderelection.ElectionOpts {
	return &leaderelection.ElectionOpts{
		LeaseDuration: viper.GetDuration(leaseDuration),
		RenewDeadline: viper.GetDuration(renewDeadline),
		RetryPeriod:   viper.GetDuration(retryPeriod),
	}
}

// AddHTTPFlags adds the http-specific command line arguments to the cobra.Command.
func AddElectionFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultElectionOpts()
	cmd.Flags().Duration(leaseDuration, defaultOpts.LeaseDuration, "lease duration")
	cmd.Flags().Duration(renewDeadline, defaultOpts.RenewDeadline, "renew deadline")
	cmd.Flags().Duration(retryPeriod, defaultOpts.RetryPeriod, "retry period")
	for _, flag := range []string{leaseDuration, renewDeadline, retryPeriod, leaderElect} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
