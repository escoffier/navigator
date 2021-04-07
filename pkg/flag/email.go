package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	emailUsername = "email-username"
	emailPassword = "email-password"
	emailHost     = "email-host"
	emailPort     = "email-port"
	emailSuffix   = "email-suffix"
	emailCheck    = "email-check"
)

// EmailOpts the Email options.
type EmailOpts struct {
	Username string
	Password string
	Host     string
	Port     string
	Suffix   string
	Check    bool
}

// NewDefaultEmailOpts returns a new default email options.
func NewDefaultEmailOpts() *EmailOpts {
	return &EmailOpts{
		Username: "84447952@qq.com",
		Password: "kfvnnmhwfiikcaae",
		Host:     "smtp.qq.com",
		Port:     "465",
		Suffix:   "*",
		Check:    true,
	}
}

// GetEmailOpts parses the cobra.Command and returns the EmailOpts.
func GetEmailOpts(cmd *cobra.Command) *EmailOpts {
	return &EmailOpts{
		Username: viper.GetString(emailUsername),
		Password: viper.GetString(emailPassword),
		Host:     viper.GetString(emailHost),
		Port:     viper.GetString(emailPort),
		Suffix:   viper.GetString(emailSuffix),
		Check:    viper.GetBool(emailCheck),
	}
}

// AddEmailOpts adds the Email-specific command line arguments to the cobra.Command.
func AddEmailOpts(cmd *cobra.Command) {
	defaultOpts := NewDefaultEmailOpts()
	cmd.PersistentFlags().String(emailUsername, defaultOpts.Username, "Email username")
	cmd.PersistentFlags().String(emailPassword, defaultOpts.Password, "Email password")
	cmd.PersistentFlags().String(emailHost, defaultOpts.Host, "Email host")
	cmd.PersistentFlags().String(emailPort, defaultOpts.Port, "Email port")
	cmd.PersistentFlags().String(emailSuffix, defaultOpts.Suffix, "Email suffix")
	cmd.PersistentFlags().Bool(emailCheck, defaultOpts.Check, "Email check")

	for _, flag := range []string{emailUsername, emailPassword, emailHost, emailPort, emailSuffix, emailCheck} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
