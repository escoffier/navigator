package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	postgresWithConsole = "console-postgres"
)

type PostgresOpts struct {
	PostgresConnectionString string
}

func NewDefaultPostgresOpts() *PostgresOpts {
	return &PostgresOpts{
		PostgresConnectionString: "postgres://postgres:postgres@localhost:5432/postgres",
	}
}
func GetPostgresOpts(cmd *cobra.Command) *PostgresOpts {
	return &PostgresOpts{
		PostgresConnectionString: viper.GetString(postgresWithConsole),
	}
}

func AddPostgresFlags(cmd *cobra.Command) {
	postgresOpts := NewDefaultPostgresOpts()
	cmd.Flags().String(postgresWithConsole, postgresOpts.PostgresConnectionString, "postgres DB connection string")

	for _, flag := range []string{
		postgresWithConsole,
	} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
