package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	postgresWithConsole = "console-postgres"
	postgresPVC         = "postgres-pvc"
	postgresPod         = "postgres-pod"
	postgresDataPath    = "postgres-data-path"
)

type PostgresOpts struct {
	PostgresConnectionString string
	PVC                      string
	Pod                      string
	DataPath                 string
}

func NewDefaultPostgresOpts() *PostgresOpts {
	return &PostgresOpts{
		PostgresConnectionString: "postgres://postgres:postgres@localhost:5432/postgres",
		PVC:                      "tensorsec-postgres-pvc",
		Pod:                      "tensorsec-postgres-pod",
		DataPath:                 "/data",
	}
}
func GetPostgresOpts(cmd *cobra.Command) *PostgresOpts {
	return &PostgresOpts{
		PostgresConnectionString: viper.GetString(postgresWithConsole),
		PVC:                      viper.GetString(postgresPVC),
		Pod:                      viper.GetString(postgresPod),
		DataPath:                 viper.GetString(postgresDataPath),
	}
}

func AddPostgresFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultPostgresOpts()
	cmd.PersistentFlags().String(postgresWithConsole, defaultOpts.PostgresConnectionString, "postgres DB connection string")
	cmd.PersistentFlags().String(postgresPVC, defaultOpts.PVC, "postgres kubernetes PVC")
	cmd.PersistentFlags().String(postgresPod, defaultOpts.Pod, "postgres kubernetes Pod")
	cmd.PersistentFlags().String(postgresDataPath, defaultOpts.DataPath, "postgres data path")
	for _, flag := range []string{
		postgresWithConsole,
		postgresPVC,
		postgresPod,
		postgresDataPath,
	} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
