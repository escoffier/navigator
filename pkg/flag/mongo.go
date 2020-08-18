package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	mongoEndpoint = "mongo-endpoint"
	mongoUsername = "mongo-username"
	mongoPassword = "mongo-password"
	mongoDatabase = "mongo-database"
)

// MongoOpts the Mongo options.
type MongoOpts struct {
	Endpoint string
	Username string
	Password string
	Database string
}

// NewDefaultMongoOpts returns a new default mongo options.
func NewDefaultMongoOpts() *MongoOpts {
	return &MongoOpts{
		Endpoint: "localhost:27017",
		Username: "redstone",
		Password: "redstoneMongo123",
		Database: "vegeta",
	}
}

// GetMongoOpts parses the cobra.Command and returns the MongoOpts.
func GetMongoOpts(cmd *cobra.Command) *MongoOpts {
	return &MongoOpts{
		Endpoint: viper.GetString(mongoEndpoint),
		Username: viper.GetString(mongoUsername),
		Password: viper.GetString(mongoPassword),
		Database: viper.GetString(mongoDatabase),
	}
}

// AddMongoFlags adds the Mongo-specific command line arguments to the cobra.Command.
func AddMongoFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultMongoOpts()
	cmd.PersistentFlags().String(mongoEndpoint, defaultOpts.Endpoint, "Mongo endpoint")
	cmd.PersistentFlags().String(mongoUsername, defaultOpts.Username, "Mongo username")
	cmd.PersistentFlags().String(mongoPassword, defaultOpts.Password, "Mongo password")
	cmd.PersistentFlags().String(mongoDatabase, defaultOpts.Database, "Mongo database")
	for _, flag := range []string{mongoEndpoint, mongoUsername, mongoPassword, mongoDatabase} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
