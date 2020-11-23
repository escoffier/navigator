package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	mongoEndpoint     = "mongo-endpoint"
	mongoUsername     = "mongo-username"
	mongoPassword     = "mongo-password"
	mongoDatabase     = "mongo-database"
	mongoK8SecretName = "mongo-k8secretname"
	mongoPVC          = "mongo-pvc"
	mongoPod          = "mongo-pod"
	mongoDataPath     = "mongo-data-path"
)

// MongoOpts the Mongo options.
type MongoOpts struct {
	Endpoint   string
	Username   string
	Password   string
	Database   string
	SecretName string
	PVC        string
	Pod        string
	DataPath   string
}

// NewDefaultMongoOpts returns a new default mongo options.
func NewDefaultMongoOpts() *MongoOpts {
	return &MongoOpts{
		Endpoint:   "localhost:27017",
		Username:   "redstone",
		Password:   "redstoneMongo123",
		Database:   "vegeta",
		SecretName: "tensorsec-mongodb",
		PVC:        "tensorsec-mongodb-pvc",
		Pod:        "tensorsec-mongodb-pod",
		DataPath:   "/data",
	}
}

// GetMongoOpts parses the cobra.Command and returns the MongoOpts.
func GetMongoOpts(cmd *cobra.Command) *MongoOpts {
	return &MongoOpts{
		Endpoint:   viper.GetString(mongoEndpoint),
		Username:   viper.GetString(mongoUsername),
		Password:   viper.GetString(mongoPassword),
		Database:   viper.GetString(mongoDatabase),
		SecretName: viper.GetString(mongoK8SecretName),
		PVC:        viper.GetString(mongoPVC),
		Pod:        viper.GetString(mongoPod),
		DataPath:   viper.GetString(mongoDataPath),
	}
}

// AddMongoFlags adds the Mongo-specific command line arguments to the cobra.Command.
func AddMongoFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultMongoOpts()
	cmd.PersistentFlags().String(mongoEndpoint, defaultOpts.Endpoint, "Mongo endpoint")
	cmd.PersistentFlags().String(mongoUsername, defaultOpts.Username, "Mongo username")
	cmd.PersistentFlags().String(mongoPassword, defaultOpts.Password, "Mongo password")
	cmd.PersistentFlags().String(mongoDatabase, defaultOpts.Database, "Mongo database")
	cmd.PersistentFlags().String(mongoK8SecretName, defaultOpts.SecretName, "Mongo kubernetes secret name")
	cmd.PersistentFlags().String(mongoPVC, defaultOpts.PVC, "Mongo kubernetes PVC")
	cmd.PersistentFlags().String(mongoPod, defaultOpts.Pod, "Mongo kubernetes Pod")
	cmd.PersistentFlags().String(mongoDataPath, defaultOpts.DataPath, "Mongo data path")

	for _, flag := range []string{mongoEndpoint, mongoUsername, mongoPassword, mongoDatabase, mongoK8SecretName, mongoPVC, mongoPod, mongoDataPath} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
