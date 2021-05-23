package cleaner

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"
)

var (
	mongodb *mongotools.DatabaseWrapper
)

func initMongoCleanerRequirement(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	var envVars = map[string]string{
		env.MongoEndpoint:       "127.0.0.1:27017",
		env.MongoDatabase:       "vegeta",
		env.MongoReadPreference: "primary",
	}

	for key, val := range envVars {
		if err := os.Setenv(key, val); err != nil {
			t.Fatal(err)
		}
	}

	var err error
	mongodb, err = util.NewMongoClient(
		env.GetEnvWithDefault(env.MongoUsername, env.DefaultMongoUsername),
		env.GetEnvWithDefault(env.MongoPassword, ""),
		env.GetEnvWithDefault(env.MongoEndpoint, env.DefaultMongoEndpoint),
		env.GetEnvWithDefault(env.MongoDatabase, env.DefaultMongoDatabase))
	if err != nil {
		t.Fatal(err)
	}
}

func TestMongoCleaner(t *testing.T) {
	initMongoCleanerRequirement(t)
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	cleaner := NewMongoCleaner(mongodb, &conf.MongoDumpConf{
		Batch:     1000,
		BaseDir:   path.Join(pwd, "dump_test", "mongo"),
		TimeField: "historicised_timestamp",
	})

	err = cleaner.Clean(context.TODO(), 7)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInsertMongo(t *testing.T) {
	initMongoCleanerRequirement(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	for i := 0; i < 500; i++ {
		_, err := mongodb.Get().Collection("test").InsertOne(ctx, bson.D{
			{
				Key:   "historicised_timestamp",
				Value: time.Now().Add(-time.Duration(rand.Uint64()) % (15 * time.Hour * 24)),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMongoRestore(t *testing.T) {
	initMongoCleanerRequirement(t)
	var mongoURI string
	mongoUsername := env.GetEnvWithDefault(env.MongoUsername, env.DefaultMongoUsername)
	mongoPassword := env.GetEnvWithDefault(env.MongoPassword, "")
	mongoEndpoint := env.GetEnvWithDefault(env.MongoEndpoint, env.DefaultMongoEndpoint)
	mongoDatabase := env.GetEnvWithDefault(env.MongoDatabase, env.DefaultMongoDatabase)

	if mongoUsername != "" && mongoPassword != "" {
		mongoURI = fmt.Sprintf("mongodb://%s:%s@%s", mongoUsername, mongoPassword, mongoEndpoint)
	} else {
		mongoURI = fmt.Sprintf("mongodb://%s", mongoEndpoint)
	}

	file := "/Users/moses/workspace/tensor/tensornavigator/cmd/data/tool/cleaner/dump_test/mongo/test/2021-04-30T18:21:52.564"

	cmd := exec.Command("mongoimport",
		fmt.Sprintf("--collection=test"),
		fmt.Sprintf("--uri=\"%s\"", mongoURI),
		"-d", mongoDatabase,
		fmt.Sprintf("--file=%s", file),
	)

	t.Log(util2.ExecuteCmd(cmd))
}
