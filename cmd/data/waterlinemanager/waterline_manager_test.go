package waterlinemanager

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	manager *Manager
)

func initWaterlineManagerRequirement(t *testing.T) {
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
	mongodb, err := util.NewMongoClient(
		util2.GetEnvWithDefault(env.MongoUsername, env.DefaultMongoUsername),
		util2.GetEnvWithDefault(env.MongoPassword, ""),
		util2.GetEnvWithDefault(env.MongoEndpoint, env.DefaultMongoEndpoint),
		util2.GetEnvWithDefault(env.MongoDatabase, env.DefaultMongoDatabase))
	if err != nil {
		t.Fatal(err)
	}

	manager = NewManager(mongodb, model.DataWaterlineSettingCollection.String())
}
func TestManager_GetWaterline(t *testing.T) {
	initWaterlineManagerRequirement(t)
	percentage, err := manager.GetWaterline(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(percentage)
}

func TestManager_SetWaterline(t *testing.T) {
	initWaterlineManagerRequirement(t)
	assert.Equal(t, nil, manager.SetWaterline(context.TODO(), 30))
	percentage, err := manager.GetWaterline(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 30, percentage)
}
