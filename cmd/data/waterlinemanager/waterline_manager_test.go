package waterlinemanager

import (
	"context"
	"github.com/stretchr/testify/assert"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"math/rand"
	"os"
	"testing"
	"time"
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
		env.GetEnvWithDefault(env.MongoUsername, env.DefaultMongoUsername),
		env.GetEnvWithDefault(env.MongoPassword, ""),
		env.GetEnvWithDefault(env.MongoEndpoint, env.DefaultMongoEndpoint),
		env.GetEnvWithDefault(env.MongoDatabase, env.DefaultMongoDatabase))
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
