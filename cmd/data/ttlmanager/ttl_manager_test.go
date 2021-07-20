package ttlmanager

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	manager *Manager
)

func initTTLManagerRequirement(t *testing.T) {
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

	manager = NewManager(mongodb, model.DataTTLSettingCollection.String())
}
func TestManager_GetTTLDayOffset(t *testing.T) {
	initTTLManagerRequirement(t)

	var ttl int
	var err error

	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeHotLogic)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(def.GCTaskTypeHotLogic.String(), ttl)

	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeHotOffline)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(def.GCTaskTypeHotOffline.String(), ttl)

	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeCold)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(def.GCTaskTypeCold.String(), ttl)
}

func TestManager_SetTTLDayOffset(t *testing.T) {
	initTTLManagerRequirement(t)

	assert.Equal(t, nil, manager.SetTTLDayOffset(context.TODO(), def.GCTaskTypeHotLogic, 25))
	assert.Equal(t, nil, manager.SetTTLDayOffset(context.TODO(), def.GCTaskTypeHotOffline, 26))
	assert.Equal(t, nil, manager.SetTTLDayOffset(context.TODO(), def.GCTaskTypeCold, 300))

	var ttl int
	var err error
	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeHotLogic)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 25, ttl)

	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeHotOffline)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 26, ttl)

	ttl, err = manager.GetTTLDayOffset(context.TODO(), def.GCTaskTypeCold)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 300, ttl)
}
