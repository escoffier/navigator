package taskmanager

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

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	manager *Manager
)

func initTaskManagerRequirement(t *testing.T) {
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

	manager = NewManager(mongodb, model.GCTaskCollection.String(), time.Second*20)
}

func TestManager_CreateGCTask(t *testing.T) {
	initTaskManagerRequirement(t)
	logicTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotLogic)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(logicTask)

	offlineTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotOffline)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(offlineTask)

	coldTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeCold)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(coldTask)

	_, err = manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotLogic)
	assert.Equal(t, def.ErrTaskConflict, err)
	_, err = manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotOffline)
	assert.Equal(t, def.ErrTaskConflict, err)
	_, err = manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotOffline)
	assert.Equal(t, def.ErrTaskConflict, err)

	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), logicTask.ID, model.GCCompleted))
	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), offlineTask.ID, model.GCCompleted))
	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), coldTask.ID, model.GCCompleted))
}

func TestManager_DealExpireTasks(t *testing.T) {
	initTaskManagerRequirement(t)
	createdLogicTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotLogic)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(createdLogicTask)

	createdOfflineTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeHotOffline)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(createdOfflineTask)

	createdColdTask, err := manager.CreateGCTask(context.TODO(), def.GCTaskTypeCold)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(createdColdTask)

	assert.Equal(t, nil, manager.DealExpireTasks(context.TODO(), time.Now()))
	time.Sleep(time.Second * 30)
	assert.Equal(t, nil, manager.DealExpireTasks(context.TODO(), time.Now()))

	logicTask, err := manager.GetGCTask(context.TODO(), createdLogicTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, logicTask.Status)

	offlineTask, err := manager.GetGCTask(context.TODO(), createdOfflineTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, offlineTask.Status)

	coldTask, err := manager.GetGCTask(context.TODO(), createdColdTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, coldTask.Status)
}

func TestManager_GetGCTask(t *testing.T) {
	initTaskManagerRequirement(t)
	_, err := manager.GetGCTask(context.TODO(), primitive.NilObjectID)
	assert.Equal(t, def.ErrTaskNotFound, err)
}
