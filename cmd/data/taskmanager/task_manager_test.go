package taskmanager

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	manager *Manager
)

func initTaskManagerRequirement(t *testing.T) {
	var envVars = map[string]string{
		env.RDBHost:     "localhost",
		env.RDBUser:     "pguser",
		env.RDBDBName:   "tensorsecurity",
		env.RDBSSLMode:  "disable",
		env.RDBPassword: "pgpassword",
	}

	for key, val := range envVars {
		if err := os.Setenv(key, val); err != nil {
			t.Fatal(err)
		}
	}
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	db, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, nil, db.Get().AutoMigrate(&model.GCTask{}))
	manager = NewManager(db, time.Second*20)
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

	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), logicTask.Hash, model.GCCompleted))
	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), offlineTask.Hash, model.GCCompleted))
	assert.Equal(t, nil, manager.UpdateTaskStatus(context.TODO(), coldTask.Hash, model.GCCompleted))
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

	logicTask, err := manager.GetGCTask(context.TODO(), createdLogicTask.Hash)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, logicTask.Status)

	offlineTask, err := manager.GetGCTask(context.TODO(), createdOfflineTask.Hash)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, offlineTask.Status)

	coldTask, err := manager.GetGCTask(context.TODO(), createdColdTask.Hash)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, model.GCFailed, coldTask.Status)
}

func TestManager_GetGCTask(t *testing.T) {
	initTaskManagerRequirement(t)
	_, err := manager.GetGCTask(context.TODO(), "nosense")
	assert.Equal(t, def.ErrTaskNotFound, err)
}
