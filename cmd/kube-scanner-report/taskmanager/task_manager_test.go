package taskmanager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	manager *Manager
)

func initTaskManagerRequirement(t *testing.T) {
	var db *rdbtools.GormWrapper
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	db, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	manager = NewManager(db, time.Second*20)
}

func TestManager_CreateGCTask(t *testing.T) {
	initTaskManagerRequirement(t)
	cluster := util.GenerateUUIDHex()
	record, err := manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(record)

	_, err = manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	assert.Equal(t, def.ErrTaskConflict, err)
}

func TestManager_DealExpireTasks(t *testing.T) {
	initTaskManagerRequirement(t)
	cluster := util.GenerateUUIDHex()
	record, err := manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(record.UUID)
	time.Sleep(time.Second * 30)
	err = manager.DealExpireRecords(context.TODO(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_UpdateRecord(t *testing.T) {
	initTaskManagerRequirement(t)
	cluster := util.GenerateUUIDHex()
	record, err := manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	if err != nil {
		t.Fatal(err)
	}

	err = manager.UpdateRecord(context.TODO(), record.UUID, model.KubeHunterRecordStatusFailed, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = manager.UpdateRecord(context.TODO(), record.UUID, model.KubeHunterRecordStatusComplete, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_GetLatestCompleteRecord(t *testing.T) {
	initTaskManagerRequirement(t)
	cluster := util.GenerateUUIDHex()
	record, err := manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.GetLatestCompleteRecord(context.TODO(), cluster)
	if err != nil {
		if err == def.ErrNoRecord {
			t.Log("no record")
		} else {
			t.Fatal(err)
		}
	}

	err = manager.UpdateRecord(context.TODO(), record.UUID, model.KubeHunterRecordStatusComplete, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.GetLatestCompleteRecord(context.TODO(), cluster)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(result)
}

func TestManager_CheckInProgress(t *testing.T) {
	initTaskManagerRequirement(t)
	cluster := util.GenerateUUIDHex()
	record, err := manager.CreateKubeHunterRecord(context.TODO(), cluster, util.GenerateUUIDHex(), "user")
	if err != nil {
		t.Fatal(err)
	}

	inProgress, err := manager.CheckInProgress(context.TODO(), cluster)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, true, inProgress)
	err = manager.UpdateRecord(context.TODO(), record.UUID, model.KubeHunterRecordStatusExpired, nil)
	if err != nil {
		t.Fatal(err)
	}

	inProgress, err = manager.CheckInProgress(context.TODO(), cluster)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, false, inProgress)
}
