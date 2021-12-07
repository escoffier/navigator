package ttlmanager

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	manager *Manager
)

func initTTLManagerRequirement(t *testing.T) {
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

	assert.Equal(t, nil, db.Get().AutoMigrate(&model.TensorConfig{}))
	manager = NewManager(db)
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
