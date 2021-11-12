package waterlinemanager

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	manager *Manager
)

func initWaterlineManagerRequirement(t *testing.T) {
	var envVars = map[string]string{
		env.PostgresHost:     "localhost",
		env.PostgresUser:     "pguser",
		env.PostgresDBName:   "tensorsecurity",
		env.PostgresSSLMode:  "disable",
		env.PostgresPassword: "pgpassword",
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
