package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	db *gorm.DB

	envVars = map[string]string{
		"PGSQL_HOST":     "localhost",
		"PGSQL_USER":     "pguser",
		"PGSQL_DBNAME":   "tensorsecurity",
		"PGSQL_SSLMODE":  "disable",
		"PGSQL_PASSWORD": "pgpassword",
	}
)

func initDB(t *testing.T) {
	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		envVars["PGSQL_HOST"],
		envVars["PGSQL_USER"],
		envVars["PGSQL_DBNAME"],
		envVars["PGSQL_SSLMODE"],
		envVars["PGSQL_PASSWORD"],
	)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold: time.Millisecond * 100, // Slow SQL threshold
			LogLevel:      logger.Info,            // Log level
			Colorful:      true,                   // Enable color
		},
	)

	var err error
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  connInfo,
		PreferSimpleProtocol: true,
	}), &gorm.Config{Logger: newLogger})
	if err != nil {
		t.Fatal(err)
	}

	err = db.AutoMigrate(&model.ATTCKRuleData{}, &model.ATTCKRuleMask{}, &model.ATTCKRuleMaskVersion{})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("init db success")
}

func TestLoadATTCKConfData(t *testing.T) {
	initDB(t)
	data, err := LoadATTCKConfData(context.TODO(), db)
	if err != nil && err != ErrATTCKConfDataNotFound {
		t.Fatal(err)
	}
	t.Log(data)
}

func TestLoadATTCKConfVersions(t *testing.T) {
	initDB(t)
	total, versions, err := LoadATTCKConfVersions(context.TODO(), db, 0, 10)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(total, versions)
}

func TestLoadATTCKRuleMasks(t *testing.T) {
	initDB(t)
	masks, err := LoadATTCKRuleMasks(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(masks)
}

func TestLoadATTCKRuleMaskVersion(t *testing.T) {
	initDB(t)
	version, err := LoadATTCKRuleMaskVersion(context.TODO(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(version)
}

func TestSaveATTCKConfData(t *testing.T) {
	initDB(t)
	baseOffset, err := SaveATTCKConfData(context.TODO(), db, &model.ATTCKRuleData{
		Content: []byte("test"),
		ATTCKConfVersion: model.ATTCKConfVersion{
			Version:   "1.0",
			Username:  "testUsername",
			CreatedAt: time.Now(),
		},
	}, []string{"testDelete1", "testDelete2"}, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(baseOffset)
}

func TestUpdateRuleMask(t *testing.T) {
	initDB(t)
	var err = UpdateRuleMask(context.TODO(), db, []*model.ATTCKRuleMask{
		{
			Name: "add1",
		},
		{
			Name: "add2",
		},
	}, []string{"del1", "del2"}, 1)
	if err != nil {
		t.Fatal(err)
	}
}
