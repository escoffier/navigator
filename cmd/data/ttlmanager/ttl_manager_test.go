package ttlmanager

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	manager *Manager
)

func initTTLManagerRequirement(t *testing.T) {
	dsn := "root:123456@tcp(127.0.0.1:3306)/local_test?charset=utf8mb4&parseTime=True&loc=Local"

	f := func() (*gorm.DB, error) {
		newLogger := logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold: time.Millisecond * 100, // Slow SQL threshold
				LogLevel:      logger.Info,            // Log level
				Colorful:      true,                   // Enable color
			},
		)

		return gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newLogger})
	}
	dbWrapper, err := rdbtools.GormWrapperOpen(time.Second, f)
	if err != nil {
		t.Fatal(err)
	}

	manager = NewManager(dbWrapper)
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
