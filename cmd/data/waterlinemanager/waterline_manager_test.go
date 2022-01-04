package waterlinemanager

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

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	manager *Manager
)

func initWaterlineManagerRequirement(t *testing.T) {
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
