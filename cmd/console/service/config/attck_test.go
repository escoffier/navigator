package config

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func TestParseItems(t *testing.T) {
	data, err := ioutil.ReadFile("encrypt_rule.data")
	if err != nil {
		t.Fatal(err)
	}

	copyData := make([]byte, len(data))
	copy(copyData, data)

	version, rules, err := parseItems(data)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(version)
	for _, rule := range rules {
		t.Log("name:", rule.name, "description:", rule.description,
			"ruleType:", rule.ruleType, "adapter:", rule.adapter,
			"severity:", rule.severity, "hthreats:", rule.hthreats)
	}

	for i := 0; i < len(data); i++ {
		if data[i] != copyData[i] {
			t.Fatal("data changed")
		}
	}
}

func TestFlushCache(t *testing.T) {
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

	redisCli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	handler, err := NewATTCKHandler(dbWrapper, redisCli)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(flushInterval * 2)
	_ = handler
}

func TestFlushCache_2(t *testing.T) {
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
	redisCli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	handler, err := NewATTCKHandler(dbWrapper, redisCli)
	if err != nil {
		t.Fatal(err)
	}

	handler.onlineOffset = 0
	handler.baseOffset = 0

	time.Sleep(flushInterval * 2)
	_ = handler
}
