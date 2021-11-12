package config

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

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
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	dbWrapper, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

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
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	dbWrapper, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

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
