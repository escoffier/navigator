package store

import (
	"context"
	"os"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
)

var dbInitOnce sync.Once
var RDB *databases.RDBInstance

func NewRDBInstance() *databases.RDBInstance {
	if RDB != nil {
		return RDB
	}
	db, err := databases.NewRDBWithMySQLByEnv(context.Background(), databases.OptionWithmaxOpenConnections(60),
		databases.OptionWithMaxIdleConns(30),
		databases.OptionWithConnMaxLifeTime(time.Hour),
	)
	if err != nil {
		return nil
	}

	logLevelStr := os.Getenv("LOGGING_LEVEL")
	if logLevelStr == "0" {
		db.SetDebugMode()
	}
	RDB = db

	return RDB
}
