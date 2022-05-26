package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
)

var dbInitOnce sync.Once
var scannerDB *databases.RDBInstance
var scannerOrm *ScannerOrm
var scannerDb *ScannerDB // todo: should be deprecated
var scanConfigDao *ScanConfigDao
var redisClients []*redis.Client = make([]*redis.Client, 2)

func InitDb(loglevel string) (err error) {
	dbInitOnce.Do(func() {
		var err error
		scannerDB, err = databases.NewRDBWithMySQLByEnv(context.Background(), databases.OptionWithmaxOpenConnections(60),
			databases.OptionWithMaxIdleConns(30),
			databases.OptionWithConnMaxLifeTime(time.Hour),
		)
		if err != nil {
			err = fmt.Errorf("connect db err:%v", err)
			return
		}
		if loglevel == "debug" {
			scannerDB.SetDebugMode()
		}
		scannerOrm = NewScannerOrm(scannerDB)
		scanConfigDao = NewScanConfigDao(scannerDB)
		// todo: should be deprecated
		scannerDb = NewScannerDB(scannerDB)
	})

	return
}

func GetScannerWrapperDb() *databases.RDBInstance {
	return scannerDB
}

func GetScanConfigDao() *ScanConfigDao {
	return scanConfigDao
}

func GetScannerOrmDb() *ScannerOrm {
	return scannerOrm
}

func GetScannerDb() *ScannerDB {
	return scannerDb
}

func InitRedisClient() error {
	// share data use db 0
	rc0, err := cache.NewRedis(cache.SetDB(0))
	if err != nil {
		return err
	}
	redisClients[0] = rc0

	// image secure use db 1
	rc1, err := cache.NewRedis(cache.SetDB(1))
	if err != nil {
		return err
	}
	redisClients[1] = rc1
	return nil
}

func GetRedisClient(index uint) (*redis.Client, error) {
	if index >= uint(len(redisClients)) {
		return nil, fmt.Errorf("not found redis client with index %d,max:%v", index, len(redisClients))
	}
	return redisClients[index], nil
}
