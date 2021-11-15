package store

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
)

var dbInitOnce sync.Once
var scannerGormWrapDb *rdbtools.GormWrapper
var scannerOrm *ScannerOrm
var scannerDb *ScannerDB // todo: should be deprecated
var scanConfigDao *ScanConfigDao
var redisClients []*redis.Client = make([]*redis.Client, 2)

func InitDb(dbConnectStr string) (err error) {
	dbInitOnce.Do(func() {
		scannerGormWrapDb, err = rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {
			return gorm.Open(postgres.Open(dbConnectStr), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
		})
		if err != nil {
			err = fmt.Errorf("connect db err:%v", err)
			return
		}
		var sqlDB *sql.DB
		sqlDB, err = scannerGormWrapDb.Get().DB()
		if err != nil {
			err = fmt.Errorf("get db error:%v", err)
			return
		}

		sqlDB.SetMaxIdleConns(30)
		sqlDB.SetMaxOpenConns(60)
		sqlDB.SetConnMaxLifetime(time.Hour)
		scannerOrm = NewScannerOrm(scannerGormWrapDb)
		scanConfigDao = NewScanConfigDao(scannerGormWrapDb)
		// todo: should be deprecated
		scannerDb = NewScannerDB(scannerGormWrapDb)
	})

	return
}

func GetScannerWrapperDb() *rdbtools.GormWrapper {
	return scannerGormWrapDb
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

func InitRedisClient(endpoint, password string) error {
	sa := strings.Split(endpoint, ",")
	rc, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{ // share data use db 0
		MasterName:    "mymaster", // default name
		SentinelAddrs: sa,
		Password:      password,
		DB:            0,
	})
	if err != nil {
		return err
	}
	redisClients[0] = rc

	rc1, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{ // image secure use db 1
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      password,
		DB:            1,
	})
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
