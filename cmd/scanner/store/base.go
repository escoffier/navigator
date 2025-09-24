package store

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm/logger"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
)

var dbInitOnce sync.Once
var scannerDB *databases.RDBInstance
var ciDao *adaptStore.CiDao // 还在用
var redisClients = make([]*redis.Client, 2)

func NewRDBInstance() *databases.RDBInstance {
	if scannerDB != nil {
		return scannerDB
	}
	db, err := databases.NewRDBWithMySQLByEnv(context.Background(), databases.OptionWithmaxOpenConnections(60),
		databases.OptionWithMaxIdleConns(30),
		databases.OptionWithConnMaxLifeTime(time.Hour),
	)
	if err != nil {
		logging.Get().Err(err).Msg("New RDBInstance")
		err = fmt.Errorf("connect db err:%v", err)
		return nil
	}

	logLevelStr := os.Getenv("LOGGING_LEVEL")
	if logLevelStr == "0" {
		db.SetDebugMode()
	}
	scannerDB = db
	ciDao = adaptStore.NewCiDao(scannerDB)

	return scannerDB
}

func InitDb(loglevel string) (err error) {
	dbInitOnce.Do(func() {
		var err error
		scannerDB, err = databases.NewRDBWithMySQLByEnv(
			context.Background(),
			databases.OptionWithmaxOpenConnections(60),
			databases.OptionWithMaxIdleConns(30),
			databases.OptionWithConnMaxLifeTime(time.Hour),
		)
		if err != nil {
			logging.Get().Err(err).Msg("InitDb")
			err = fmt.Errorf("connect db err:%v", err)
			return
		}
		rdbLogLevel := int(logger.Error)
		if len(loglevel) > 0 {
			var parseErr error
			rdbLogLevel, parseErr = strconv.Atoi(loglevel)
			if parseErr != nil {
				rdbLogLevel = int(logger.Error)
			}
		}
		if rdbLogLevel == int(logger.Info) {
			scannerDB.SetDebugMode()
		}
		ciDao = adaptStore.NewCiDao(scannerDB)
	})

	return
}

func GetRDBInstance() *databases.RDBInstance {
	for {
		if scannerDB != nil {
			return scannerDB
		}
		scannerDB = NewRDBInstance()
		logging.Get().Info().Msg("RDBInstance is nil waite 1 minute")
		time.Sleep(time.Second * 10)
	}
}

func GetCiDb() adaptStore.ScanCiInterface {
	return ciDao
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

	// flash redis db 1
	// 使用trivy进行扫描时，trivy会记录层信息到redis中，如果上一次解析出错的话，那么之后的扫描会直接取到错误的，
	// 现在我们的扫描已经在数据库中做了缓存，可以scanner启动时清空redis里的缓存
	rc1.FlushAll(context.Background())
	return nil
}

func GetRedisClient(index uint) (*redis.Client, error) {
	if index >= uint(len(redisClients)) {
		return nil, fmt.Errorf("not found redis client with index %d,max:%v", index, len(redisClients))
	}
	return redisClients[index], nil
}
