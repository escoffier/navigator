package apiscan

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
)

type Service struct {
	db *databases.RDBInstance
}

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(db *databases.RDBInstance) error {
	if db == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		instance, err = newService(db)
		go func(scanDB *gorm.DB) {
			logrus.Infoln("begin a go routine to clean unfinished api scan job")
			ticker := time.NewTicker(time.Minute * 1)
			defer ticker.Stop()
			for range ticker.C {
				cleanUnfinishedJob(scanDB)
			}
		}(db.Get())
	})
	return err
}

func cleanUnfinishedJob(db *gorm.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gerr := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Exec("update ivan_assets_apis set status = 0 where status = 1 and updated_at < DATE_SUB(NOW(), INTERVAL 100 MINUTE)").Error
	})
	if gerr != nil {
		return
	}
}

func newService(db *databases.RDBInstance) (*Service, error) {
	service := &Service{
		db: db,
	}
	return service, nil
}

var (
	ErrClusterNotFound = errors.New("cluster not found")
)
