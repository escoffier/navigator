package apiscan

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	"sync"
	"time"
)

type Service struct {
	db *rdbtools.GormWrapper
}

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(db *rdbtools.GormWrapper) error {
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

func newService(db *rdbtools.GormWrapper) (*Service, error) {
	service := &Service{
		db: db,
	}
	return service, nil
}

var (
	ErrClusterNotFound = errors.New("cluster not found")
)
