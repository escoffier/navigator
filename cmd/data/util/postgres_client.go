package util

import (
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewPostgresClient(postgresDSN string) (*rdbtools.GormWrapper, error) {
	return rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(postgresDSN), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
		if err != nil {
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(10)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
		return db, nil
	})
}
