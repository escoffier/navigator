package util

import (
	"fmt"

	"gorm.io/gorm/logger"

	"github.com/pkg/errors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PGMaster struct {
	Host     string `mapstructure:"host"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbName"`
	Port     int    `mapstructure:"port"`
}

func InitPGDB(dbcfg PGMaster) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=Asia/Shanghai",
		dbcfg.Host, dbcfg.User, dbcfg.Password, dbcfg.DBName, dbcfg.Port,
	)
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
	}), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
	if err != nil {
		return nil, errors.Wrap(err, "failed to connet specified db")
	}
	db.Logger = logger.Discard.LogMode(logger.Silent)
	return db, nil
}
