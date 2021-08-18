package util

import (
	"fmt"

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
	}), &gorm.Config{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to connet specified db")
	}
	return db, nil
}
