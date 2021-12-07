package util

import (
	"fmt"
	"os"

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

func InitPGDB() (*gorm.DB, error) {
	rdbUser := os.Getenv("RDB_USER")
	rdbPassword := os.Getenv("RDB_PASSWORD")
	rdbHost := os.Getenv("RDB_HOST")
	rdbPort := os.Getenv("RDB_PORT")
	rdbDBName := os.Getenv("RDB_DBNAME")
	rdbSSLMode := os.Getenv("RDB_SSLMODE")
	if rdbUser == "" || rdbPassword == "" || rdbHost == "" || rdbPort == "" || rdbSSLMode == "" || rdbDBName == "" {
		return nil, errors.New("missing RDB env")
	}
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Asia/Shanghai",
		rdbHost, rdbUser, rdbPassword, rdbDBName, rdbPort, rdbSSLMode,
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
