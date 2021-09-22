package dal

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db *gorm.DB

	envVars = map[string]string{
		"PGSQL_HOST":     "localhost",
		"PGSQL_USER":     "pguser",
		"PGSQL_DBNAME":   "tensorsecurity",
		"PGSQL_SSLMODE":  "disable",
		"PGSQL_PASSWORD": "pgpassword",
	}
)

func initDB(t *testing.T) {
	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		envVars["PGSQL_HOST"],
		envVars["PGSQL_USER"],
		envVars["PGSQL_DBNAME"],
		envVars["PGSQL_SSLMODE"],
		envVars["PGSQL_PASSWORD"],
	)

	t.Log("connInfo:", connInfo)
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold: time.Millisecond * 100, // Slow SQL threshold
			LogLevel:      logger.Info,            // Log level
			Colorful:      true,                   // Enable color
		},
	)

	var err error
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  connInfo,
		PreferSimpleProtocol: true,
	}), &gorm.Config{Logger: newLogger})
	if err != nil {
		t.Fatal(err)
	}

}
