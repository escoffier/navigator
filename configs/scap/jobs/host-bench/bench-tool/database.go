package main

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
)

type ScanResult struct {
	ID            uint32 `gorm:"column:id"`
	TaskID        string `gorm:"column:task_id"`
	CheckType     string `gorm:"column:check_type"`
	NodeName      string `gorm:"column:node_name"`
	ClusterKey    string `gorm:"column:cluster_key"`
	PolicyID      string `gorm:"column:policy_id"`
	State         string `gorm:"column:state"`
	ActualValue   string `gorm:"column:actual_value"`
	RemediationEn string `gorm:"column:remediation_en"`
	RemediationZh string `gorm:"column:remediation_zh"`
	CreatedAt     int64  `gorm:"column:create_at"`
	Status        int32  `gorm:"column:status"`
}

func (sr *ScanResult) TableName() string {
	return "scan_bench_result"
}

type PostgreDB struct {
	Db *gorm.DB
}

func NewConnPostgreDB() (*PostgreDB, error) {
	pgDsn := os.Getenv("PG_DSN")
	//print debug log
	fmt.Printf("postgre dsn : %s.\n", pgDsn)

	if pgDsn == "" {
		return nil, errors.Errorf("postgre dsn is nil")
	}
	//connect postgre
	db, err := gorm.Open(postgres.Open(pgDsn), &gorm.Config{})

	if err != nil {
		return nil, errors.Errorf("received error connecting to database: %s", err)
	}

	err = db.AutoMigrate(&ScanResult{})
	if err != nil {
		sqlDb, err := db.DB()
		if sqlDb != nil {
			sqlDb.Close()
		}
		return nil, errors.Errorf("error on automigrate: %s", err)
	}
	//print debug log
	fmt.Println("connect postgre db success!")

	return &PostgreDB{Db: db}, nil
}

func (pg PostgreDB) Close() error {
	if pg.Db != nil {
		sqlDb, err := pg.Db.DB()
		if err != nil {
			return errors.Errorf("postgre db error, %v", err)
		}

		return sqlDb.Close()
	}
	return nil
}

func (pg PostgreDB) SaveScanResult(result *ScanResult) error {
	if pg.Db == nil {
		return errors.Errorf("postgre db handle is nil")
	}

	return pg.Db.WithContext(context.Background()).Create(result).Error
}
