package model

import (
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"reflect"
	"testing"
	"unsafe"
)

func mockGorm() (*databases.RDBInstance, sqlmock.Sqlmock, error) {
	db, mock, err := sqlmock.New()
	if nil != err {
		return nil, nil, fmt.Errorf("init sqlmock failed, err: %w", err)
	}

	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		SkipInitializeWithVersion: true,
		Conn:                      db,
	}), &gorm.Config{Logger: logger.Default.LogMode(logger.Info)})
	if nil != err {
		return nil, nil, fmt.Errorf("init DB with sqlmock failed, err %w", err)
	}

	rdb := &databases.RDBInstance{}
	v1 := reflect.ValueOf(rdb).Elem().FieldByName("followerDB")
	newV1 := reflect.NewAt(v1.Type(), unsafe.Pointer(v1.UnsafeAddr())).Elem()
	rv1 := reflect.ValueOf(gormDB)
	newV1.Set(rv1)

	v2 := reflect.ValueOf(rdb).Elem().FieldByName("primaryDB")
	newV2 := reflect.NewAt(v2.Type(), unsafe.Pointer(v2.UnsafeAddr())).Elem()
	rv2 := reflect.ValueOf(gormDB)
	newV2.Set(rv2)

	return rdb, mock, nil
}

func TestUpsertBait(t *testing.T) {
	rdb, mock, _ := mockGorm()
	mock.ExpectBegin()
	mock.ExpectExec("^INSERT").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	//mock.ExpectExec("^INSERT").WillReturnError(nil)
	//db.GetReadDB().DryRun = true

	var onDupUpdatedColsForBait = []string{
		"name",
		"bait_name",
		"image",
	}

	bs := &BaitService{
		TableBase:      TableBase{},
		Name:           "",
		BaitName:       "test",
		BaitId:         0,
		ClusterKey:     "",
		Namespace:      "",
		ResourceName:   "",
		Prefix:         "",
		Image:          "",
		RegistryId:     0,
		WorkLoadStatus: "",
		HaveAlerts:     false,
		Replica:        0,
		OutboundOff:    false,
	}
	rdb.Get().Model(&BaitService{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForBait),
	}).Create(bs)
}
