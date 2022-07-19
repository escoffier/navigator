package model

import (
	"database/sql/driver"
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

func TestManager(t *testing.T) {
	m := Managers{"123", "456"}
	value, err := m.Value()
	if err != nil {
		return
	}
	t.Logf("%v", string(value.([]byte)))
}

func TestStringSlice_Value(t *testing.T) {
	tests := []struct {
		name    string
		l       StringSlice
		want    driver.Value
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			l:    []string{"aac", "123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.l.Value()
			if (err != nil) != tt.wantErr {
				t.Errorf("Value() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			data := got.([]byte)
			t.Log([]string{"aac1", "1234"})
			t.Log(string(data))
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("Value() got = %v, want %v", got, tt.want)
			//}
		})
	}
}

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

func TestDB(t *testing.T) {
	db, mock, _ := mockGorm()
	mock.ExpectBegin()
	mock.ExpectExec("^INSERT").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	//mock.ExpectExec("^INSERT").WillReturnError(nil)
	//db.GetReadDB().DryRun = true
	cnt_rels := []*TensorContainerRelation{{ID: 123, Arguments: StringSlice{"bin/sh", "bin/sh", "sleep 5m"}, Environment: EnvVars{{Name: "1222", Value: "dddd"}}}}

	db.GetReadDB().Debug().Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"updated_at", "container_id", "name", "status", "pod_name"}),
	}).Create(cnt_rels)

}
