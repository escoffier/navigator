package configs

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	"github.com/DATA-DOG/go-sqlmock"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/mysql"
)

func Test_UserOperator_Export(t *testing.T) {
	assert := assert.New(t)

	db, mock, err := sqlmock.New()
	assert.Error(err)

	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		SkipInitializeWithVersion: true,
		Conn:                      db,
	}), &gorm.Config{})
	assert.Error(err)

	rdb := &databases.RDBInstance{}
	v1 := reflect.ValueOf(rdb).Elem().FieldByName("followerDB")
	newV1 := reflect.NewAt(v1.Type(), unsafe.Pointer(v1.UnsafeAddr())).Elem()
	rv1 := reflect.ValueOf(gormDB)
	newV1.Set(rv1)

	v2 := reflect.ValueOf(rdb).Elem().FieldByName("primaryDB")
	newV2 := reflect.NewAt(v2.Type(), unsafe.Pointer(v2.UnsafeAddr())).Elem()
	rv2 := reflect.ValueOf(gormDB)
	newV2.Set(rv2)

	mock.ExpectQuery("^SELECT").WillReturnRows(sqlmock.NewRows([]string{"fake"}))

	conf, err := (&UserOperator{rdb: rdb}).Export(context.Background())
	assert.Error(err)

	t.Log(string(conf))
}
