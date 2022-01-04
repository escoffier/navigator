package cleaner

import (
	"context"
	"log"
	"math/rand"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"gorm.io/datatypes"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)


var (
	mysqlDB *rdbtools.GormWrapper
)

func initMysqlCleanerRequirement(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	dsn := "root:123456@tcp(127.0.0.1:3306)/local_test?charset=utf8mb4&parseTime=True&loc=Local"
	f := func() (*gorm.DB, error) {
		newLogger := logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold: time.Millisecond * 100, // Slow SQL threshold
				LogLevel:      logger.Info,            // Log level
				Colorful:      true,                   // Enable color
			},
		)

		return gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newLogger})
	}
	var err error
	mysqlDB, err = rdbtools.GormWrapperOpen(time.Second, f)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMysqlCleaner(t *testing.T) {
	initMysqlCleanerRequirement(t)

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	c := NewMysqlCleaner(mysqlDB, []*conf.RDBDumpItem{
		{
			DumpItem: conf.DumpItem{
				Name:      "tests",
				TimeField: "timestamp",
				DataDir:   path.Join(pwd, "dump_test", "postgresql", "tests"),
				Batch:     50,
			},
		},
		{
			DumpItem: conf.DumpItem{
				Name:      "test2",
				TimeField: "timestamp",
				DataDir:   path.Join(pwd, "dump_test", "postgresql", "test2"),
				Batch:     50,
			},
			PrimaryKey: []string{"p_key_1", "p_key_2"},
			Condition:  "status = 1",
			TTL:        100,
		},
	})

	err = c.Clean(context.TODO(), &def.CleanArg{
		DaysOffset: 1,
		Cron:       false,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMockMysqlInsert(t *testing.T) {
	initMysqlCleanerRequirement(t)
	type Test struct {
		ID         int32          `gorm:"primaryKey; autoIncrement; column:id"`
		TestField1 string         `gorm:"column:test_field_1"`
		TestField2 int32          `gorm:"column:test_field_2"`
		TestField3 datatypes.JSON `gorm:"column:test_field_3"`
		Timestamp  time.Time      `gorm:"index:test_timestamp_key; column:timestamp"`
	}

	type Test2 struct {
		PKey1 int32 `gorm:"primaryKey; column:p_key_1"`
		PKey2 int32 `gorm:"primaryKey; column:p_key_2"`

		Status     uint8          `gorm:"column:status"`
		TestField1 string         `gorm:"column:test_field_1"`
		TestField2 int32          `gorm:"column:test_field_2"`
		TestField3 datatypes.JSON `gorm:"column:test_field_3"`
		Timestamp  time.Time      `gorm:"index:test2_timestamp_key; column:timestamp"`
	}

	err := mysqlDB.Get().AutoMigrate(&Test{}, &Test2{})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	base := now.Unix()
	for i := 0; i < 5000; i++ {
		err = mysqlDB.Get().Create(&Test{
			TestField1: strconv.Itoa(rand.Int()),
			TestField2: rand.Int31(),
			TestField3: datatypes.JSON("{\"x\":\"y\"}"),
			Timestamp:  now.Add(-time.Duration(rand.Uint64()) % (15 * time.Hour * 24)),
		}).Error
		if err != nil {
			t.Fatal(err)
		}
		err = mysqlDB.Get().Create(&Test2{
			PKey1:      int32(i) + int32(base),
			PKey2:      int32(i) + int32(base),
			TestField1: strconv.Itoa(rand.Int()),
			Status:     uint8(rand.Uint64() % 2),
			TestField2: rand.Int31(),
			TestField3: datatypes.JSON("{\"x\":\"y\"}"),
			Timestamp:  now.Add(-time.Duration(rand.Uint64()) % (15 * time.Hour * 24)),
		}).Error
		if err != nil {
			t.Fatal(err)
		}
	}
}

