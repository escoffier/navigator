package cleaner

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"strconv"
	"testing"
	"time"

	"gorm.io/datatypes"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	postgresDB *rdbtools.GormWrapper
)

func initPGCleanerRequirement(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	var envVars = map[string]string{
		env.RDBHost:     "localhost",
		env.RDBUser:     "pguser",
		env.RDBDBName:   "tensorsecurity",
		env.RDBSSLMode:  "disable",
		env.RDBPassword: "pgpassword",
	}

	for key, val := range envVars {
		if err := os.Setenv(key, val); err != nil {
			t.Fatal(err)
		}
	}

	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		util2.GetEnvWithDefault(env.RDBHost, env.DefaultRDBHost),
		util2.GetEnvWithDefault(env.RDBUser, env.DefaultRDBUser),
		util2.GetEnvWithDefault(env.RDBDBName, env.DefaultRDBDBName),
		util2.GetEnvWithDefault(env.RDBSSLMode, env.DefaultRDBSSLMode),
		util2.GetEnvWithDefault(env.RDBPassword, ""),
	)

	var err error
	postgresDB, err = rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCleaner(t *testing.T) {
	initPGCleanerRequirement(t)

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	c := NewPostgresCleaner(postgresDB, []*conf.RDBDumpItem{
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

func TestMockInsert(t *testing.T) {
	initPGCleanerRequirement(t)
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

	err := postgresDB.Get().AutoMigrate(&Test{}, &Test2{})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	base := now.Unix()
	for i := 0; i < 5000; i++ {
		err = postgresDB.Get().Create(&Test{
			TestField1: strconv.Itoa(rand.Int()),
			TestField2: rand.Int31(),
			TestField3: datatypes.JSON("{\"x\":\"y\"}"),
			Timestamp:  now.Add(-time.Duration(rand.Uint64()) % (15 * time.Hour * 24)),
		}).Error
		if err != nil {
			t.Fatal(err)
		}
		err = postgresDB.Get().Create(&Test2{
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

func TestRestore(t *testing.T) {
	initPGCleanerRequirement(t)

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	dumpPath := path.Join(pwd, "/dump_test/postgresql", "tests/2021-06-05T18:11:13.113")
	t.Log(dumpPath)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	cmd := exec.CommandContext(ctx, "psql",
		"-h", util2.GetEnvWithDefault(env.RDBHost, env.DefaultRDBHost),
		"-U", util2.GetEnvWithDefault(env.RDBUser, env.DefaultRDBUser),
		"-d", util2.GetEnvWithDefault(env.RDBDBName, env.DefaultRDBDBName),
		"-c", fmt.Sprintf("\\copy tests from '%s'", dumpPath),
	)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "PGPASSWORD=%s", util2.GetEnvWithDefault(env.RDBPassword, ""))
	stdout, stderr, err := util2.ExecuteCmd(cmd)
	if err != nil {
		t.Log(stderr)
		t.Fatal(err)
	}

	if stderr != "" {
		t.Fatal(stderr)
	}

	t.Log(stdout)
}

func TestTimeFormat(t *testing.T) {
	t.Log(time.Now().Format("2006-01-02T15:04:05.000"))
	t.Log(time.Now().Format("2006-01-02T15:04:05.000Z"))
	t.Log(time.Now().Format("2006-01-02 15:04:05.000"))
}

func TestGetPrimaryKeyGroup(t *testing.T) {
	item := &conf.RDBDumpItem{}
	t.Log(getPrimaryKeyGroup(item))
	t.Log(getPrimaryKeyColumns(item))

	item.PrimaryKey = []string{"uuid"}
	t.Log(getPrimaryKeyGroup(item))
	t.Log(getPrimaryKeyColumns(item))

	item.PrimaryKey = []string{"id1", "id2"}
	t.Log(getPrimaryKeyGroup(item))
	t.Log(getPrimaryKeyColumns(item))
}

func TestGetPrimaryKeySort(t *testing.T) {
	item := &conf.RDBDumpItem{}
	t.Log(getPrimaryKeySortColumns(item, "desc"))

	item.PrimaryKey = []string{"uuid"}
	t.Log(getPrimaryKeySortColumns(item, "desc"))

	item.PrimaryKey = []string{"id1", "id2"}
	t.Log(getPrimaryKeySortColumns(item, "desc"))
}