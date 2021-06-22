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

	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	util2 "gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	postgresDB *rdbtools.GormWrapper
)

func initPGCleanerRequirement(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	var envVars = map[string]string{
		env.PostgresHost:     "localhost",
		env.PostgresUser:     "pguser",
		env.PostgresDBName:   "tensorsecurity",
		env.PostgresSSLMode:  "disable",
		env.PostgresPassword: "pgpassword",
	}

	for key, val := range envVars {
		if err := os.Setenv(key, val); err != nil {
			t.Fatal(err)
		}
	}

	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		env.GetEnvWithDefault(env.PostgresHost, env.DefaultPostgresHost),
		env.GetEnvWithDefault(env.PostgresUser, env.DefaultPostgresUser),
		env.GetEnvWithDefault(env.PostgresDBName, env.DefaultPostgresDBName),
		env.GetEnvWithDefault(env.PostgresSSLMode, env.DefaultPostgresSSLMode),
		env.GetEnvWithDefault(env.PostgresPassword, ""),
	)

	var err error
	postgresDB, err = util.NewPostgresClient(postgresqlDSN)
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

	c := NewPostgresCleaner(postgresDB, []*conf.DumpItem{
		{
			Name:      "tests",
			TimeField: "timestamp",
			DataDir:   path.Join(pwd, "dump_test", "postgresql", "tests"),
			Batch:     50,
		},
	})

	err = c.Clean(context.TODO(), 6)
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

	err := postgresDB.Get().AutoMigrate(&Test{})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
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
		"-h", env.GetEnvWithDefault(env.PostgresHost, env.DefaultPostgresHost),
		"-U", env.GetEnvWithDefault(env.PostgresUser, env.DefaultPostgresUser),
		"-d", env.GetEnvWithDefault(env.PostgresDBName, env.DefaultPostgresDBName),
		"-c", fmt.Sprintf("\\copy tests from '%s'", dumpPath),
	)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "PGPASSWORD=%s", env.GetEnvWithDefault(env.PostgresPassword, ""))
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
