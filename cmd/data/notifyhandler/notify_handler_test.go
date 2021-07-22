package notifyhandler

import (
	"context"
	"fmt"
	"github.com/badoux/checkmail"
	"github.com/stretchr/testify/assert"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"os"
	"testing"
)

var (
	handler *Handler
)

func initHandler(t *testing.T) {
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
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	db, err := util.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, nil, db.Get().Migrator().DropTable(&model.ModuleGroup{}))
	assert.Equal(t, nil, db.Get().AutoMigrate(&model.ModuleGroup{}))
	assert.Equal(t, nil, db.Get().Migrator().DropTable(&model.User{}))
	assert.Equal(t, nil, db.Get().AutoMigrate(&model.User{}))

	mg1 := model.ModuleGroup{
		ModuleNameZh: "用户中心",
		ModuleNameEn: "User Center",
	}

	mg2 := model.ModuleGroup{
		ModuleNameZh: "平台",
		ModuleNameEn: "Platform",
	}

	mg3 := model.ModuleGroup{
		ModuleNameZh: "容器安全",
		ModuleNameEn: "Container security",
	}

	assert.Equal(t, nil, db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg1).Error)
	assert.Equal(t, nil, db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg2).Error)
	assert.Equal(t, nil, db.Get().Table(model.ModuleGroup{}.TableName()).Create(&mg3).Error)

	assert.Equal(t, nil, db.Get().Create(&model.User{
		ID:       1,
		UserName: "weichangan@tensorsecurity.cn",
		ModuleID: `["2","3"]`,
		Rule:     model.RoleAdmin,
	}).Error)

	assert.Equal(t, nil, db.Get().Create(&model.User{
		ID:       2,
		UserName: "nonsense",
		ModuleID: `["2","3"]`,
		Rule:     model.RoleAdmin,
	}).Error)

	assert.Equal(t, nil, db.Get().Create(&model.User{
		ID:       3,
		UserName: "nonsense@tensorsecurity.cn",
		ModuleID: `["1", "3"]`,
		Rule:     model.RoleAdmin,
	}).Error)

	handler = NewHandler(db, &EmailConf{
		Username: "console-robot@tensorsecurity.cn",
		Host:     "smtp.feishu.cn",
		Port:     465,
		Password: "r8UJgg7ejpSoDOAF",
	})
}

func TestMailCheck(t *testing.T) {
	assert.Equal(t, nil, checkmail.ValidateFormat("weichangan@tensorsecurity.cn"))
	assert.Equal(t, checkmail.ErrBadFormat, checkmail.ValidateFormat("nonsense"))
}

func TestLoadAdminEmails(t *testing.T) {
	initHandler(t)
	emails, err := handler.loadAdminEmails(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	t.Log(emails)
}

func TestSendEmail(t *testing.T) {
	initHandler(t)
	err := handler.sendEmail([]string{"weichangan@tensorsecurity.cn"}, "test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestNotify(t *testing.T) {
	initHandler(t)
	assert.Equal(t, nil, handler.Notify(context.TODO(), model.DataTypeHotLogic, &model.StorageView{
		Total: 1000000000,
		Used:  900000000,
	}))
}
