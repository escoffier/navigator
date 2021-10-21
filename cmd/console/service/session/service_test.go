package session

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func initService(t *testing.T) {
	redisCli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	if err := redisCli.Ping(context.TODO()).Err(); err != nil {
		t.Fatal(err)
	}

	if err := Init(redisCli, DefaultConf); err != nil {
		t.Fatal(err)
	}
}

func TestService_SaveUserSession(t *testing.T) {
	initService(t)
	userSession := &model.UserSession{
		Username:  "testUsername",
		Pwd:       "testPwd",
		Salt:      "testSalt",
		Role:      "testRole",
		ModuleID:  "testModuleID",
		Checked:   true,
		BanStatus: 0,
		External:  true,
	}

	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	if err := service.SaveUserSession(context.TODO(), userSession); err != nil {
		t.Fatal(err)
	}
}

func TestService_GetUserSession(t *testing.T) {
	initService(t)
	userSession := &model.UserSession{
		Username:  "testUsername",
		Pwd:       "testPwd",
		Salt:      "testSalt",
		Role:      "testRole",
		ModuleID:  "testModuleID",
		Checked:   true,
		BanStatus: 0,
		External:  true,
	}

	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	if err := service.SaveUserSession(context.TODO(), userSession); err != nil {
		t.Fatal(err)
	}

	result, err := service.GetUserSession(context.TODO(), "testUsername")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(*result)

	_, err = service.GetUserSession(context.TODO(), "nonsense")
	assert.Equal(t, ErrNotFound, err)

	time.Sleep(service.conf.SessionExpiration)
	_, err = service.GetUserSession(context.TODO(), "testUsername")
	assert.Equal(t, ErrNotFound, err)
}

func TestService_DeleteUserSession(t *testing.T) {
	initService(t)
	userSession := &model.UserSession{
		Username:  "testUsername",
		Pwd:       "testPwd",
		Salt:      "testSalt",
		Role:      "testRole",
		ModuleID:  "testModuleID",
		Checked:   true,
		BanStatus: 0,
		External:  true,
	}

	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	if err := service.SaveUserSession(context.TODO(), userSession); err != nil {
		t.Fatal(err)
	}

	if err := service.DeleteUserSession(context.TODO(), "testUsername"); err != nil {
		t.Fatal(err)
	}

	if err := service.DeleteUserSession(context.TODO(), "nonsense"); err != nil {
		t.Fatal(err)
	}
}

func TestService_RefreshUserSession(t *testing.T) {
	initService(t)
	userSession := &model.UserSession{
		Username:  "testUsername",
		Pwd:       "testPwd",
		Salt:      "testSalt",
		Role:      "testRole",
		ModuleID:  "testModuleID",
		Checked:   true,
		BanStatus: 0,
		External:  true,
	}

	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	if err := service.RefreshUserSession(context.TODO(), "nonsense"); err != nil {
		t.Fatal(err)
	}

	if err := service.SaveUserSession(context.TODO(), userSession); err != nil {
		t.Fatal(err)
	}

	time.Sleep(service.conf.SessionExpiration / 2)
	if err := service.RefreshUserSession(context.TODO(), "testUsername"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(service.conf.SessionExpiration/2 + time.Second)
	if _, err := service.GetUserSession(context.TODO(), "testUsername"); err != nil {
		t.Fatal(err)
	}
}
