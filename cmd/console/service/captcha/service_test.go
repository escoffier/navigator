package captcha

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
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

func TestService_CreateCaptcha(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	id := service.CreateCaptcha()
	t.Log(id)
	t.Log(service.GetCaptchaString(id))
}

func TestService_GetCaptchaString(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	t.Log(service.GetCaptchaString("nonsense"))
}

func TestService_Verify(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	id := service.CreateCaptcha()
	t.Log(id)
	content := service.GetCaptchaString(id)
	t.Log(content)
	assert.Equal(t, true, service.Verify(id, content))
	assert.Equal(t, false, service.Verify(id, content))
}

func TestService_WriteImage(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	id := service.CreateCaptcha()
	t.Log(id, service.GetCaptchaString(id))

	f, err := os.Create("testCaptcha.png")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = service.WriteImage(f, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestService_Set(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	service.Set("1", []byte("1"))
	t.Log(string(service.Get("1", false)))
	time.Sleep(service.conf.CaptchaExpiration)
	t.Log(string(service.Get("1", false)))

	service.Set("2", []byte("2"))
	t.Log(string(service.Get("2", true)))
	t.Log(string(service.Get("2", true)))
}

func TestService_Get(t *testing.T) {
	initService(t)
	service, ok := GetService()
	if !ok {
		t.Fatal("get service fail")
	}

	t.Log(service.Get("nonsense", false))
}
