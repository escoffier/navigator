package api

import (
	"os"
	"testing"

	"github.com/dchest/captcha"
	"github.com/stretchr/testify/assert"
)

func TestCaptcha(t *testing.T) {
	id := captcha.NewLen(captchaLen)
	value := GetCaptchaString(id)
	t.Log(id, value)
	f, err := os.Create("testCaptcha.png")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = captcha.WriteImage(f, id, captchaWidth, captchaHeight)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, CaptchaVerifyString(id, value))
}
