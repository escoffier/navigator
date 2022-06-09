package util

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/smartystreets/goconvey/convey"
)

func TestJwt(t *testing.T) {
	secretKey := "file"
	sub := "sub"
	urlPath := "https://console3-test-cn.tensorsecurity.cn/#/image-security/images"
	jt := NewJWT(secretKey)

	convey.Convey("Test GenJWTToken ", t, func() {
		token, err := jt.GenJWTToken(sub, time.Second*3)
		convey.So(err, convey.ShouldBeNil)

		validateToken := jt.ValidateToken(token)
		convey.So(validateToken, convey.ShouldEqual, true)
		time.Sleep(5 * time.Second)
		validateToken = jt.ValidateToken(token)
		convey.So(validateToken, convey.ShouldEqual, false)
	})

	convey.Convey("Test GenJWTToken ", t, func() {
		token, err := jt.GenJWTToken(sub, time.Second*3)
		convey.So(err, convey.ShouldBeNil)
		decode, err := jt.DecodeJwtToken(token)
		convey.So(err, convey.ShouldBeNil)
		if err == nil {
			convey.So(decode.Subject, convey.ShouldEqual, sub)
		}
	})

	convey.Convey("Test GenJWTToken ", t, func() {
		encrypted, err := AesEncryptCBC([]byte(urlPath), []byte(DownloadFileKey))

		convey.So(err, convey.ShouldBeNil)
		key := hex.EncodeToString(encrypted)
		jt := NewJWT(string(secretKey))

		token, err := jt.GenJWTToken(string(key), time.Second*60)

		convey.So(err, convey.ShouldBeNil)

		jt2 := NewJWT(string(secretKey))

		jwtToken, err := jt2.DecodeJwtToken(token)
		convey.So(err, convey.ShouldBeNil)
		validateToken := jt2.ValidateToken(token)

		convey.So(validateToken, convey.ShouldEqual, true)

		decodeString, err := hex.DecodeString(jwtToken.Subject)
		convey.So(err, convey.ShouldBeNil)

		cbc, err := AesDecryptCBC(decodeString, []byte(DownloadFileKey))
		convey.So(err, convey.ShouldBeNil)
		convey.So(string(cbc), convey.ShouldEqual, urlPath)

	})

}
