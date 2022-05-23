package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func mockGorm() (*databases.RDBInstance, sqlmock.Sqlmock, error) {
	db, mock, err := sqlmock.New()
	if nil != err {
		return nil, nil, fmt.Errorf("init sqlmock failed, err: %w", err)
	}

	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		SkipInitializeWithVersion: true,
		Conn:                      db,
	}), &gorm.Config{})
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

var privateKey []byte

func mockRSA() {
	publicKey = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA2YHUuqUAy8V935fbxWJ1A19lFJ0WHbV9fol5/Eu1h+cJxekFE4vW
+28aA9Nz6nZVwTuYk0DmAkebjIq18SXfq/G65a3qnLbQE1xteVKwYVnhLqBTOkiM
RmOX7VXeIV05gnClq94HRaokxLIVlqbZhkSqB5Uwhlpr1qLhcn8TB0PdN4ARCfkK
eL+nKCn1ZsmNavrrEcUuALUtjtEK113QDcv1AActTnUxBUXco2Z4+np86aU+KfYB
9khGrMIN1JZn6MV7L4BYxtl/IGU1cV625OPhjYbppD9zwAM3i4/Nx55BIcxIdmcT
344MHicA7FTYSZxiSms2G71qw69HGGNczwIDAQAB
-----END RSA PUBLIC KEY-----`)

	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2YHUuqUAy8V935fbxWJ1A19lFJ0WHbV9fol5/Eu1h+cJxekF
E4vW+28aA9Nz6nZVwTuYk0DmAkebjIq18SXfq/G65a3qnLbQE1xteVKwYVnhLqBT
OkiMRmOX7VXeIV05gnClq94HRaokxLIVlqbZhkSqB5Uwhlpr1qLhcn8TB0PdN4AR
CfkKeL+nKCn1ZsmNavrrEcUuALUtjtEK113QDcv1AActTnUxBUXco2Z4+np86aU+
KfYB9khGrMIN1JZn6MV7L4BYxtl/IGU1cV625OPhjYbppD9zwAM3i4/Nx55BIcxI
dmcT344MHicA7FTYSZxiSms2G71qw69HGGNczwIDAQABAoIBAQDIMwo86Vc8OAFN
5pbwrVkKy6lcOeJ7YeuqpptTL9RczLlgIsT7YsF0GKUXVG/jJRx1iYc8MoYDHyn7
SEmDNtsThqICefvyVwpaZ76T5xpV4Ma1hfhVMyV6PH1AhMK6bvZaK5kyAmErLBo/
ubLJQbYCMf1WkWlioKOVocJlArXe/lOUKCDY956ZsI/5o28lEI7UklzbmsUpjlwj
ss32uAYVwtWGs3aT/8j2YWiUPAi1OlvRY0sdUtKuVZAcAy728QFlf1keEJp4CSBc
2OgCvPVxrIs+IoKy+b8jZuXnGfsssnkk1LjwLTG+Y4xyjZAZKaim0I6bQy1KGnL9
kWNzK9MRAoGBAO+X9MAAyfkN+iNB+fQFFWEvk+GVH3qiAYY+9IKQaMcT79mnwgpM
bTrdA3ZBjn/bsfJwg6hf8T5RC3cjiPTLSzHvghLEP/rLeLcTEdoilIIPqiuLMvdu
ly8J/Z5lU+HWbjN577qWAp6z5jqXw3HhwWafF53ruwGNm31YvD0IZpPDAoGBAOhm
s+jK8w+uFU1DMM70ILcJU/eppqxqw9L24Ulz3+N6WAxmWNtfksrIs80V/FkG3man
4rsf0DmPscvAlVbAHL0hiOC11bLqncxl3WGfywu/1hYC8tV43sJtW5lySPuxTTn9
h3/GRmLFUkQ8paIk7E2q2l5qV8tReLGAoCSvrf4FAoGAXd0vQoVMmyjRpTx0uxe+
v3tPOSId2gJcDIbfbcM7eTqjTab+SuCULmplr8+RDyA3v546xh0IOvyvPDaMsjJu
vBpz3/xIgG10Vmy/IrFHcwjGBxcamXsW+ZO1a3eQ/DnwpHQR6gxY7GnYOX45UIU8
KoMLUpAGjF4420uHO3XuEdcCgYEAvwkten7Zrln7SLeit3wWKF+SllLun2xj7Fbk
eey2bddz6T14bVvy3p58rmkUNlpfFyOKTSepkqd8D3EPUXA6L34RdiYCtEAH1q0l
fcpMrivTX+SsmK3y7v/V/BzlwX/Na43shCwIT8jEBzOTM+YGGRIIzvO7l3YxMDf7
bCy9acECgYBmCidyPdwukH1L/XH4U/G2AdixNy1VOvIHMfYUvrPxOkOf28bcFMQ3
J5jVkhKmJjjiZxpD4hQk2+GvVc1a07igkWlrbi+hZczc+K0M6K+sh0Xo1KlOgoN+
r2eXCjsWC5h4xI0VEVHI0rTmL7zhqXlvUK/ZF9yJME2oCNaJVGx1dw==
-----END RSA PRIVATE KEY-----
`)
}

func loadPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key not in pem format")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to key file: %w", err)
	}

	return key, nil
}

func TestGenerateEnvKey(t *testing.T) {
	rdb, mock, err := mockGorm()
	if err != nil {
		t.Fatal(err)
	}
	mockRSA()

	mock.ExpectQuery("^SELECT").WillReturnRows(sqlmock.NewRows([]string{}))
	err = Init(rdb)
	assert.NoError(t, err)

	envKey, err := GenerateEnvKey()
	assert.NoError(t, err)
	encrypted, err := base64.StdEncoding.DecodeString(envKey)
	assert.NoError(t, err)

	key, err := loadPrivateKey(privateKey)
	assert.NoError(t, err)

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, key, encrypted)
	assert.NoError(t, err)

	ek := envKeyInfo{}
	err = json.Unmarshal(decrypted, &ek)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), ek.NodeNum)
}

func TestRefreshLicenseInfo(t *testing.T) {
	rdb, mock, err := mockGorm()
	if err != nil {
		t.Fatal(err)
	}
	mockRSA()

	mock.ExpectQuery("^SELECT").WillReturnRows(sqlmock.NewRows([]string{}))
	err = Init(rdb)
	assert.NoError(t, err)

	key, err := loadPrivateKey(privateKey)
	assert.NoError(t, err)

	tests := []struct {
		info      Info
		expectErr bool
	}{
		{
			info: Info{
				SerialNo:    "fake",
				LicenseType: "fake",
				ExpireAt:    time.Now().Add(-time.Minute).Unix(),
				NodeLimit:   0,
				Module:      "fake",
				Eigenvalue:  "fake",
			},
			expectErr: true,
		},
		{
			info: Info{
				SerialNo:    "fake",
				LicenseType: "fake",
				ExpireAt:    time.Now().Add(time.Minute).Unix(),
				NodeLimit:   0,
				Module:      "fake",
				Eigenvalue:  "fake",
			},
			expectErr: false,
		},
	}

	for _, test := range tests {
		rawSign := util.SHA256(fmt.Sprintf(signTpl, test.info.Eigenvalue, test.info.ExpireAt, test.info.LicenseType, test.info.Module, test.info.NodeLimit, test.info.SerialNo))
		sign, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, rawSign)
		assert.NoError(t, err)
		test.info.Sign = base64.StdEncoding.EncodeToString(sign)

		licenseCode, err := json.Marshal(test.info)
		assert.NoError(t, err)

		licenseCode, err = util.AesEncryptCBC(licenseCode, publicKey[31:47])
		assert.NoError(t, err)

		err = RefreshLicenseInfo(base64.StdEncoding.EncodeToString(licenseCode), "fake")
		if test.expectErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}

		t.Log(ValidateLicense(false))
	}
}
