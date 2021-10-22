package rsa

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	private *Private
	public  *Public
)

var (
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwYxCm6x2eCHty6lpsojwsPIPXJ1ByLd6yVImC75fPnoEOnHu
vx5U2wLj+a4GM0z2JilgJtfvk3QQNECr9NdZUNUJngrRDvfMVaUZbTFpuqefBF0r
ru+HU8A08thidO4awum5K+0ogzStKPpi15PzuZbqmxySSYZyktn+iFK2fPM3zDjX
r6cT/0qmhonSjqkDEYKxeljgzbiA7lHO5dsGs6/fHidC/JxFjygaoaZMqvtgVOGg
vrQRRxPMO87+bi1bwBZo13jg1lE4d5kphmDYHaWqVh0RaSQM33DVGr9J4arotaCf
agvBPUqMLv2/dPIRO7IMSemo2CoHXzG6Xu3WNQIDAQABAoIBAQCj/1/1HnYnpsAi
YMNR5xzjIcgIdqtmEqn06imYq89yVds9Voqw4FeQV+uqBV31nBG6FjcF0tSKgb61
N9M8nDhu+IS0qH+qCifWrhVUY5kt8pgYD4ZTLVzihyuWVelfIN4GKBqh8MryGfFb
loWoGxJaQFk740LFECoG6rX09vjv93+rc0eVXCVBb1JDX4Mr/zwoR+RgmiYvtHH3
O/0Nlunbjg2y2mLz2zmeCCTUAg2A7gmjpP/VX/zoVf6lrrfSCdOVzjSQXyv8BxYA
qdMHHVxYwxHSBVjvojxxqH+bh/H2eTARLx+rgW6Fmvfvd17kJ/m1V9q3HTdOZ1YH
vuoRGwCFAoGBAPM9namTC1Brs+pm3wb3UQRwny22A6rbE8/tqINjWq8tc9DvJIUA
25+A3yTrKbhep/ELyAIRYvOd0RYAb0DokZT84OzTEJPQ7c7maCswX+iBPQyqxKd8
QiP99P1W38tCj1n9omoufnXr+Eu97u+MGvZMKtYd5qhLZfjX8YO36fcTAoGBAMuz
VtTgfX3bMs8fgcET9K4NRmy1uKG8XKD6xReX7c9OB4g2NhEKlQtz0B4XaclSqFlW
sAGbUMOihpluDhgfxRDOWQWCSSUDpAuCfHTlraTxDmY+Dx1HZ4R3J0xSESy6FI1n
NLCmT4rpt7iEbFfzBkHe3WoYTK2GXAsHZ9CH376XAoGAZd2qB3gzRsy0HjhSsqIk
Zc2cfBI72vPAilWnOs8DDVXlqNxd2O2RDG12BgoOAM5zWrlqW6NYY1n2VFZ+QRqk
zVZSBBwoVx8qWHmZqmyp3b8yB/oEPXgGYvhZ/zbApmkLi85ylDFAeLYH2ACE7gEo
0Xj4f48qJ9TbsakN1fHRo80CgYEAh36mTnl43+OTW3SgsZadlbzc0GjcBDEwCCBm
Q3haxh8oIXG16wX3+CM0FyAJzNF/i9V+w8LVKRyNnbc4BtHzGme3jVOJZeaTEtjc
AkHYjDOQGXBES3x4ngNID5szM2YfT6OLx8kIdeVawJDNJH9R9TTSYMUDFBWgWfG2
G16V9McCgYAG5GZBMBVJxRhC/JPinK+iLJm178ASGPWJwAN+o2XcaRsyBAy308jQ
9ODefXcLuwFc7iJ27hiykSh7+JOjw8bFGb70R9dnnDlYfMFc14jd1o5XuPpVYFTT
eZ0hsX2YDYFwfzXF2JyyJgCqFPl6PmFlG96edyZxDXZMJ5kT8hpYUA==
-----END RSA PRIVATE KEY-----
`

	publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYxCm6x2eCHty6lpsojw
sPIPXJ1ByLd6yVImC75fPnoEOnHuvx5U2wLj+a4GM0z2JilgJtfvk3QQNECr9NdZ
UNUJngrRDvfMVaUZbTFpuqefBF0rru+HU8A08thidO4awum5K+0ogzStKPpi15Pz
uZbqmxySSYZyktn+iFK2fPM3zDjXr6cT/0qmhonSjqkDEYKxeljgzbiA7lHO5dsG
s6/fHidC/JxFjygaoaZMqvtgVOGgvrQRRxPMO87+bi1bwBZo13jg1lE4d5kphmDY
HaWqVh0RaSQM33DVGr9J4arotaCfagvBPUqMLv2/dPIRO7IMSemo2CoHXzG6Xu3W
NQIDAQAB
-----END PUBLIC KEY-----
`
)

func TestMain(m *testing.M) {
	var err error
	private, err = NewPrivateWithBytes([]byte(privateKey))
	if err != nil {
		panic(fmt.Sprintf("initial private error, err: %v", err))
	}

	public, err = NewPublicWithBytes([]byte(publicKey))
	if err != nil {
		panic(fmt.Sprintf("initial public error, err: %v", err))
	}

	m.Run()
}

func TestSign(t *testing.T) {
	var s = "hello tensor security"
	signature, err := private.Sign([]byte(s))
	assert.Nil(t, err)

	err = public.VerifySign([]byte(s), signature)
	assert.Nil(t, err)
}

func TestEncrypt(t *testing.T) {
	var s = "hello tensor security"
	r, err := public.Encrypt([]byte(s))
	assert.Nil(t, err)
	b, err := private.Decrypt(r)
	assert.Nil(t, err)
	assert.Equal(t, s, string(b))
}

func TestSha256(t *testing.T) {
	s, err := Sha256String([]byte("hello tensor security"))
	assert.Nil(t, err)
	assert.Equal(t, s, "37aaba9c553636a8523f74a3203fc55a612ee33c7adecf5c826174c3c73a14c9")
}
