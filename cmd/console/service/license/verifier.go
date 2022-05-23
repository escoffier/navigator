package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	DeadlineStatusWillExpire  deadlineStatus = "willExpire"
	DeadlineStatusGracePeriod deadlineStatus = "gracePeriod"
	DeadlineStatusExpired     deadlineStatus = "expired"

	NodeLimitStatusExceedLimit nodeLimitStatus = "exceedLimit"

	signTpl = "eigenvalue=%s&expire_at=%d&license_type=%s&module=%s&node_limit=%d&serial_no=%s"
)

type deadlineStatus string
type nodeLimitStatus string

type Status struct {
	Valid          bool            `json:"valid"`
	DeadlineState  deadlineStatus  `json:"deadlineState"`
	NodeLimitState nodeLimitStatus `json:"nodeLimitState"`
}

func (l Status) IsValid() bool {
	return l.Valid
}

// StrictValid the license must be valid
// not allowed the grace period and the number of nodes exceeds the upper limit
func (l Status) StrictValid() bool {
	return l.Valid && l.NodeLimitState == "" &&
		(l.DeadlineState == "" || l.DeadlineState == DeadlineStatusWillExpire)
}

type licenseVerifierOption struct {
	publicKey    *rsa.PublicKey
	gracePeriod  time.Duration
	remindPeriod time.Duration
}

// licenseVerifier license decode and verify
type licenseVerifier struct {
	licenseVerifierOption
}

func newLicenseVerifier(option licenseVerifierOption) *licenseVerifier {
	return &licenseVerifier{
		licenseVerifierOption: option,
	}
}

type Info struct {
	SerialNo    string `json:"serial_no"`
	LicenseType string `json:"license_type"`
	ExpireAt    int64  `json:"expire_at"`
	NodeLimit   int64  `json:"node_limit"`
	Module      string `json:"module"`
	Eigenvalue  string `json:"eigenvalue"`
	Sign        string `json:"sign"`
}

func (l *licenseVerifier) validate(info *Info, allowGracePeriod bool) Status {
	status := Status{Valid: true}

	if info == nil {
		status.Valid = false
		status.DeadlineState = DeadlineStatusExpired
		return status
	}

	now := time.Now()
	if info.ExpireAt < now.Unix() {
		if allowGracePeriod && l.gracePeriod > 0 &&
			info.ExpireAt < now.Add(-l.gracePeriod).Unix() {
			status.DeadlineState = DeadlineStatusGracePeriod
			return status
		}

		status.Valid = false
		status.DeadlineState = DeadlineStatusExpired
		return status
	} else if l.remindPeriod > 0 && info.ExpireAt < now.Add(l.remindPeriod).Unix() {
		status.DeadlineState = DeadlineStatusWillExpire
		return status
	}

	// nodeLimit check
	if info.NodeLimit > 0 {
		nodeNum, err := GetUsedNodeNum()
		if err != nil {
			logging.Get().Error().Err(err).Msg("count nodes failed")
		} else if info.NodeLimit < nodeNum {
			status.NodeLimitState = NodeLimitStatusExceedLimit
		}
	}

	return status
}

func (l *licenseVerifier) decode(licenseCode string) (*Info, error) {
	encrypted, err := base64.StdEncoding.DecodeString(licenseCode)
	if err != nil {
		logging.Get().Err(err)
		return nil, err
	}

	rawJSON, err := util.AesDecryptCBC(encrypted, publicKey[31:47])
	if err != nil {
		logging.Get().Err(err)
		return nil, err
	}

	info := Info{}
	if err = json.Unmarshal(rawJSON, &info); err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf(signTpl, info.Eigenvalue, info.ExpireAt,
		info.LicenseType, info.Module, info.NodeLimit, info.SerialNo)))

	sign, err := base64.StdEncoding.DecodeString(info.Sign)
	if err != nil {
		return nil, err
	}

	err = rsa.VerifyPKCS1v15(l.publicKey, crypto.SHA256, hash.Sum(nil), sign)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// encrypt data via publicKey
func (l *licenseVerifier) encrypt(data []byte) (string, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, l.publicKey, data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
