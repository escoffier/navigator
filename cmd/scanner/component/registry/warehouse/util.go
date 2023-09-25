package warehouse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	registry2 "github.com/heroku/docker-registry-client/registry"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func ClientLogFormatter(format string, args ...interface{}) {
	logging.Get().Trace().Msgf(format, args...)
}

func NewDockerRegistryClient(url, userName, password string, skipTLSVerify bool) (*registry2.Registry, error) {
	hub, err := registry2.New(url, userName, password)
	if err != nil && skipTLSVerify {
		// Check for any type of error defined in x509 package.
		ok1 := errors.As(err, &x509.SystemRootsError{})
		ok2 := errors.As(err, &x509.CertificateInvalidError{})
		ok3 := errors.As(err, &x509.UnknownAuthorityError{})
		ok4 := errors.As(err, &x509.HostnameError{})
		if ok1 || ok2 || ok3 || ok4 {
			logging.Get().Warn().Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry2.NewInsecure(url, userName, password)
		}
	}
	if err != nil {
		logging.Get().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	hub.Logf = ClientLogFormatter
	return hub, nil
}

type Hash struct {
	// Algorithm holds the algorithm used to compute the hash.
	Algorithm string

	// Hex holds the hex portion of the content hash.
	Hex string
}

func (h Hash) String() string {
	return fmt.Sprintf("%s:%s", h.Algorithm, h.Hex)
}

func SHA256(r io.Reader) (Hash, int64, error) {
	hasher := sha256.New()
	n, err := io.Copy(hasher, r)
	if err != nil {
		return Hash{}, 0, err
	}
	return Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}, n, nil
}

func GetRegistryDriver(reg imagesecModel.Registry) (Registry, error) {

	drive, err := Open(RegToRegistryConf(reg))
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("name", reg.Name).Msg("sync image open registry")
		return nil, err
	}
	if err := drive.Ping(); err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("regName", reg.Name).Msg("connect registry")
		return nil, err
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("reg", reg).Msg("getRegistryDriver")

	return drive, nil
}

func RegToRegistryConf(reg imagesecModel.Registry) RegistrableComponentConfig {
	opt := make(map[string]interface{})
	opt["type"] = reg.RegType
	opt["registry_id"] = reg.ID
	opt["url"] = reg.Url
	opt["username"] = reg.Username
	opt["password"] = reg.PasswordString
	opt["skip_tls_verify"] = true
	opt["insecure"] = true
	opt["access_key"] = reg.AccessKey
	opt["access_secret"] = reg.AccessSecret
	opt["instance_id"] = reg.InstanceID
	opt["region_id"] = reg.RegionID

	if reg.RegType == imagesecModel.HaiWeiSwrVersion {
		opt["access_key"] = reg.Username
		opt["secret_key"] = reg.PasswordString
		opt["username"] = ""
		opt["password"] = ""
	}

	conf := RegistrableComponentConfig{
		Type:    reg.RegType,
		Options: opt,
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("reg", opt).Msg("RegToRegistryConf")
	return conf
}
