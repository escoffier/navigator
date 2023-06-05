package registry

import (
	"crypto/x509"
	"errors"
	registry2 "github.com/heroku/docker-registry-client/registry"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func ClientLogFormatter(format string, args ...interface{}) {
	logging.GetLogger().Trace().Msgf(format, args...)
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
			logging.GetLogger().Warn().Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry2.NewInsecure(url, userName, password)
		}
	}
	if err != nil {
		logging.GetLogger().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	hub.Logf = ClientLogFormatter
	return hub, nil
}
