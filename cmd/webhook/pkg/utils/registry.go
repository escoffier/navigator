package utils

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	registry2 "github.com/heroku/docker-registry-client/registry"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func NewDockerRegistryClient(url, userName, password string, skipTLSVerify bool) (*registry2.Registry, error) {
	hub, err := registry2.New(url, userName, password)
	if err != nil && skipTLSVerify {
		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			logging.GetLogger().Warn().Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry2.NewInsecure(url, userName, password)
		}
	}
	if err != nil {
		logging.GetLogger().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	return hub, nil
}

func GetImageDigest(userName, password string, skipTLSVerify bool, imageName string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return "", err
	}
	url := ref.Context().RegistryStr()
	if !strings.Contains(url, "http") {
		url = "https://" + url
	}
	cli, err := NewDockerRegistryClient(url, userName, password, skipTLSVerify)
	if err != nil {
		return "", err
	}

	tag := ref.Identifier()
	repoName := ref.Context().RepositoryStr()

	data, err := pullImageManifestV2(cli, repoName, tag)
	if err != nil {
		data, err = pullImageManifestV1(cli, repoName, tag)
		if err != nil {
			return "", err
		}
	}

	dig, _, err := registry.SHA256(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return dig.String(), nil
}

func GetImageUrl(image string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", err
	}
	url := ref.Context().RegistryStr()
	return url, nil
}

func pullImageManifestV2(registryClient *registry2.Registry, repo, digest string) ([]byte, error) {
	manifest, err := registryClient.ManifestV2(repo, digest)
	if err != nil {
		return nil, err
	}
	manifestJSON, err := manifest.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return manifestJSON, nil
}

func pullImageManifestV1(registryClient *registry2.Registry, repo, digest string) ([]byte, error) {
	manifest, err := registryClient.Manifest(repo, digest)
	if err != nil {
		return nil, err
	}
	manifestJSON, err := manifest.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return manifestJSON, nil
}
