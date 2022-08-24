package utils

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const DigestTineOut = time.Second * 4

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
		logging.GetLogger().Warn().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	return hub, nil
}

func GetImageDigest(userName, password string, skipTLSVerify bool, imageName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DigestTineOut)
	defer cancel()

	digest := make(chan string)
	err := make(chan error)
	go func() {
		digest1, err1 := getImageDigest(userName, password, skipTLSVerify, imageName)
		digest <- digest1
		err <- err1
	}()

	select {
	case d := <-digest:
		return d, nil
	case e := <-err:
		logging.GetLogger().Err(e).Msg("get image err")
		return "", e
	case <-ctx.Done():
		return "", fmt.Errorf("get image: %s digests time out", imageName)
	}
}

func getImageDigest(userName, password string, skipTLSVerify bool, imageName string) (string, error) {

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err1 := name.ParseReference(imageName, nameOpts...)
	if err1 != nil {
		//err <- err1
		//return digest, err
		return "", err1
	}
	url := ref.Context().RegistryStr()
	if !strings.Contains(url, "http") {
		url = "https://" + url
	}
	cli, err1 := NewDockerRegistryClient(url, userName, password, skipTLSVerify)
	if err1 != nil {
		return "", err1
	}

	tag := ref.Identifier()
	repoName := ref.Context().RepositoryStr()

	data, err1 := pullImageManifestV2(cli, repoName, tag)
	if err1 != nil {
		data, err1 = pullImageManifestV1(cli, repoName, tag)
		if err1 != nil {
			return "", err1
		}
	}

	dig, _, err1 := registry.SHA256(bytes.NewReader(data))
	if err1 != nil {
		return "", err1
	}
	d := dig.String()
	logging.GetLogger().Info().Msgf("digest of image %s is %s", imageName, d)
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
