package docker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"

	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	Version = "registry-v2"
)

type RegistryV2 struct {
	ctx            context.Context
	config         Opts
	registryClient *registry2.Registry //client for pull manifest
}

type Opts struct {
	URL           string
	Username      string
	Password      string
	SkipTLSVerify bool
}

func (r *RegistryV2) ListRepos() ([]string, error) {
	repos, err := r.registryClient.Repositories()
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (r *RegistryV2) ListRepoTags(repo string) ([]string, error) {
	tags, err := r.registryClient.Tags(repo)
	if err != nil {
		return nil, err
	}
	return tags, nil
}

func (r *RegistryV2) ListImages(extender registry.ImageListExtender) ([]registry.Image, error) {
	images := make([]registry.Image, 0)

	// get all repos
	repos, err := r.ListRepos()
	if err != nil {
		return nil, err
	}

	for _, repo := range repos {
		tags, err := r.ListRepoTags(repo)
		if err != nil {
			logging.GetLogger().Error().Msgf("get repo %s tags err %v", repo, err)
			continue
		}
		for _, tag := range tags {
			var (
				manifestV2   string
				manifestV1   string
				configBlob   string
				configDigest digest.Digest
			)
			manifestV2, configDigest, err := r.pullImageManifestV2(repo, tag)
			if err == nil {
				//pull config json
				configBlob, err = r.pullConfigBlob(repo, configDigest)
				if err != nil {
					logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", repo, tag)
					continue
				}
			} else {
				// pull manifest v2 err,try v1
				logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, repo, tag)
				manifestV1, err = r.pullImageManifestV1(repo, tag)
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, repo, tag)
					continue
				}
			}

			i := r.makeImage(repo, tag)
			i.ImageDigest = configDigest.String()
			i.ManifestV2 = string(manifestV2)
			i.ManifestV1 = string(manifestV1)
			i.ConfigJson = configBlob
			images = append(images, *i)

			extender(*i)
		}

	}

	return images, nil
}

func (r *RegistryV2) makeImage(repo, tag string) *registry.Image {
	i := registry.Image{
		ImageDigest: "",
		Repository:  repo,
		Tag:         tag,
		//Size: 0,
		//LastPullTime: t.PullTime,
		//LastPushTime: t.PushTime,
	}
	return &i
}

func (r *RegistryV2) pullImageManifestV2(repo, digest string) (string, digest.Digest, error) {
	manifest, err := r.registryClient.ManifestV2(repo, digest)
	if err != nil {
		return "", "", err
	}
	manifestJson, err := manifest.MarshalJSON()
	if err != nil {
		return "", "", err
	}

	return string(manifestJson), manifest.Config.Digest, nil
}

func (r *RegistryV2) pullImageManifestV1(repo, digest string) (string, error) {
	manifest, err := r.registryClient.Manifest(repo, digest)
	if err != nil {
		return "", err
	}
	manifestJson, err := manifest.MarshalJSON()
	if err != nil {
		return "", err
	}

	return string(manifestJson), nil
}
func (r *RegistryV2) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := r.registryClient.DownloadBlob(repo, configDigest)
	if err != nil {
		return "", err
	}
	configBlob := new(strings.Builder)
	_, err = io.Copy(configBlob, reader)
	if err != nil {
		return "", err
	}

	return configBlob.String(), nil
}

func init() {
	registry.Register(Version, openRegistry)
}

func openRegistry(registrableComponentConfig registry.RegistrableComponentConfig) (registry.Registry, error) {
	var r RegistryV2

	r.ctx = context.Background()

	// parse config
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("registryV2: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &r.config)
	if err != nil {
		return nil, fmt.Errorf("registryV2: could not load configuration: %v", err)
	}

	// create client to pull image manifest and config
	rc, err := newRegistryClient(&r.config)
	if err != nil {
		return nil, fmt.Errorf("registryV2:new registry client err:%v", err)
	}
	r.registryClient = rc

	return &r, nil
}

func newRegistryClient(config *Opts) (*registry2.Registry, error) {
	hub, err := registry2.New(config.URL, config.Username, config.Password)
	if err != nil && config.SkipTLSVerify {
		// seems like error Golang's x509 package doesn't support error wrapping API yet:
		// https://github.com/golang/go/issues/30322
		//var hostnameErr *x509.HostnameError
		//if errors.As(err, &hostnameErr) { ... }
		// Therefore we must unwrap the error from HTTP package manually and try to cast

		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			logging.GetLogger().Warn().Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry2.NewInsecure(config.URL, config.Username, config.Password)
		}
	}
	if err != nil {
		logging.GetLogger().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	return hub, nil
}
