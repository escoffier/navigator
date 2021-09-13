package alauda

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/docker"

	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	Version = "alauda-registry-v2"
)

var (
	ErrNoMorePages = errors.New("no more pages")
)

var singletonRegistry *dockerRegistryV2

type dockerRegistryV2 struct {
	docker.RegistryV2
}

type repositoriesResponse struct {
	Repositories []string `json:"repositories"`
}

func (r *dockerRegistryV2) url(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", r.RegistryClient.URL, pathSuffix)
	return url
}

func (r *dockerRegistryV2) getPaginatedJSON(url string, response interface{}) (string, error) {
	resp, err := r.RegistryClient.Client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(response)
	if err != nil {
		return "", err
	}
	return getNextLink(resp)
}

func (r *dockerRegistryV2) completeNextUrl(nextUrl string) (string, error) {
	if strings.HasPrefix(nextUrl, r.RegistryClient.URL) {
		return nextUrl, nil
	}
	return r.RegistryClient.URL + nextUrl, nil
}

func (r *dockerRegistryV2) Repositories() ([]string, error) {
	url := r.url("/v2/_catalog")
	repos := make([]string, 0, 10)
	var response repositoriesResponse
	for {
		nextUrl, err := r.getPaginatedJSON(url, &response)
		logging.GetLogger().Debug().Msgf("alauda registry repositories next url %v,err %v", nextUrl, err)
		switch err {
		case ErrNoMorePages:
			repos = append(repos, response.Repositories...)
			return repos, nil
		case nil:
			url, err = r.completeNextUrl(nextUrl)
			logging.GetLogger().Debug().Msgf("alauda registry repositories complete url %v,err:%v", url, err)
			repos = append(repos, response.Repositories...)
			continue
		default:
			logging.GetLogger().Error().Msgf("alauda registry repositories unexpected err:%v", err)
			return nil, err
		}
	}
}

func (r *dockerRegistryV2) ListRepos() ([]string, error) {
	repos, err := r.Repositories()
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (r *dockerRegistryV2) ListRepoTags(repo string) ([]string, error) {
	return r.RegistryV2.ListRepoTags(repo)
}

func (r *dockerRegistryV2) ListImages(extender registry.ImageListExtender) ([]registry.Image, error) {
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
				manifestV2    *schema2.DeserializedManifest
				manifestV2Str []byte
				manifestV1    *schema1.SignedManifest
				manifestV1Str []byte
				configBlob    string
				configDigest  digest.Digest
				imageDigest   string
			)
			manifestV2, err := r.PullImageManifestV2(repo, tag)
			if err == nil {
				// pull config json
				imageDigest, err = registry.ManifestV2Digest(manifestV2)
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest digest err, repo %s ,digest %s", repo, tag)
					continue
				}
				manifestV2Str, err = manifestV2.MarshalJSON()
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest string err, repo %s ,digest %s", repo, tag)
					continue
				}

				// pull config json
				configDigest = manifestV2.Config.Digest
				configBlob, err = r.PullConfigBlob(repo, configDigest)
				if err != nil {
					logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", repo, tag)
					continue
				}
			} else {
				// pull manifest v2 err,try v1
				logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, repo, tag)
				manifestV1, err = r.PullImageManifestV1(repo, tag)
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, repo, tag)
					continue
				}
				manifestV1Str, err = manifestV1.MarshalJSON()
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest v1 str err %v, repo %s ,digest %s", err, repo, tag)
					continue
				}

				// according: github.com/google/go-containerregistry@v0.1.2/pkg/v1/remote/descriptor.go
				// use http-header "Docker-Content-digest" as manifest-v1 image digest
				tmp, err := r.RegistryClient.ManifestDigest(repo, tag)
				if err != nil {
					logging.GetLogger().Error().Msgf("get manifest v1 image list err %v, repo %s ,digest %s", err, repo, tag)
					continue
				}
				imageDigest = tmp.String()
			}

			i := r.MakeImage(repo, tag)
			i.ImageDigest = imageDigest
			i.ManifestV2 = string(manifestV2Str)
			i.ManifestV1 = string(manifestV1Str)
			i.ConfigJson = configBlob
			images = append(images, *i)

			err = extender(r.Config, *i)
			if err != nil {
				logging.GetLogger().Error().Msgf("extender function for image %s, err %v", i.ImageDigest, err)
			}
		}
	}

	return images, nil
}

func (r *dockerRegistryV2) GetImage(projectName, repoName, tag string) (*registry.Image, error) {
	return r.RegistryV2.GetImage(projectName, repoName, tag)
}

func (r *dockerRegistryV2) CheckProject(projectName string) error {
	return errors.New("not implement")
}
func (r *dockerRegistryV2) GetRegistryConfig() registry.RegisterConfig {
	return r.Config
}

func (r *dockerRegistryV2) CreateProject(projectName string, public bool) error {
	return errors.New("not implement")
}

// func init() {
// 	err := registry.Register(Version, OpenRegistry)
// 	if err != nil {
// 		logging.GetLogger().Error().Msgf("init alauda docker registry driver error:%v", err)
// 	}
// }

func OpenRegistry(config registry.RegisterConfig) (registry.Registry, error) {
	if singletonRegistry != nil {
		return singletonRegistry, nil
	}
	var r dockerRegistryV2

	r.Ctx = context.Background()

	// // parse config
	// bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	// if err != nil {
	// 	return nil, fmt.Errorf("alauda registryV2: could not load configuration: %v", err)
	// }
	// err = yaml.Unmarshal(bytes, &r.Config)
	// if err != nil {
	// 	return nil, fmt.Errorf("alauda registryV2: could not load configuration: %v", err)
	// }

	// create client to pull image manifest and config
	rc, err := NewRegistryClient(config)
	if err != nil {
		return nil, fmt.Errorf("alauda registryV2:new registry client err:%v", err)
	}
	r.RegistryClient = rc
	r.Config = config
	singletonRegistry = &r

	return singletonRegistry, nil
}

func NewRegistryClient(config registry.RegisterConfig) (*registry2.Registry, error) {
	hub, err := registry2.New(config.URL, config.Username, config.Password)
	if err != nil && config.SkipTLSVerify {
		// seems like error Golang's x509 package doesn't support error wrapping API yet:
		// https://github.com/golang/go/issues/30322
		// var hostnameErr *x509.HostnameError
		// if errors.As(err, &hostnameErr) { ... }
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
