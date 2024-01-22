package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type repositoriesResponse struct {
	Repositories []string `json:"repositories"`
}

var (
	ErrNoMorePages = errors.New("no more pages")
)

type RegistryV2 struct {
	Ctx            context.Context
	Config         RegisterConfig
	RegistryClient *registry2.Registry // client for pull manifest
	ImageDal       adaptStore.ScannerDalInterface
}

func (r *RegistryV2) ListRepos() ([]string, error) {
	repos, err := r.Repositories()
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (r *RegistryV2) getPaginatedJSON(url string, response interface{}) (string, error) {
	resp, err := r.RegistryClient.Client.Get(url)
	if err != nil {
		return "", err
	}
	defer util.CloseBodyWithLog(resp.Body)

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(response)
	if err != nil {
		return "", err
	}
	return getNextLink(resp)
}

var nextLinkRE = regexp.MustCompile(`^ *<?([^;>]+)>? *(?:;[^;]*)*; *rel="?next"?(?:;.*)?`)

func getNextLink(resp *http.Response) (string, error) {
	for _, link := range resp.Header[http.CanonicalHeaderKey("Link")] {
		parts := nextLinkRE.FindStringSubmatch(link)
		if parts != nil {
			return parts[1], nil
		}
	}
	return "", ErrNoMorePages
}

func (r *RegistryV2) completeNextURL(nextURL string) (string, error) {
	if strings.HasPrefix(nextURL, r.RegistryClient.URL) {
		return nextURL, nil
	}
	return r.RegistryClient.URL + nextURL, nil
}

func (r *RegistryV2) Repositories() ([]string, error) {
	url := r.url("/v2/_catalog")
	repos := make([]string, 0, 10)
	var response repositoriesResponse
	for {
		nextURL, err := r.getPaginatedJSON(url, &response)
		logging.GetLogger().Debug().Msgf("docker registry repositories next url %v,err %v", nextURL, err)
		switch err {
		case ErrNoMorePages:
			repos = append(repos, response.Repositories...)
			return repos, nil
		case nil:
			url, err = r.completeNextURL(nextURL)
			logging.GetLogger().Debug().Msgf("docker registry repositories complete url %v,err:%v", url, err)
			repos = append(repos, response.Repositories...)
			continue
		default:
			logging.GetLogger().Err(err).Msg("docker registry repositories unexpected err")
			return nil, err
		}
	}
}

func (r *RegistryV2) url(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", r.RegistryClient.URL, pathSuffix)
	return url
}

func (r *RegistryV2) ListRepoTags(repo string) ([]string, error) {
	tags, err := r.RegistryClient.Tags(repo)
	if err != nil {
		return nil, err
	}
	return tags, nil
}

func (r *RegistryV2) SupportIncrementalSync(ctx context.Context) bool {
	return false
}

func (r *RegistryV2) ListImages(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesRequest) (*warehouse.ListImagesRes, error) {
	if extender.CreateImageExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender")
	}
	cnt := 0
	res := new(warehouse.ListImagesRes)
	// get all repos
	repos, err := r.ListRepos()
	if err != nil {
		return nil, err
	}

	for _, repo := range repos {
		tags, err := r.ListRepoTags(repo)
		if err != nil {
			res.HasErr = true
			logging.GetLogger().Err(err).Msgf("get repo %s tags err", repo)
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
				imageDigest, err = ManifestV2Digest(manifestV2)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("get manifest digest err, repo %s ,digest %s", repo, tag)
					continue
				}
				manifestV2Str, err = manifestV2.MarshalJSON()
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("get manifest string err, repo %s ,tag %s", repo, tag)
					continue
				}

				// pull config json
				configDigest = manifestV2.Config.Digest
				configBlob, err = r.PullConfigBlob(repo, configDigest)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("get config blob err, repo %s ,tag %s", repo, tag)
					continue
				}
			} else {
				// pull manifest v2 err,try v1
				logging.GetLogger().Info().Msgf("get manifest v2 err,try v1, repo %s ,tag %s", repo, tag)
				manifestV1, err = r.PullImageManifestV1(repo, tag)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("get manifest (both v1,v2) err, repo %s ,tag %s", repo, tag)
					continue
				}
				manifestV1Str, err = manifestV1.MarshalJSON()
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("get manifest v1 str err, repo %s ,tag %s", repo, tag)
					continue
				}

				// according: github.com/google/go-containerregistry@v0.1.2/pkg/v1/remote/descriptor.go
				// use http-header "Docker-Content-digest" as manifest-v1 image digest
				tmp, err := r.RegistryClient.ManifestDigest(repo, tag)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("get manifest v1 image list err, repo %s ,digest %s", repo, tag)
					continue
				}
				imageDigest = tmp.String()
			}

			image := warehouse.Image{
				RegistryUrl: r.Config.URL,
				RegistryID:  r.Config.RegistryID,
				ImageDigest: imageDigest,
				Repository:  repo,
				Tag:         tag,
				ManifestV2:  string(manifestV2Str),
				ManifestV1:  string(manifestV1Str),
				ConfigJSON:  configBlob,
			}

			cnt++

			im, err := extender.CreateImageExtender(ctx, image)
			if err != nil {
				res.HasErr = true
				if err != preConsts.ErrNotNodeImage {
					logging.GetLogger().Err(err).Msg("HarborV2 Insert imagelist error")
				}
				continue
			}
			if req.NeedToReturnAll {
				res.All = append(res.All, im.All...)
			}
			if req.NeedToReturnAdded {
				res.Added = append(res.Added, im.Added...)
			}
		}
	}

	logging.GetLogger().Info().Msgf("docker-registry List images  count:%d", cnt)
	return res, nil
}

func (r *RegistryV2) GetImage(projectName, repoName, tag string) (*warehouse.Image, error) {

	if projectName != "" {
		repoName = projectName + "/" + repoName
	}

	tags, err := r.ListRepoTags(repoName)
	if err != nil {
		return nil, err
	}
	hasTag := false
	// 查看是否有这个tag
	for _, tg := range tags {
		if tg == tag {
			hasTag = true
			break
		}
	}

	if !hasTag {
		return nil, errors.New("not fond the image")
	}

	var (
		manifestV2    *schema2.DeserializedManifest
		manifestV2Str []byte
		manifestV1    *schema1.SignedManifest
		manifestV1Str []byte
		configBlob    string
		configDigest  digest.Digest
		imageDigest   string
	)
	manifestV2, err = r.PullImageManifestV2(repoName, tag)

	if err == nil {
		// pull config json
		imageDigest, err = ManifestV2Digest(manifestV2)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest digest err, repo %s ,tag %s", repoName, tag)
			return nil, err
		}
		manifestV2Str, err = manifestV2.MarshalJSON()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest string err, repo %s ,tag %s", repoName, tag)
			return nil, err
		}

		// pull config json
		configDigest = manifestV2.Config.Digest
		configBlob, err = r.PullConfigBlob(repoName, configDigest)

		if err != nil {
			logging.GetLogger().Err(err).Msgf("get config blob err, repo %s ,tag %s", repoName, tag)
			return nil, err

		}
	} else {
		// pull manifest v2 err,try v1
		logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,tag %s", err, repoName, tag)
		manifestV1, err = r.PullImageManifestV1(repoName, tag)

		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest (both v1,v2) err, repo %s ,tag %s", repoName, tag)
			return nil, err
		}
		manifestV1Str, err = manifestV1.MarshalJSON()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest v1 str err, repo %s ,tag %s", repoName, tag)
			return nil, err
		}

		// according: github.com/google/go-containerregistry@v0.1.2/pkg/v1/remote/descriptor.go
		// use http-header "Docker-Content-digest" as manifest-v1 image digest
		tmp, err := r.RegistryClient.ManifestDigest(repoName, tag)

		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest v1 image list err, repo %s ,tag %s", repoName, tag)
			return nil, err
		}
		imageDigest = tmp.String()
	}

	image := warehouse.Image{
		RegistryUrl: r.Config.URL,
		RegistryID:  r.Config.RegistryID,
		ImageDigest: imageDigest,
		Repository:  repoName,
		Tag:         tag,
		ManifestV2:  string(manifestV2Str),
		ManifestV1:  string(manifestV1Str),
		ConfigJSON:  configBlob,
	}

	return &image, nil
}

func (r *RegistryV2) DeleteImages(projectName, repoName, dig string) error {
	if projectName != "" {
		repoName = projectName + "/" + repoName
	}
	err := r.RegistryClient.DeleteManifest(repoName, digest.Digest(dig))
	return err
}

func (r *RegistryV2) Ping() error {
	if err := r.RegistryClient.Ping(); err != nil {
		return warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (r *RegistryV2) CheckProject(projectName string) error {
	return errors.New("not implement")
}

func (r *RegistryV2) CreateProject(projectName string, public bool) error {
	return errors.New("not implement")
}

func ManifestV2Digest(m *schema2.DeserializedManifest) (string, error) {
	// caculate image digest
	data, err := m.MarshalJSON()
	if err != nil {
		return "", err
	}
	dig, _, err := warehouse.SHA256(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return dig.String(), err
}

func (r *RegistryV2) PullImageManifestV2(repo, digest string) (*schema2.DeserializedManifest, error) {
	manifest, err := r.RegistryClient.ManifestV2(repo, digest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

func (r *RegistryV2) PullImageManifestV1(repo, digest string) (*schema1.SignedManifest, error) {
	manifest, err := r.RegistryClient.Manifest(repo, digest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

func (r *RegistryV2) ListImagesWithAuditLog(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesAuditLog) (*warehouse.ListImagesRes, error) {
	return nil, nil
}
func (r *RegistryV2) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := r.RegistryClient.DownloadBlob(repo, configDigest)
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
	err := warehouse.Register(imagesec.DockerRegistryV2Version, openRegistry)
	if err != nil {
		logging.GetLogger().Error().Msgf("init harborV2 error:%v", err)
	} else {
		logging.GetLogger().Info().Msg("docker driver register success")
	}
}

func openRegistry(config warehouse.RegistrableComponentConfig) (warehouse.Registry, error) {
	var r RegistryV2

	r.Ctx = context.Background()

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.GetLogger().Err(err).Msg("docker marshal config")
		return nil, err
	}
	conf := new(RegisterConfig)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.GetLogger().Err(err).Msg("docker Unmarshal config")
		return nil, err
	}

	// create client to pull image manifest and config
	r.Config = *conf
	rc, err := warehouse.NewDockerRegistryClient(r.Config.URL, r.Config.Username, r.Config.Password, r.Config.SkipTLSVerify)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("registryV2:new registry client err:%v", err)
		return nil, warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	r.RegistryClient = rc

	return &r, nil
}
