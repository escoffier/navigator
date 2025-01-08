package nexus

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

	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type repositoriesResponse struct {
	Repositories []string `json:"repositories"`
}

var (
	ErrNoMorePages = errors.New("no more pages")
)

type Nexus struct {
	Config         RegisterConfig
	RegistryClient *registry2.Registry // client for pull manifest
	Log            *scannerUtils.LogEvent
}

func (r *Nexus) ListRepos() ([]string, error) {
	repos, err := r.Repositories()
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (r *Nexus) getPaginatedJSON(url string, response interface{}) (string, error) {
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

func (r *Nexus) completeNextURL(nextURL string) (string, error) {
	if strings.HasPrefix(nextURL, r.RegistryClient.URL) {
		return nextURL, nil
	}
	return r.RegistryClient.URL + nextURL, nil
}

func (r *Nexus) Repositories() ([]string, error) {
	url := r.url("/v2/_catalog")
	repos := make([]string, 0, 10)
	var response repositoriesResponse
	for {
		nextURL, err := r.getPaginatedJSON(url, &response)
		r.Log.Info().Msgf("docker registry repositories next url %v,err %v", nextURL, err)
		switch {
		case errors.Is(err, ErrNoMorePages):
			repos = append(repos, response.Repositories...)
			return repos, nil
		case err == nil:
			url, err = r.completeNextURL(nextURL)
			r.Log.Info().Msgf("docker registry repositories complete url %v,err:%v", url, err)
			repos = append(repos, response.Repositories...)
			continue
		default:
			r.Log.Error().Err(err).Msg("docker registry repositories unexpected err")
			return nil, err
		}
	}
}

func (r *Nexus) url(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", r.RegistryClient.URL, pathSuffix)
	return url
}

func (r *Nexus) ListRepoTags(repo string) ([]string, error) {
	tags, err := r.RegistryClient.Tags(repo)
	if err != nil {
		return nil, err
	}
	return tags, nil
}

func (r *Nexus) SupportIncrementalSync(ctx context.Context) bool {
	return false
}

func (r *Nexus) ListImages(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesRequest) (*warehouse.ListImagesRes, error) {
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
			r.Log.Err(err).Msgf("get repo %s tags err", repo)
			continue
		}
		for _, tag := range tags {

			manifestV2, err := r.PullImageManifestV2(repo, tag)
			if err != nil {
				r.Log.Error().Err(err).Str("Repo", repo).Str("Tag", tag).Msg("PullImageManifestV2")
				continue
			}

			// pull config json
			imageDigest, err := ManifestV2Digest(manifestV2)
			if err != nil {
				res.HasErr = true
				r.Log.Err(err).Msgf("get manifest digest err, repo %s ,digest %s", repo, tag)
				continue
			}
			manifestV2Str, err := manifestV2.MarshalJSON()
			if err != nil {
				res.HasErr = true
				r.Log.Err(err).Msgf("get manifest string err, repo %s ,tag %s", repo, tag)
				continue
			}

			// pull config json
			configDigest := manifestV2.Config.Digest
			configBlob, err := r.PullConfigBlob(repo, configDigest)
			if err != nil {
				r.Log.Err(err).Msgf("get config blob err, repo %s ,tag %s", repo, tag)
				continue
			}

			image := warehouse.Image{
				RegistryUrl: r.Config.URL,
				RegistryID:  r.Config.RegistryID,
				ImageDigest: imageDigest,
				Repository:  repo,
				Tag:         tag,
				ManifestV2:  string(manifestV2Str),
				ConfigJSON:  configBlob,
			}

			im, err := extender.CreateImageExtender(ctx, image)
			if err != nil {
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

	r.Log.Info().Msgf("nexus List images  count:%d", cnt)
	return res, nil
}

func (r *Nexus) Ping() error {
	if err := r.RegistryClient.Ping(); err != nil {
		return warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
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

func (r *Nexus) PullImageManifestV2(repo, digest string) (*schema2.DeserializedManifest, error) {
	manifest, err := r.RegistryClient.ManifestV2(repo, digest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

func (r *Nexus) ListImagesWithAuditLog(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesAuditLog) (*warehouse.ListImagesRes, error) {
	return nil, fmt.Errorf("not implement")
}
func (r *Nexus) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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
	err := warehouse.Register(imagesec.Nexus, openRegistry)
	if err != nil {
		logging.Get().Error().Msgf("init nexus error:%v", err)
	} else {
		logging.Get().Info().Msg("nexus driver register success")
	}
}

func openRegistry(config warehouse.RegistrableComponentConfig) (warehouse.Registry, error) {
	r := &Nexus{}
	r.Log = scannerUtils.NewLogEvent(
		scannerUtils.WithSubModule("nexus"),
		scannerUtils.WithModule(consts.ModuleImageRegistry))

	byt, err := json.Marshal(config.Options)
	if err != nil {
		r.Log.Err(err).Msg("docker marshal config")
		return nil, err
	}
	conf := new(RegisterConfig)

	if err := json.Unmarshal(byt, conf); err != nil {
		r.Log.Err(err).Msg("docker Unmarshal config")
		return nil, err
	}

	// create client to pull image manifest and config
	r.Config = *conf
	rc, err := warehouse.NewDockerRegistryClient(r.Config.URL, r.Config.Username, r.Config.Password, r.Config.SkipTLSVerify)
	if err != nil {
		r.Log.Err(err).Msgf("registryV2:new registry client err:%v", err)
		return nil, warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	r.RegistryClient = rc

	return r, nil
}
