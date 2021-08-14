package harborv2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/avast/retry-go"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gopkg.in/yaml.v2"
)

const (
	HarborVersion        = "harbor-v2.0"
	ApiVersion           = "api/v2.0"
	RetryCount      uint = 3
	DefaultPageSize int  = 100
)

type harborV2 struct {
	ctx            context.Context
	client         *http.Client // client for pull harbor repos and tags
	config         HarborOpts
	registryClient *registry2.Registry // client for pull manifest
}

type HarborOpts struct {
	URL           string
	Username      string
	Password      string
	SkipTLSVerify bool
}

func (h *harborV2) reqHarbor(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)
	var resp *http.Response

	err = util.RetryWithBackoff(h.ctx, func() error {
		var err error
		resp, err = h.client.Do(req.WithContext(h.ctx))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
			return fmt.Errorf("status code is %d", resp.StatusCode)
		}
		return nil
	}, retry.Attempts(RetryCount))

	// defer util.CloseBodyWithLog(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}

	return resp.Body, nil
}

func (h *harborV2) ListProjects() ([]Project, error) {
	var projects []Project
	page := 1
	for {
		p, err := h.ListProjectsWithPage(page, DefaultPageSize)
		if err != nil {
			break
		}
		projects = append(projects, p...)
		if len(p) < DefaultPageSize {
			// last page
			break
		}
		page++
	}

	//	logging.GetLogger().Info().Msgf("projects %+v", projects)
	return projects, nil
}

func (h *harborV2) ListProjectsWithPage(page, pageSize int) ([]Project, error) {
	url := fmt.Sprintf("%s/%s/projects?page=%d&page_size=%d", h.config.URL, ApiVersion, page, pageSize)
	// logging.GetLogger().Info().Msgf("req harbor projects url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor projects err %v", err)
		return nil, err
	}

	var projects []Project
	err = json.NewDecoder(data).Decode(&projects)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor projects body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("projects %+v",projects)
	return projects, nil
}

func (h *harborV2) ListProjectRepos(project string) ([]Repository, error) {
	var repos []Repository
	page := 1
	for {
		r, err := h.ListProjectReposWithPage(project, page, DefaultPageSize)
		if err != nil {
			break
		}
		repos = append(repos, r...)
		if len(r) < DefaultPageSize {
			// last page
			break
		}
		page++
	}

	logging.GetLogger().Info().Msgf("repos %+v", repos)
	return repos, nil
}

func (h *harborV2) ListProjectReposWithPage(project string, page, pageSize int) ([]Repository, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories?page=%d&page_size=%d", h.config.URL, ApiVersion, project, page, pageSize)
	//	logging.GetLogger().Info().Msgf("req harbor repo url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor repos err %v", err)
		return nil, err
	}

	var repos []Repository
	err = json.NewDecoder(data).Decode(&repos)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor repos body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("repos %+v",repos)
	return repos, nil
}

func (h *harborV2) ListRepoArtifacts(project, repo string) ([]Artifact, error) {
	var artifacts []Artifact
	page := 1
	repo = strings.Replace(repo, "/", "%252F", -1)
	for {
		a, err := h.ListRepoArtifactsWithPage(project, repo, page, DefaultPageSize)
		if err != nil {
			break
		}
		artifacts = append(artifacts, a...)
		if len(a) < DefaultPageSize {
			// last page
			break
		}
		page++
	}
	//	logging.GetLogger().Info().Msgf("artifacts %v", artifacts)
	return artifacts, nil
}

func (h *harborV2) ListRepoArtifactsWithPage(project, repo string, page, pageSize int) ([]Artifact, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d", h.config.URL, ApiVersion, project, repo, page, pageSize)
	//	logging.GetLogger().Info().Msgf("req harbor repo artifacts url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor repo artifacts err %v", err)
		return nil, err
	}

	var artifacts []Artifact
	err = json.NewDecoder(data).Decode(&artifacts)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor artifacts body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("artifacts %v",artifacts)
	return artifacts, nil
}

func (h *harborV2) ListImages(extender registry.ImageListExtender) ([]registry.Image, error) {
	images := make([]registry.Image, 0)

	// get all projects
	projects, err := h.ListProjects()
	if err != nil {
		return nil, err
	}

	// get all repos
	for _, v := range projects {
		repos, err := h.ListProjectRepos(v.Name)
		if err != nil {
			// just log and try next project
			logging.GetLogger().Error().Msgf("project %s get repo err,try next project.%v", v.Name, err)
			continue
		}

		// get all artifacts in repo
		for _, r := range repos {
			// repo name like 'library/xxx',we only need 'xxx'
			index := strings.Index(r.Name, "/")
			tmp := r.Name[index+1:]
			if index == -1 {
				logging.GetLogger().Error().Msgf("repo %s format err", r.Name)
				continue
			}
			repoName := tmp
			artifacts, err := h.ListRepoArtifacts(v.Name, repoName)
			if err != nil {
				logging.GetLogger().Error().Msgf("repo %s get artifacts err,try next repo.%v", r.Name, err)
				continue
			}

			for _, a := range artifacts {
				// pull manifest v2
				var (
					manifestV2   string
					manifestV1   string
					configBlob   string
					configDigest digest.Digest
				)

				manifestV2, configDigest, err := h.pullImageManifestV2(r.Name, a.Digest)
				if err == nil {
					// pull config json
					configBlob, err = h.pullConfigBlob(r.Name, configDigest)
					if err != nil {
						logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", r.Name, a.Digest)
						continue
					}
				} else {
					// pull manifest v2 err,try v1
					//	logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, r.Name, a.Digest)
					manifestV1, err = h.pullImageManifestV1(r.Name, a.Digest)
					if err != nil {
						logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, r.Name, a.Digest)
						continue
					}
				}

				for _, t := range a.Tags {
					i := h.makeImage(&r, &a, &t)
					i.ManifestV2 = string(manifestV2)
					i.ManifestV1 = string(manifestV1)
					i.ConfigJson = configBlob

					// do some extend stuff
					err := extender(*i)
					if err != nil {
						logging.GetLogger().Error().Msgf("HarborV2 Insert imagelist error %v", err)
						continue
					}
					images = append(images, *i)
				}
			} // end of for artifacts
		} // end of for repos
	}

	return images, nil
}

func (h *harborV2) GetImage(projectName, repoName, tag string) (*registry.Image, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s", h.config.URL, ApiVersion, projectName, repoName, tag)
	// logging.GetLogger().WithContext(h.ctx).Infof(fmt.Sprintf("getImage url:%s", url))
	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor repo artifacts err %v", err)
		return nil, err
	}

	var artifact Artifact
	err = json.NewDecoder(data).Decode(&artifact)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor artifact body err.%v", err.Error()))
	}
	// add mainfest
	var (
		manifestV2   string
		manifestV1   string
		configBlob   string
		configDigest digest.Digest
	)
	if len(artifact.Tags) == 0 || artifact.Tags[0].Name != tag {
		return nil, errors.New("not find the image")
	}

	fullRepoNeme := projectName + "/" + repoName
	manifestV2, configDigest, err = h.pullImageManifestV2(fullRepoNeme, artifact.Digest)
	if err == nil {
		configBlob, err = h.pullConfigBlob(fullRepoNeme, configDigest)
		if err != nil {
			logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", fullRepoNeme, artifact.Digest)
		}
	} else {
		manifestV1, err = h.pullImageManifestV1(fullRepoNeme, artifact.Digest)
		if err != nil {
			msg := fmt.Sprintf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, fullRepoNeme, artifact.Digest)
			logging.GetLogger().Error().Msgf(msg)
			return nil, errors.New(msg)
		}
	}
	img := &registry.Image{
		ImageDigest:  artifact.Digest,
		Repository:   fullRepoNeme,
		Tag:          tag,
		Size:         artifact.Size,
		Created:      artifact.ExtraAttrs.Created,
		LastPushTime: artifact.Tags[0].PushTime,
		LastPullTime: artifact.Tags[0].PullTime,
		ManifestV2:   manifestV2,
		ManifestV1:   manifestV1,
		ConfigJson:   configBlob,
	}
	return img, nil
}

func (h *harborV2) DeleteImages(projectName, repoName, digest string) error {
	panic("not implement")
}

// CreateProject 创建project
func (h *harborV2) CreateProject(projectName string, public bool) error {
	url := fmt.Sprintf("%s/%s/projects", h.config.URL, ApiVersion)
	type ProjectReq struct {
		ProjectName string `json:"project_name"`
		Public      bool   `json:"public"`
	}

	reqBody := ProjectReq{
		ProjectName: projectName,
		Public:      public,
	}
	bys, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bys))
	if err != nil {
		return err
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req.WithContext(h.ctx))
	if err != nil {
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

// 检查project是否存在
func (h *harborV2) CheckProject(projectName string) error {
	url := fmt.Sprintf("%s/%s/projects?project_name=%s", h.config.URL, ApiVersion, projectName)
	// logging.GetLogger().WithContext(h.ctx).Infof(fmt.Sprintf("getImage url:%s", url))
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)

	resp, err := h.client.Do(req.WithContext(h.ctx))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

func (h *harborV2) makeImage(r *Repository, a *Artifact, t *Tag) *registry.Image {
	i := &registry.Image{
		ImageDigest:  a.Digest,
		Repository:   r.Name,
		Tag:          t.Name,
		Size:         a.Size,
		Created:      a.ExtraAttrs.Created,
		LastPullTime: t.PullTime,
		LastPushTime: t.PushTime,
	}
	return i
}

func (h *harborV2) pullImageManifestV2(repo, digest string) (string, digest.Digest, error) {
	manifest, err := h.registryClient.ManifestV2(repo, digest)
	if err != nil {
		return "", "", err
	}
	manifestJson, err := manifest.MarshalJSON()
	if err != nil {
		return "", "", err
	}

	return string(manifestJson), manifest.Config.Digest, nil
}

func (h *harborV2) pullImageManifestV1(repo, digest string) (string, error) {
	manifest, err := h.registryClient.Manifest(repo, digest)
	if err != nil {
		return "", err
	}
	manifestJson, err := manifest.MarshalJSON()
	if err != nil {
		return "", err
	}

	return string(manifestJson), nil
}

func (h *harborV2) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := h.registryClient.DownloadBlob(repo, configDigest)
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
	err := registry.Register(HarborVersion, openRegistry)
	if err != nil {
		logging.GetLogger().Error().Msgf("init harborV2 error:%v", err)
	}
}

func openRegistry(registrableComponentConfig registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h harborV2

	h.ctx = context.Background()

	// parse config
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("harbor-v2: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &h.config)
	if err != nil {
		return nil, fmt.Errorf("harbor-v2: could not load configuration: %v", err)
	}

	// create client to pull harbor repos and tags
	httpClient := http.Client{}
	if h.config.SkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	h.client = &httpClient

	// create client to pull image manifest and config
	r, err := newRegistryClient(&h.config)
	if err != nil {
		return nil, fmt.Errorf("harbor-v2:new registry client err:%v", err)
	}
	h.registryClient = r

	return &h, nil
}

func newRegistryClient(config *HarborOpts) (*registry2.Registry, error) {
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
	hub.Logf = registry.RegistryClientLog
	return hub, nil
}
