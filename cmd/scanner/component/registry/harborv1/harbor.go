package harborv1

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
	"strconv"
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
	HarborVersion        = "harbor-v1.0"
	ApiVersion           = "api"
	RetryCount      uint = 3
	DefaultPageSize int  = 100
)

type harborV1 struct {
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

func (h *harborV1) projectsToIds(projects []Project) []string {
	res := make([]string, 0)
	for _, v := range projects {
		res = append(res, fmt.Sprintf("%s", v.ProjectID))
	}
	return res
}

func (h *harborV1) reqHarbor(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("get harbor projects err.%v", err.Error()))
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
		return nil, errors.New(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}

	return resp.Body, nil
}

func (h *harborV1) ListProjects() ([]Project, error) {
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

	logging.GetLogger().Info().Msgf("projects %+v", projects)
	return projects, nil
}

func (h *harborV1) ListProjectsWithPage(page, pageSize int) ([]Project, error) {
	url := fmt.Sprintf("%s/%s/projects?page=%d&page_size=%d", h.config.URL, ApiVersion, page, pageSize)
	logging.GetLogger().Info().Msgf("req harbor projects url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor projects err %v", err)
		return nil, err
	}

	var projects []Project
	err = json.NewDecoder(data).Decode(&projects)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("decode harbor projects body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("projects %+v",projects)
	return projects, nil
}

func (h *harborV1) ListProjectRepos(project int) ([]Repository, error) {
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

func (h *harborV1) ListProjectReposWithPage(project, page, pageSize int) ([]Repository, error) {
	url := fmt.Sprintf("%s/%s/repositories?project_id=%d&page=%d&page_size=%d", h.config.URL, ApiVersion, project, page, pageSize)
	logging.GetLogger().Info().Msgf("req harbor repo url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor repos err %v", err)
		return nil, err
	}

	var repos []Repository
	err = json.NewDecoder(data).Decode(&repos)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("decode harbor repos body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("repos %+v",repos)
	return repos, nil
}

func (h *harborV1) ListRepoTags(repo string) ([]Tag, error) {
	url := fmt.Sprintf("%s/%s/repositories/%s/tags?detail=true", h.config.URL, ApiVersion, repo)
	logging.GetLogger().Info().Msgf("req harbor repo artifacts url %s", url)

	data, err := h.reqHarbor(url)
	defer util.CloseBodyWithLog(data)
	if err != nil {
		logging.GetLogger().Error().Msgf("req harbor repo artifacts err %v", err)
		return nil, err
	}

	var tags []Tag
	err = json.NewDecoder(data).Decode(&tags)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("decode harbor artifacts body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("artifacts %v",artifacts)
	return tags, nil
}

func (h *harborV1) ListImages(extender registry.ImageListExtender) ([]registry.Image, error) {
	images := make([]registry.Image, 0)

	// get all projects
	projects, err := h.ListProjects()
	if err != nil {
		return nil, err
	}

	// get all repos
	for _, v := range projects {
		repos, err := h.ListProjectRepos(v.ProjectID)
		if err != nil {
			// just log and try next project
			logging.GetLogger().Error().Msgf("project %s get repo err,try next project.%v", v.Name, err)
			continue
		}

		// get all artifacts in repo
		for _, r := range repos {
			// repo name like 'library/xxx'
			tags, err := h.ListRepoTags(r.Name)
			if err != nil {
				logging.GetLogger().Error().Msgf("repo %s get artifacts err,try next repo.%v", r.Name, err)
				continue
			}

			for _, t := range tags {
				// pull manifest v2
				var (
					manifestV2   string
					manifestV1   string
					configBlob   string
					configDigest digest.Digest
				)

				manifestV2, configDigest, err := h.pullImageManifestV2(r.Name, t.Digest)
				if err == nil {
					// pull config json
					configBlob, err = h.pullConfigBlob(r.Name, configDigest)
					if err != nil {
						logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", r.Name, t.Digest)
						continue
					}
				} else {
					// pull manifest v2 err,try v1
					logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, r.Name, t.Digest)
					manifestV1, err = h.pullImageManifestV1(r.Name, t.Digest)
					if err != nil {
						logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, r.Name, t.Digest)
						continue
					}
				}

				i := h.makeImage(&r, &t)
				i.Created = t.Created
				i.ManifestV2 = string(manifestV2)
				i.ManifestV1 = string(manifestV1)
				i.ConfigJson = configBlob
				images = append(images, *i)

				extender(*i)

			} // end of for artifacts
		} // end of for repos
	}

	return images, nil
}

func (h *harborV1) GetImage(projectName, repoName, tag string) (*registry.Image, error) {
	// fullRopoName name like 'library/xxx'
	fullRopoName := projectName + "/" + repoName

	tags, err := h.ListRepoTags(fullRopoName)
	if err != nil {
		logging.GetLogger().Error().Msgf("repo %s get artifacts err,try next repo.%v", fullRopoName, err)
	}
	var artifact Tag
	for _, t := range tags {
		if t.Name == tag {
			artifact = t
			break
		}
	}
	if artifact.Name == "" {
		return nil, errors.New("not find the image")
	}

	// pull manifest v2
	var (
		manifestV2   string
		manifestV1   string
		configBlob   string
		configDigest digest.Digest
	)

	manifestV2, configDigest, err = h.pullImageManifestV2(fullRopoName, artifact.Digest)
	if err == nil {
		configBlob, err = h.pullConfigBlob(fullRopoName, configDigest)
		if err != nil {
			logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", fullRopoName, artifact.Digest)
		}
	} else {
		logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, fullRopoName, artifact.Digest)
		manifestV1, err = h.pullImageManifestV1(fullRopoName, artifact.Digest)
		if err != nil {
			logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, fullRopoName, artifact.Digest)
		}
	}
	img := &registry.Image{
		ImageDigest:  artifact.Digest,
		Repository:   fullRopoName,
		Tag:          tag,
		Size:         artifact.Size,
		Created:      artifact.Created,
		LastPushTime: artifact.PushTime,
		LastPullTime: artifact.PullTime,
		ManifestV2:   manifestV2,
		ManifestV1:   manifestV1,
		ConfigJson:   configBlob,
	}
	return img, nil
}

func (h *harborV1) DeleteImages(projectName, repoName, digest string) error {
	panic("not implement")
}

// CreateProject 创建project
func (h *harborV1) CreateProject(projectName string, public bool) error {
	url := fmt.Sprintf("%s/%s/projects", h.config.URL, ApiVersion)
	type MetaData struct {
		Public string `json:"public"`
	}
	type ProjectReq struct {
		ProjectName string   `json:"project_name"`
		MetaData    MetaData `json:"metadata"`
	}

	reqBody := ProjectReq{
		ProjectName: projectName,
		MetaData:    MetaData{Public: strconv.FormatBool(public)},
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
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

// CheckProject 检查project是否存在
func (h *harborV1) CheckProject(projectName string) error {
	url := fmt.Sprintf("%s/%s/projects?project_name=%s", h.config.URL, ApiVersion, projectName)
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
		return errors.New(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

func (h *harborV1) makeImage(r *Repository, t *Tag) *registry.Image {

	i := &registry.Image{
		ImageDigest:  t.Digest,
		Repository:   r.Name,
		Tag:          t.Name,
		Size:         t.Size,
		LastPullTime: t.PullTime,
		LastPushTime: t.PushTime,
	}
	return i
}

func (h *harborV1) pullImageManifestV2(repo, digest string) (string, digest.Digest, error) {
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

func (h *harborV1) pullImageManifestV1(repo, digest string) (string, error) {
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
func (h *harborV1) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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
	registry.Register(HarborVersion, openRegistry)
}

func openRegistry(registrableComponentConfig registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h harborV1

	h.ctx = context.Background()

	// parse config
	bys, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("harbor-v2: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bys, &h.config)
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
	return hub, nil
}
