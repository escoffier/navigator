package jfrog

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// Jfrog is a Jfrog to interact with Jfrog
type Jfrog struct {
	// RegistryClient is a RegistryClient to access jfrog
	RegistryClient *registry2.Registry
	Config         Config
	JfrogClient    *http.Client // client for jfrog
}

func (c *Jfrog) CheckProject(projectName string) error {
	panic("implement me")
}

func (c *Jfrog) CreateProject(projectName string, public bool) error {
	panic("implement me")
}

func (c *Jfrog) GetImage(projectName, fullRepoName, tag string) (*registry.Image, error) {
	panic("implement me")
}

func (c *Jfrog) DeleteImages(projectName, repoName, digest string) error {
	panic("implement me")
}

func (c *Jfrog) Ping() error {
	if err := c.RegistryClient.Ping(); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (c *Jfrog) SupportIncrementalSync(ctx context.Context) bool {
	return false
}

func (c *Jfrog) ListRepos(packageType string) ([]Repository, error) {
	url := fmt.Sprintf("%s/artifactory/api/repositories?packageType=%s", c.Config.URL, packageType) // 查全部 repo
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("get jfrog projects err.%v", err.Error())
	}
	req.SetBasicAuth(c.Config.Username, c.Config.Password)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()
	resp, err := c.JfrogClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("req Jfrog:%s", err.Error())
		return nil, err
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
		return nil, fmt.Errorf("jfrog status code is %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reps := make([]Repository, 0)
	if err := json.Unmarshal(body, &reps); err != nil {
		return nil, err
	}
	return reps, nil
}

func (c *Jfrog) ListImagesWithAuditLog(ctx context.Context, extender registry.Extender, req registry.ListImagesAuditLog) (*registry.ListImagesRes, error) {
	return nil, nil
}

func (c *Jfrog) ListRepoImags(repo string) ([]string, error) {
	url := fmt.Sprintf("%s/artifactory/api/docker/%s/v2/_catalog", c.Config.URL, repo) // 单个repo下的镜像名
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("get jfrog projects err.%v", err.Error())
	}
	req.SetBasicAuth(c.Config.Username, c.Config.Password)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	resp, err := c.JfrogClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
		return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reps := new(RepoImages)
	if err := json.Unmarshal(body, reps); err != nil {
		return nil, err
	}
	return reps.Repositories, nil
}

func (c *Jfrog) ListImagTags(repo, imaName string) ([]string, error) {
	url := fmt.Sprintf("%s/artifactory/api/docker/%s/v2/%s/tags/list", c.Config.URL, repo, imaName) // 镜像的taglist
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("get jfrog projects err.%v", err.Error())
	}
	req.SetBasicAuth(c.Config.Username, c.Config.Password)
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(c.Config.Username, c.Config.Password)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()
	resp, err := c.JfrogClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("reqHarbor:%s", err.Error())
		return nil, err
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
		return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reps := new(ImageTage)
	if err := json.Unmarshal(body, reps); err != nil {
		return nil, err
	}
	return reps.Tags, nil
}

func ManifestV2Digest(m *schema2.DeserializedManifest) (string, error) {
	// caculate image digest
	data, err := m.MarshalJSON()
	if err != nil {
		return "", err
	}
	dig, _, err := registry.SHA256(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return dig.String(), err
}

func (c *Jfrog) PullImageManifest(repo, imaName, tag string) (*schema2.DeserializedManifest, error) {
	return c.RegistryClient.ManifestV2(repo+"/"+imaName, tag)
}

func (c *Jfrog) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := c.RegistryClient.DownloadBlob(repo, configDigest)
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

func (c *Jfrog) ImageRetry(ctx context.Context, extender registry.Extender, req registry.ImageRetryRequest) (*registry.ListImagesRes, error) {
	return nil, nil
}

func (c *Jfrog) ListImages(ctx context.Context, extender registry.Extender, req registry.ListImagesRequest) (*registry.ListImagesRes, error) {
	if extender.CreateImageExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender")
	}
	res := new(registry.ListImagesRes)
	cnt := 0
	// get all repos
	repos, err := c.ListRepos("docker") // 暂时只查docker的repo
	if err != nil {
		res.HasErr = true
		logging.GetLogger().Err(err).Msg("jfrog listRepos")
		return nil, err
	}
	logging.GetLogger().Info().Msgf("jfrog ListRepos:%v", repos)

	for _, repo := range repos {
		imgNames, err := c.ListRepoImags(repo.Key)
		if err != nil {
			res.HasErr = true
			logging.GetLogger().Err(err).Msgf("jfrog ListRepoImags:%s", repo.Key)
			continue
		}
		for i := range imgNames {
			tags, err := c.ListImagTags(repo.Key, imgNames[i])
			if err != nil {
				res.HasErr = true
				logging.GetLogger().Err(err).Msgf("jfrog listImagTags:%s/%s", repo.Key, imgNames[i])
				continue
			}

			for j := range tags {
				// 拉manifest
				manifest, err := c.PullImageManifest(repo.Key, imgNames[i], tags[j])
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("jfrog PullImageManifest:%s/%s:%s", repo.Key, imgNames[i], tags[j])
					continue
				}

				manifestByte, err := manifest.MarshalJSON()
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("jfrog MarshalJSON:%s/%s:%s", repo.Key, imgNames[i], tags[j])
					continue
				}

				// 解析imageDigest
				imageDigest, err := ManifestV2Digest(manifest)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("jfrog ManifestV2Digest:%s/%s:%s", repo.Key, imgNames[i], tags[j])
					continue
				}
				// pull config json
				configDigest := manifest.Config.Digest
				configBlob, err := c.PullConfigBlob(repo.Key+"/"+imgNames[i], configDigest)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msgf("jfrog PullConfigBlob:%s/%s:%s", repo.Key, imgNames[i], tags[j])
					continue
				}
				img := registry.Image{
					ImageDigest: imageDigest,
					Repository:  repo.Key + "/" + imgNames[i],
					Tag:         tags[j],
					ManifestV2:  string(manifestByte),
					ConfigJSON:  configBlob,
					RegistryUrl: c.Config.URL,
					RegistryID:  c.Config.RegistryID,
					FromType:    c.Config.UseType,
				}

				im, err := extender.CreateImageExtender(ctx, img)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Msg("jfrog Insert imagelist")
					continue
				}
				cnt++
				if req.NeedToReturnAll {
					res.All = append(res.All, im.All...)
				}
				if req.NeedToReturnAdded {
					res.Added = append(res.Added, im.Added...)
				}
			}
		}
	}
	logging.GetLogger().Info().Msgf("jfrog List images count:%d", cnt)
	return res, nil
}

func init() {
	err := registry.Register(consts.JfrogVersion, openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init harborV2 error")
	}
	logging.GetLogger().Info().Msg("jfrog dirver register success")
}

// openRegistry constructs a jfrog Jfrog
func openRegistry(config registry.RegistrableComponentConfig) (registry.Registry, error) {
	var r Jfrog

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.GetLogger().Err(err).Msg("jfrog marshal config")
		return nil, err
	}
	conf := new(Config)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.GetLogger().Err(err).Msg("jfrog Unmarshal config")
		return nil, err
	}

	r.Config = *conf
	// rc, err := NewDockerRegistryClient(r.Config)
	rc, err := registry.NewDockerRegistryClient(r.Config.URL, r.Config.Username, r.Config.Password, r.Config.SkipTLSVerify)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("jfrog:new registry client err:%v", err)
		return nil, consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	r.RegistryClient = rc

	httpClient := http.Client{}
	if r.Config.SkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	r.JfrogClient = &httpClient

	return &r, nil
}
