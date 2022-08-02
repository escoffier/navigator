package hwswree

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type HwSwrEE struct {
	Config         Config
	RegistryClient *registry2.Registry // client for pull config json
	Client         *http.Client
}

func (h *HwSwrEE) ImageRetry(ctx context.Context, extender registry.Extender, req registry.ImageRetryRequest) (*registry.ListImagesRes, error) {
	return nil, nil
}

func (h *HwSwrEE) SupportIncrementalSync(ctx context.Context) bool {
	return false
}

func (h *HwSwrEE) ListImagesWithAuditLog(ctx context.Context, extender registry.Extender, req registry.ListImagesAuditLog) (*registry.ListImagesRes, error) {
	return nil, nil
}

func (h *HwSwrEE) ListImages(ctx context.Context, extender registry.Extender, req registry.ListImagesRequest) (*registry.ListImagesRes, error) {
	if extender.CreateImageExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender")
	}
	res := new(registry.ListImagesRes)
	cnt := 0
	repos, err := h.getRepositories(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("huawei-swr-en getRepositories")
		return nil, err
	}

	for _, repo := range repos {
		for _, tag := range repo.Tags {
			// pull manifest
			imageName := fmt.Sprintf("%s/%s", repo.Namespace, repo.Name)

			manifest, err := h.pullImageManifest(imageName, tag)
			if err != nil {
				res.HasErr = true
				logging.Get().Err(err).Str("image", fmt.Sprintf("%s:%s", imageName, tag)).Msg("huawei-swr-en pullImageManifest")
				continue
			}
			manifestByte, err := manifest.MarshalJSON()
			if err != nil {
				res.HasErr = true
				logging.Get().Err(err).Str("image", fmt.Sprintf("%s:%s", imageName, tag)).Msg("huawei-swr-en MarshalJSON")
				continue
			}

			// download config json
			configBlob, err := h.pullConfigBlob(imageName, manifest.Config.Digest)
			if err != nil {
				res.HasErr = true
				logging.Get().Err(err).Str("image", fmt.Sprintf("%s:%s", imageName, tag)).Msg("huawei-swr-en pullConfigBlob")
				continue
			}

			// append image info
			image := &registry.Image{
				RegistryID:   h.Config.RegistryID,
				RegistryUrl:  h.Config.URL,
				ImageDigest:  manifest.Config.Digest.String(),
				FromType:     h.Config.UseType,
				Repository:   imageName,
				Tag:          tag,
				Size:         uint(repo.Size),
				Created:      repo.CreatedAt,
				LastPushTime: repo.UpdatedAt,
				LastPullTime: repo.UpdatedAt,
				ManifestV2:   string(manifestByte),
				ConfigJSON:   configBlob,
			}

			im, err := extender.CreateImageExtender(ctx, *image)
			if err != nil {
				res.HasErr = true
				logging.Get().Err(err).Msg("huawei-swr-en ListImages.extender")
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

	logging.Get().Info().Msgf("huawei-swr-en List images count:%d", cnt)
	return res, nil
}

func (h *HwSwrEE) CheckProject(projectName string) error {
	return fmt.Errorf("not implement")
}

func (h *HwSwrEE) CreateProject(projectName string, public bool) error {
	return fmt.Errorf("not implement")
}

func (h *HwSwrEE) GetImage(projectName, fullRepoName, tag string) (*registry.Image, error) {
	return nil, fmt.Errorf("not implement")
}

func (h *HwSwrEE) Ping() error {
	if err := h.RegistryClient.Ping(); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (h *HwSwrEE) DeleteImages(projectName, repoName, digest string) error {
	return fmt.Errorf("not implement")
}

func init() {
	err := registry.Register(consts.HaiWeiSwrENVersion, openRegistry)
	if err != nil {
		logging.Get().Err(err).Msgf("init huawei-swr-en error")
		return
	}
	logging.Get().Info().Msg("huawei-swr-en driver register success")
}

func (h *HwSwrEE) getRepositories(ctx context.Context) ([]Repository, error) {
	bys, err := h.reqHarbor(ctx, h.Config.URL+"/dockyard/v2/repositories?filter=center::self")
	if err != nil {
		return nil, err
	}
	res := make([]Repository, 0)
	if err := json.Unmarshal(bys, &res); err != nil {
		return nil, err
	}
	return res, err
}

func openRegistry(config registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h HwSwrEE

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().Err(err).Msg("hw-swr marshal config")
		return nil, err
	}
	conf := Config{}

	if err := json.Unmarshal(byt, &conf); err != nil {
		logging.Get().Err(err).Msg("hw-swr Unmarshal config")
		return nil, err
	}

	h.Config = conf

	logging.Get().Info().Interface("config", h.Config).Msg("openRegistry")

	rc, err := registry.NewDockerRegistryClient(h.Config.URL, h.Config.Username, h.Config.Password, h.Config.SkipTLSVerify)
	if err != nil {
		logging.Get().Err(err).Msg("huawei en swr: new registry client")
		return nil, consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	h.RegistryClient = rc

	httpClient := http.Client{}
	if h.Config.SkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	h.Client = &httpClient

	return &h, nil
}

func (h *HwSwrEE) reqHarbor(ctx context.Context, url string) ([]byte, error) {
	logging.Get().Info().Str("url", url).Msg("huawei-swr-en reqHarbor")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(h.Config.Username, h.Config.Password)
	var resp *http.Response
	resp, err = h.Client.Do(req.WithContext(ctx))

	if err != nil {
		return nil, err
	}
	defer func() {
		if resp != nil {
			util.CloseBodyWithLog(resp.Body)
		}
	}()

	if resp.StatusCode > http.StatusMultipleChoices || resp.StatusCode < http.StatusOK {
		return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	}

	bys, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bys, nil
}

func (h *HwSwrEE) pullImageManifest(fullRepo, tag string) (*schema2.DeserializedManifest, error) {
	return h.RegistryClient.ManifestV2(fullRepo, tag)
}

func (h *HwSwrEE) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := h.RegistryClient.DownloadBlob(repo, configDigest)
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
