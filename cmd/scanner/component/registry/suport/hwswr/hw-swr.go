package hwswr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	swr "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/swr/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/swr/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/swr/v2/region"
	"github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	Version      = "hw-swr"
	RegionRegExp = `.*swr\.(.*)\.myhuaweicloud.com`
)

var (
	RegionReg = regexp.MustCompile(RegionRegExp)
)

type HwSwr struct {
	Ctx            context.Context
	Config         HwSwrConfig
	RegistryClient *registry2.Registry // client for pull config json
	SwrClient      *swr.SwrClient      // client for swr
}

func (h *HwSwr) ListNameSpaces() (*model.ListNamespacesResponse, error) {
	request := &model.ListNamespacesRequest{}
	response, err := h.SwrClient.ListNamespaces(request)
	if err != nil {
		return nil, fmt.Errorf("get namespaces err:%v", err)
	}

	return response, nil
}

func (h *HwSwr) ListRepositoryTags(ns, repo string) (*model.ListRepositoryTagsResponse, error) {
	request := &model.ListRepositoryTagsRequest{}
	request.Namespace = ns
	request.Repository = repo
	response, err := h.SwrClient.ListRepositoryTags(request)
	if err != nil {
		return nil, fmt.Errorf("get repository tags,namespace %s,repo %s,err:%v", ns, repo, err)
	}
	return response, nil
}

func (h *HwSwr) ListReposDetails(ns string) (*model.ListReposDetailsResponse, error) {
	request := &model.ListReposDetailsRequest{}
	request.Namespace = &ns
	response, err := h.SwrClient.ListReposDetails(request)
	if err != nil {
		return nil, fmt.Errorf("get namespace %s repos err:%v", ns, err)
	}
	return response, nil
}

func (h *HwSwr) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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

func (h *HwSwr) ListImages(extender registry.ImageListExtender, needToReturnRes bool) ([]registry.Image, error) {
	images := make([]registry.Image, 0)

	cnt := 0
	// get namespaces
	ns, err := h.ListNameSpaces()
	if err != nil {
		return nil, err
	}

	for _, v := range *ns.Namespaces {
		// get repo details
		namespace := v.Name
		repos, err := h.ListReposDetails(namespace)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("list repo details err")
			continue
		}
		// get tag info
		for _, r := range *repos.Body {
			repoName := r.Name
			tags, err := h.ListRepositoryTags(namespace, repoName)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("list repo tag err")
				continue
			}

			for _, tag := range *tags.Body {
				// hw swr will return manifest
				manifestV2 := &schema2.DeserializedManifest{}
				if err := manifestV2.UnmarshalJSON([]byte(tag.Manifest)); err != nil {
					logging.GetLogger().Error().Err(err).Msgf("unmarshal manifest err: %s", tag.Manifest)
					continue
				}

				// download config json
				imageName := fmt.Sprintf("%s/%s", namespace, repoName)
				configBlob, err := h.PullConfigBlob(imageName, manifestV2.Config.Digest)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msgf("pull image %s config json err", imageName)
					continue
				}

				// append image info
				i := &registry.Image{}
				i.Tag = tag.Tag
				i.Repository = imageName
				i.Size = uint(tag.Size)
				i.ImageDigest = tag.Digest
				i.ManifestV2 = tag.Manifest
				i.ConfigJson = configBlob
				tm1, err := time.Parse(time.RFC3339, tag.Created)
				if err != nil {
					logging.GetLogger().Warn().Msgf("time parse warning:%v", err)
				} else {
					i.Created = tm1
				}
				tm2, err := time.Parse(time.RFC3339, tag.Updated)
				if err != nil {
					logging.GetLogger().Warn().Msgf("time parse warning:%v", err)
				} else {
					i.LastPushTime = tm2
				}
				if needToReturnRes {
					images = append(images, *i)
				}
				cnt++
				if err = extender(*i); err != nil {
					logging.GetLogger().Error().Err(err).Msg("ListImages.extender")
				}
			}
		}
	}

	logging.GetLogger().Info().Msgf("hw-swr List images count:%d", cnt)
	return images, nil
}

func (h *HwSwr) CheckProject(projectName string) error {
	return fmt.Errorf("not implement")
}

func (h *HwSwr) CreateProject(projectName string, public bool) error {
	return fmt.Errorf("not implement")
}

func (h *HwSwr) GetImage(projectName, fullRepoName, tag string) (*registry.Image, error) {
	return nil, fmt.Errorf("not implement")
}

func (h *HwSwr) Ping() error {
	return h.RegistryClient.Ping()
}

func (h *HwSwr) DeleteImages(projectName, repoName, digest string) error {
	return fmt.Errorf("not implement")
}

func init() {
	err := registry.Register(Version, openRegistry)
	if err != nil {
		logging.GetLogger().Error().Msgf("init huawei-swr error:%v", err)
		return
	}
	logging.GetLogger().Info().Msg("huawei-swr dirver register success")
}

func openRegistry(config registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h HwSwr

	h.Ctx = context.Background()

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("hw-swr marshal config")
		return nil, err
	}
	conf := new(HwSwrConfig)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.GetLogger().Error().Err(err).Msg("hw-swr Unmarshal config")
		return nil, err
	}

	h.Config = *conf

	logging.GetLogger().Info().Msgf("swr config:%+v", h.Config)
	// create swr client to get namespaces,images,tags

	// generate region and credential
	if len(h.Config.Region) == 0 || len(h.Config.Username) == 0 || len(h.Config.Password) == 0 {
		logging.GetLogger().Info().Msg("get region and credential")
		region1, err := getRegionBySwrUrl(h.Config.URL)
		if err != nil {
			return nil, fmt.Errorf("huawei swr: parse region from url err.%v", err)
		}
		user, passwd, err := generateSwrRegistryCredentialByAkSk(h.Config.AccessKey, h.Config.SecretKey, region1)
		if err != nil {
			return nil, fmt.Errorf("huawei swr: generate swr credential err.%v", err)
		}
		h.Config.Username = user
		h.Config.Password = passwd
		h.Config.Region = region1
	}
	logging.GetLogger().Info().Msgf("after generate region:%s,username:%s,", h.Config.Region, h.Config.Username)

	// create client to pull image manifest and config
	rc, err := registry.NewDockerRegistryClient(h.Config.URL, h.Config.Username, h.Config.Password, h.Config.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("huawei swr: new registry client err:%v", err)
	}
	h.RegistryClient = rc

	// create swr client to get namespaces,images,tags
	sc, err := newSwrClient(h.Config.AccessKey, h.Config.SecretKey, h.Config.Region)
	if err != nil {
		return nil, fmt.Errorf("huawei swr: create swr client err:%v", err)
	}
	h.SwrClient = sc

	return &h, nil
}

func getRegionBySwrUrl(url string) (string, error) {
	res := RegionReg.FindStringSubmatch(url)
	if len(res) != 2 {
		return "", fmt.Errorf("not found match region for url:%s,%v", url, res)
	}
	return res[1], nil
}

// generateSwrRegistryCredentialByAkSk see: https://support.huaweicloud.com/usermanual-swr/swr_01_1000.html
func generateSwrRegistryCredentialByAkSk(ak, sk, region string) (string, string, error) {
	cmdStr := fmt.Sprintf("printf \"%s\" | openssl dgst -binary -sha256 -hmac \"%s\" | od -An -vtx1 | sed 's/[ \\n]//g' | sed 'N;s/\\n//'", ak, sk)
	cmd := exec.Command("bash", "-c", cmdStr)
	data, err := cmd.Output()
	password := strings.TrimSuffix(string(data), "\n")
	if err != nil {
		return "", "", fmt.Errorf("generate credential by ak sk err:%v", err)
	}
	// username,password
	return fmt.Sprintf("%s@%s", region, ak), password, nil
}

// newSwrClient
// 使用的是ak和sk获取客户端，而不是username和password
func newSwrClient(ak, sk, swrRegion string) (*swr.SwrClient, error) {
	auth := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		Build()

	client := swr.NewSwrClient(
		swr.SwrClientBuilder().
			WithRegion(region.ValueOf(swrRegion)).
			WithCredential(auth).
			Build())
	return client, nil
}
