package aliacr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cr"
	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

type AliAcr struct {
	Ctx            context.Context
	Config         Config
	RegistryClient *registry2.Registry // client for pull config json
	AliAcrClient   *cr.Client
}

func (aa *AliAcr) CheckProject(projectName string) error {
	panic("implement me")
}

func (aa *AliAcr) CreateProject(projectName string, public bool) error {
	panic("implement me")
}

func (aa *AliAcr) GetImage(projectName, fullRepoName, tag string) (*registry.Image, error) {
	panic("implement me")
}

func (aa *AliAcr) Ping() error {
	if err := aa.RegistryClient.Ping(); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (aa *AliAcr) ImageRetry(ctx context.Context, extender registry.Extender, req registry.ImageRetryRequest) (*registry.ListImagesRes, error) {
	return nil, nil
}
func (aa *AliAcr) SupportIncrementalSync(ctx context.Context) bool {
	return false
}
func (aa *AliAcr) DeleteImages(projectName, repoName, digest string) error {
	panic("implement me")
}

func (aa *AliAcr) ListImages(ctx context.Context, extender registry.Extender, req registry.ListImagesRequest) (*registry.ListImagesRes, error) {
	if extender.CreateImageExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender")
	}

	res := new(registry.ListImagesRes)
	cnt := 0
	// get namespaces
	nss, err := aa.listNamespaces(aa.AliAcrClient)
	if err != nil {
		return nil, err
	}

	for _, ns := range nss {
		// get repo details
		repos, err := aa.listReposByNamespace(aa.Config.Region, ns, aa.AliAcrClient)
		if err != nil {
			logging.Get().Err(err).Msg("list repo details err")
			continue
		}
		// get tag info
		for _, repo := range repos {
			tags, err := aa.getTags(repo, aa.AliAcrClient)
			if err != nil {
				logging.Get().Err(err).Msg("list repo tag err")
				continue
			}

			for _, tag := range tags {
				fullRepoName := repo.RepoNamespace + "/" + repo.RepoName

				manifestV2, err := aa.PullImageManifestV2(fullRepoName, tag)
				if err != nil {
					logging.Get().Err(err).Msgf("get manifest digest err, repo %s ,digest %s", fullRepoName, tag)
					continue
				}
				// pull config json
				imageDigest, err := ManifestV2Digest(manifestV2)
				if err != nil {
					logging.Get().Err(err).Msgf("get manifest digest err, repo %s ,digest %s", fullRepoName, tag)
					continue
				}
				manifestV2Str, err := manifestV2.MarshalJSON()
				if err != nil {
					logging.Get().Err(err).Msgf("get manifest string err, repo %s ,tag %s", fullRepoName, tag)
					continue
				}

				// pull config json
				configDigest := manifestV2.Config.Digest
				configBlob, err := aa.PullConfigBlob(fullRepoName, configDigest)
				if err != nil {
					logging.Get().Err(err).Msgf("get config blob err, repo %s ,tag %s", fullRepoName, tag)
					continue
				}
				var preImage = registry.Image{
					FromType:    aa.Config.UseType,
					ImageDigest: imageDigest,
					Repository:  fullRepoName,
					Tag:         tag,
					ManifestV2:  string(manifestV2Str),
					ConfigJSON:  configBlob,
					RegistryID:  aa.Config.RegistryID,
					RegistryUrl: aa.Config.URL,
				}
				cnt++

				im, err := extender.CreateImageExtender(ctx, preImage)
				if err != nil {
					if err != consts.ErrNotNodeImage {
						logging.Get().Err(err).Msgf("ali acr Insert imagelist error")
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
	}

	logging.Get().Info().Msgf("ali-acr List images count:%d", cnt)
	return res, nil
}

func (aa *AliAcr) ListImagesWithAuditLog(ctx context.Context, extender registry.Extender, req registry.ListImagesAuditLog) (*registry.ListImagesRes, error) {
	return nil, nil
}

func (aa *AliAcr) listNamespaces(c *cr.Client) (namespaces []string, err error) {
	// list namespaces
	nsReq := cr.CreateGetNamespaceListRequest()
	nsReq.SetDomain(aa.Config.Domain)
	nsResp, err := c.GetNamespaceList(nsReq)
	if err != nil {
		return nil, err
	}
	var resp = &aliACRNamespaceResp{}
	err = json.Unmarshal(nsResp.GetHttpContentBytes(), resp)
	if err != nil {
		logging.Get().Err(err).Msg("listNamespaces Unmarshal")
		return nil, err
	}
	for _, ns := range resp.Data.Namespaces {
		namespaces = append(namespaces, ns.Namespace)
	}
	logging.Get().Info().Str("driver", consts.AliAcrVersion).Strs("namespaces", namespaces).Msg("FetchArtifacts.listNamespace")
	return namespaces, nil
}

func (aa *AliAcr) listReposByNamespace(region string, namespace string, c *cr.Client) (repos []aliRepo, err error) {
	var reposReq = cr.CreateGetRepoListByNamespaceRequest()
	var reposResp = cr.CreateGetRepoListByNamespaceResponse()
	reposReq.SetDomain(aa.Config.Domain)
	reposReq.RepoNamespace = namespace
	var page = 1
	for {
		reposReq.Page = requests.NewInteger(page)
		reposResp, err = c.GetRepoListByNamespace(reposReq)
		if err != nil {
			logging.Get().Err(err).Msg("AliAcr,GetRepoListByNamespace")
			return nil, err
		}
		var resp = &aliReposResp{}
		if err := json.Unmarshal(reposResp.GetHttpContentBytes(), resp); err != nil {
			return nil, err
		}
		repos = append(repos, resp.Data.Repos...)
		if resp.Data.Total-(resp.Data.Page*resp.Data.PageSize) <= 0 {
			break
		}
		page++
	}
	return repos, nil
}

func (aa *AliAcr) getTags(repo aliRepo, c *cr.Client) (tags []string, err error) {
	logging.Get().Debug().Str("domain", aa.Config.Domain).
		Str("repo", repo.RepoNamespace+"/"+repo.RepoName).
		Msg("ali-acr getTags")
	var tagsReq = cr.CreateGetRepoTagsRequest()
	var tagsResp = cr.CreateGetRepoTagsResponse()
	tagsReq.SetDomain(aa.Config.Domain)
	tagsReq.RepoNamespace = repo.RepoNamespace
	tagsReq.RepoName = repo.RepoName
	var page = 1
	for {
		tagsReq.Page = requests.NewInteger(page)
		tagsResp, err = c.GetRepoTags(tagsReq)
		if err != nil {
			logging.Get().Err(err).Msg("AliAcr.GetRepoTags")
			return nil, err
		}

		var resp = &aliTagResp{}
		if err := json.Unmarshal(tagsResp.GetHttpContentBytes(), resp); err != nil {
			logging.Get().Err(err).Msg("getTags Unmarshal")
		}
		for _, tag := range resp.Data.Tags {
			tags = append(tags, tag.Tag)
		}

		if resp.Data.Total-(resp.Data.Page*resp.Data.PageSize) <= 0 {
			break
		}
		page++
	}

	return tags, nil
}

func openRegistry(config registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h AliAcr

	h.Ctx = context.Background()

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().Err(err).Msg("ali acr marshal config")
		return nil, err
	}
	conf := new(Config)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().Err(err).Msg("ali acr Unmarshal config")
		return nil, err
	}

	h.Config = *conf
	region, err := getRegion(h.Config.URL)
	if err != nil {
		logging.Get().Err(err).Msgf("get region :%s", h.Config.URL)
		return nil, err
	}
	h.Config.Region = region

	logging.Get().Info().Msgf("ali acr config:%+v", h.Config)

	// create client to pull image manifest and config
	rc, err := registry.NewDockerRegistryClient(h.Config.URL, h.Config.Username, h.Config.Password, h.Config.SkipTLSVerify)
	if err != nil {
		logging.Get().Err(err).Msg("openRegistry.NewClientWithAccessKey")
		return nil, consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	h.RegistryClient = rc

	sc, err := cr.NewClientWithAccessKey(h.Config.Region, h.Config.AccessKey, h.Config.AccessSecret)
	if err != nil {
		logging.Get().Err(err).Msg("openRegistry.NewClientWithAccessKey")
		return nil, consts.ErrAccessKeyOrAccessSecret
	}

	h.AliAcrClient = sc

	return &h, nil
}

func init() {
	err := registry.Register(consts.AliAcrVersion, openRegistry)
	if err != nil {
		logging.Get().Err(err).Msgf("init ali acr error")
		return
	}
	logging.Get().Info().Msg("ali acr dirver register success")
}

func (aa *AliAcr) PullImageManifestV2(repo, digest string) (*schema2.DeserializedManifest, error) {
	manifest, err := aa.RegistryClient.ManifestV2(repo, digest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
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
	return dig.String(), nil
}

func (aa *AliAcr) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
	reader, err := aa.RegistryClient.DownloadBlob(repo, configDigest)
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

// example:
// https://registry.%s.aliyuncs.com  表示阿里云镜像仓库的地址
// https://cr.%s.aliyuncs.com 表示阿里云镜像实列的的管理地址
var regRegion = regexp.MustCompile(`https://(registry|cr)\.([\w-]+)\.aliyuncs\.com`)

// 通过阿里云的url获取Region(服务器区域)信息
func getRegion(url string) (region string, err error) {
	url = strings.Trim(url, " ")
	if url == "" {
		return "", errors.New("empty url")
	}
	rs := regRegion.FindStringSubmatch(strings.Trim(url, " "))
	if len(rs) < 3 {
		return "", errors.New("invalid registry url")
	}
	return rs[2], nil
}
