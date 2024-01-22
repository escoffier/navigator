package aliacree

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

const (
	RepoStatusNormal = "NORMAL"
	DefaultPageSize  = "30"
	DefaultVersion   = "2018-12-01"
	ProtocolHTTPS    = "https"
	CodeSuccess      = "success"
)

type AliAcrEE struct {
	Ctx            context.Context
	Config         Config
	RegistryClient *registry2.Registry // client for pull config json
	AliAcrClient   *sdk.Client
}

func (aa *AliAcrEE) CheckProject(projectName string) error {
	panic("implement me")
}

func (aa *AliAcrEE) CreateProject(projectName string, public bool) error {
	panic("implement me")
}

func (aa *AliAcrEE) SupportIncrementalSync(ctx context.Context) bool {
	return false
}

func (aa *AliAcrEE) Ping() error {
	if _, err := aa.listNamespaces(); err != nil {
		return err
	}

	if err := aa.RegistryClient.Ping(); err != nil {
		return warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (aa *AliAcrEE) DeleteImages(projectName, repoName, digest string) error {
	panic("implement me")
}

func (aa *AliAcrEE) ListImages(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesRequest) (*warehouse.ListImagesRes, error) {

	if extender.CreateImageExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender")
	}
	res := new(warehouse.ListImagesRes)
	cnt := 0
	// get namespaces
	nss, err := aa.listNamespaces()
	if err != nil {
		res.HasErr = true
		logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Str("instance", aa.Config.InstanceID).Msg("listNamespaces")
		return nil, err
	}

	for _, ns := range nss {
		// get repo details
		repos, err := aa.listReposByNamespace(ns)
		if err != nil {
			res.HasErr = true
			logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).
				Str("instance", aa.Config.InstanceID).
				Str("namespace", ns.NamespaceName).
				Msg("listReposByNamespace")
			continue
		}
		for _, repo := range repos {
			// get tag info
			tags, err := aa.getTags(repo)
			if err != nil {
				res.HasErr = true
				logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).
					Str("instance", aa.Config.InstanceID).
					Str("namespace", ns.NamespaceName).
					Str("repo", repo.RepoName).
					Msg("getTags")
				continue
			}

			for _, tag := range tags {
				fullRepoName := repo.RepoNamespaceName + "/" + repo.RepoName

				manifestV2, err := aa.PullImageManifestV2(fullRepoName, tag.Tag)
				if err != nil {
					res.HasErr = true
					logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).
						Str("instance", aa.Config.InstanceID).
						Str("namespace", ns.NamespaceName).
						Str("repo", repo.RepoName).
						Str("tag", tag.Tag).
						Msg("PullImageManifestV2")
					continue
				}
				manifestV2Str, err := manifestV2.MarshalJSON()
				if err != nil {
					res.HasErr = true
					logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).
						Str("instance", aa.Config.InstanceID).
						Str("namespace", ns.NamespaceName).
						Str("repo", repo.RepoName).
						Str("tag", tag.Tag).
						Msg("MarshalJSON")
					continue
				}

				// pull config json
				configDigest := manifestV2.Config.Digest
				configBlob, err := aa.PullConfigBlob(fullRepoName, configDigest)
				if err != nil {
					res.HasErr = true
					logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).
						Str("instance", aa.Config.InstanceID).
						Str("namespace", ns.NamespaceName).
						Str("repo", repo.RepoName).
						Str("tag", tag.Tag).
						Msg("PullConfigBlob")
					continue
				}
				var preImage = warehouse.Image{
					ImageDigest: "sha256:" + tag.Digest,
					Repository:  fullRepoName,
					Tag:         tag.Tag,
					ManifestV2:  string(manifestV2Str),
					ConfigJSON:  configBlob,
					Created:     time.UnixMilli(tag.ImageCreate),
					RegistryUrl: aa.Config.URL,
					RegistryID:  aa.Config.RegistryID,
				}
				cnt++

				im, err := extender.CreateImageExtender(ctx, preImage)
				if err != nil {
					res.HasErr = true
					if err != preConsts.ErrNotNodeImage {
						logging.Get().Err(err).Str("module", "RegistryImage").Msg("Insert imagelist error")
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

	logging.Get().Info().Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Msgf("List images count:%d", cnt)
	return res, nil
}

func (aa *AliAcrEE) listNamespaces() (namespaces []Namespace, err error) {
	request := requests.NewCommonRequest()
	request.Method = http.MethodPost
	request.Scheme = ProtocolHTTPS
	request.Domain = aa.Config.Domain
	request.Version = DefaultVersion
	request.ApiName = "ListNamespace"
	request.QueryParams["PageSize"] = DefaultPageSize
	request.QueryParams["InstanceId"] = aa.Config.InstanceID
	ans := make([]Namespace, 0)

	page := 1
	for {
		request.QueryParams["PageNo"] = strconv.Itoa(page)

		// 这里可以忽略这个错误，因为如果有错，也会返回response,通过response的Code来判断是否成功
		response, _ := aa.AliAcrClient.ProcessCommonRequest(request)
		res := new(HTTPResponse)
		if err := json.Unmarshal(response.GetHttpContentBytes(), res); err != nil {
			return nil, err
		}
		if res.Code != CodeSuccess {
			return nil, fmt.Errorf(res.Code)
		}
		ans = append(ans, res.Namespaces...)
		if res.PageSize*res.PageNo >= res.TotalCount {
			break
		}
		page++
	}

	return ans, nil
}

func (aa *AliAcrEE) listReposByNamespace(namespace Namespace) (repos []Repository, err error) {
	request := requests.NewCommonRequest()
	request.Method = http.MethodPost
	request.Scheme = ProtocolHTTPS
	request.Domain = aa.Config.Domain
	request.Version = "2018-12-01"
	request.ApiName = "ListRepository"
	request.QueryParams[""] = "30"
	request.QueryParams["InstanceId"] = aa.Config.InstanceID
	request.QueryParams["RepoStatus"] = RepoStatusNormal
	request.QueryParams["RepoNamespaceName"] = namespace.NamespaceName
	ans := make([]Repository, 0)

	page := 1
	for {
		request.QueryParams["PageNo"] = strconv.Itoa(page)

		response, err := aa.AliAcrClient.ProcessCommonRequest(request)
		if err != nil {
			return nil, err
		}
		res := new(HTTPResponse)
		if err := json.Unmarshal(response.GetHttpContentBytes(), res); err != nil {
			return nil, err
		}
		if res.Code != CodeSuccess {
			return nil, fmt.Errorf(res.Message)
		}
		ans = append(ans, res.Repositories...)
		if res.PageSize*res.PageNo >= res.TotalCount {
			break
		}
		page++
	}

	return ans, nil
}

func (aa *AliAcrEE) getTags(repo Repository) (tags []Image, err error) {
	request := requests.NewCommonRequest()
	request.Method = http.MethodPost
	request.Scheme = ProtocolHTTPS
	request.Domain = aa.Config.Domain
	request.Version = DefaultVersion
	request.ApiName = "ListRepoTag"
	request.QueryParams["PageSize"] = DefaultPageSize
	request.QueryParams["InstanceId"] = aa.Config.InstanceID
	request.QueryParams["RepoId"] = repo.RepoID
	ans := make([]Image, 0)

	page := 1
	for {
		request.QueryParams["PageNo"] = strconv.Itoa(page)

		response, err := aa.AliAcrClient.ProcessCommonRequest(request)
		if err != nil {
			return nil, err
		}
		res := new(HTTPResponse)
		if err := json.Unmarshal(response.GetHttpContentBytes(), res); err != nil {
			return ans, err
		}

		if res.Code != CodeSuccess {
			return nil, fmt.Errorf(res.Message)
		}
		ans = append(ans, res.Images...)
		if res.PageSize*res.PageNo >= res.TotalCount {
			break
		}
		page++
	}

	return ans, nil
}

func (aa *AliAcrEE) ListImagesWithAuditLog(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesAuditLog) (*warehouse.ListImagesRes, error) {
	return nil, nil
}

func openRegistry(config warehouse.RegistrableComponentConfig) (warehouse.Registry, error) {
	var aa AliAcrEE

	aa.Ctx = context.Background()

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Msg("marshal config")
		return nil, err
	}
	conf := new(Config)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Msg("Unmarshal config")
		return nil, err
	}

	aa.Config = *conf

	if aa.Config.RegionID == "" {
		region, err := getRegion(aa.Config.URL)
		if err != nil {
			logging.Get().Err(err).Str("module", "RegistryImage").Msgf("get region :%s", aa.Config.URL)
			return nil, err
		}
		aa.Config.RegionID = region
	}

	aa.Config.Domain = getDomain(aa.Config.URL, aa.Config.RegionID)

	logging.Get().Debug().Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Msgf("config:%+v", aa.Config)

	// create client to pull image manifest and config
	rc, err := warehouse.NewDockerRegistryClient(aa.Config.URL, aa.Config.Username, aa.Config.Password, aa.Config.SkipTLSVerify)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("openRegistry.NewDockerRegistryClient")
		return nil, warehouse.ErrNotConnectOrWrongUsernameOrPasswd
	}
	aa.RegistryClient = rc

	sc, err := sdk.NewClientWithAccessKey(aa.Config.RegionID, aa.Config.AccessKey, aa.Config.AccessSecret)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("openRegistry.NewClientWithAccessKey")
		return nil, warehouse.ErrAccessKeyOrAccessSecret
	}

	aa.AliAcrClient = sc

	return &aa, nil
}

func init() {
	err := warehouse.Register(imagesec.AliAcrEEVersion, openRegistry)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("init ali acr error")
		return
	}
	logging.Get().Info().Str("module", "RegistryImage").Str("driver", imagesec.AliAcrEEVersion).Msg("register success")
}

func (aa *AliAcrEE) PullImageManifestV2(repo, digest string) (*schema2.DeserializedManifest, error) {
	manifest, err := aa.RegistryClient.ManifestV2(repo, digest)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (aa *AliAcrEE) PullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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
// https:%s-registry.cn-hangzhou.cr.aliyuncs.com 公有网络
// ts-acr-registry-vpc.cn-hangzhou.cr.aliyuncs.com 专有网络
var regRegion = regexp.MustCompile(`https://.*-(registry|registry-vpc)\.([\w-]+)\.cr\.aliyuncs\.com`)

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

func getDomain(url string, region string) string {
	if strings.Contains(url, "vpc") {
		return "cr-vpc." + region + ".aliyuncs.com"
	}
	return "cr." + region + ".aliyuncs.com"
}
