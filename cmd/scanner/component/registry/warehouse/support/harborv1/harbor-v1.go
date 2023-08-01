package harborv1

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	APIVersion          = "api"
	DefaultPageSize int = 100
)

type HarborV1 struct {
	ctx            context.Context
	client         *http.Client // client for pull harbor repos and tags
	config         Config
	registryClient *registry2.Registry // client for pull manifest
}

func (h *HarborV1) reqHarbor(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err))
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)
	var bytes []byte

	resp, err := h.client.Do(req.WithContext(h.ctx))
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err))
	}

	defer util.CloseBodyWithLog(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusMultipleChoices {
		return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	}
	bytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bytes is failed %v", err)
	}
	return bytes, nil
}

func (h *HarborV1) ListProjects() ([]Project, error) {
	var projects []Project
	page := 1
	for {
		p, err := h.ListProjectsWithPage(page, DefaultPageSize)
		if err != nil {
			break
		}
		for i := range p {
			if !p[i].Deleted {
				projects = append(projects, p[i])
			}
		}
		if len(p) < DefaultPageSize {
			// last page
			break
		}
		page++
	}

	logging.GetLogger().Info().Msgf("projects %+v", projects)
	return projects, nil
}

func (h *HarborV1) ListProjectsWithPage(page, pageSize int) ([]Project, error) {
	url := fmt.Sprintf("%s/%s/projects?page=%d&page_size=%d", h.config.URL, APIVersion, page, pageSize)
	logging.GetLogger().Info().Msgf("req harbor projects url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor projects err")
		return nil, err
	}

	var projects []Project
	if err := json.Unmarshal(data, &projects); err != nil {
		logging.GetLogger().Err(err).Msg("ListProjectsWithPage.Unmarshal")
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor projects body err.%v", err))
	}

	// logging.GetLogger().Info().Msgf("projects %+v",projects)
	// 过滤了被删除的镜像
	ans := make([]Project, 0)
	for i := range projects {
		if projects[i].Deleted {
			continue
		}
		ans = append(ans, projects[i])
	}

	logging.GetLogger().Debug().Msgf("ListProjectsWithPagerepos %+v", ans)
	return ans, nil
}

func (h *HarborV1) ListProjectRepos(project int) ([]Repository, error) {
	var repos []Repository
	page := 1
	for {
		r, err := h.ListProjectReposWithPage(project, page, DefaultPageSize)
		if err != nil {
			logging.GetLogger().Err(err).Msg("ListProjectRepos.ListProjectReposWithPage break")
			break
		}
		repos = append(repos, r...)
		if len(r) < DefaultPageSize {
			// last page
			break
		}
		page++
	}

	logging.GetLogger().Info().Interface("repos", repos).Msg("ListProjectRepos")
	return repos, nil
}

func (h *HarborV1) ListProjectReposWithPage(project, page, pageSize int) ([]Repository, error) {
	url := fmt.Sprintf("%s/%s/repositories?project_id=%d&page=%d&page_size=%d", h.config.URL, APIVersion, project, page, pageSize)
	logging.GetLogger().Debug().Msgf("req harbor repo url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor repos err")
		return nil, err
	}

	var repos []Repository
	if err := json.Unmarshal(data, &repos); err != nil {
		logging.GetLogger().Err(err).Msg("ListProjectReposWithPage.Unmarshal")
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor repos body err.%v", err))
	}

	// 过滤了被删除的镜像
	ans := make([]Repository, 0)
	for i := range repos {
		if len(repos[i].Labels) > 0 && repos[i].Labels[0].Deleted {
			continue
		}
		ans = append(ans, repos[i])
	}

	logging.GetLogger().Debug().Msgf("ListProjectReposWithPage repos %+v", repos)
	return ans, nil
}

func (h *HarborV1) ListRepoTags(repo string) ([]Tag, error) {
	url := fmt.Sprintf("%s/%s/repositories/%s/tags?detail=true", h.config.URL, APIVersion, repo)
	logging.GetLogger().Debug().Msgf("req harbor repo artifacts url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListRepoTags.CloseBodyWithLog")
		return nil, err
	}

	var tags []Tag
	if err = json.Unmarshal(data, &tags); err != nil {
		logging.GetLogger().Err(err).Msg("ListRepoTags.Unmarshal")
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor artifacts body err.%v", err))
	}

	logging.GetLogger().Debug().Msgf("ListRepoTags get RepoTags %v", tags)
	return tags, nil
}

func (h *HarborV1) ListAuditLogWithPage(op string, time string, projectID int, page int, pageSize int) ([]AuditLog, error) {
	url := fmt.Sprintf("%s/%s/projects/%d/logs?begin_timestamp=%s&operation=%s&page=%d&page_size=%d", h.config.URL, APIVersion, projectID, time, op, page, pageSize)
	logging.GetLogger().Info().Str("url", url).Msg("ListAuditLogWithPage")
	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor project %d AuditLog err", projectID)
		return nil, err
	}
	logging.GetLogger().Debug().Msgf("data:%v", string(data))
	var auditLog []AuditLog
	if err := json.Unmarshal(data, &auditLog); err != nil {
		logging.GetLogger().Err(err).Msg("ListAuditLogWithPage.Unmarshal")
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor artifacts body err"))
	}
	logging.GetLogger().Debug().Msgf("ListAuditLogWithPage get AuditLogs %v", auditLog)
	return auditLog, nil
}

func (h *HarborV1) GetManifest(repo string, repoTag Tag) (string, string, string, error) {
	var (
		manifestV2   string
		manifestV1   string
		configBlob   string
		configDigest digest.Digest
		err          error
	)
	manifestV2, configDigest, err = h.pullImageManifestV2(repo, repoTag.Digest)
	if err == nil {
		// pull config json
		configBlob, err = h.pullConfigBlob(repo, configDigest)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get config blob err, repo %s ,digest %s", repo, repoTag.Digest)
			return "", "", "", fmt.Errorf("get config blob err:%v, repo %s ,digest %s", err, repo, repoTag.Digest)
		}
	} else {
		// pull manifest v2 err,try v1
		logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, repo, repoTag.Digest)
		manifestV1, err = h.pullImageManifestV1(repo, repoTag.Digest)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, repo, repoTag.Digest)
			return "", "", "", fmt.Errorf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, repo, repoTag.Digest)
		}
	}
	return manifestV1, manifestV2, configBlob, nil
}

// 如果第一次同步就是增量同步，那这里会OOM
func (h *HarborV1) ListAuditLog(op string, startAt int64, projectID int) ([]AuditLog, error) {
	var auditlogs []AuditLog
	page := 1
	for {
		auditlog, err := h.ListAuditLogWithPage(op, fmt.Sprintf("%v", startAt), projectID, page, DefaultPageSize)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ListAuditLog.ListAuditLogWithPage break projectID %v", projectID)
			return nil, err
		}
		auditlogs = append(auditlogs, auditlog...)
		if len(auditlog) < DefaultPageSize {
			break
		}
		page++
	}
	return auditlogs, nil
}

func (h *HarborV1) GetImageTag(repo string, tag string) (*Tag, error) {
	url := fmt.Sprintf("%s/%s/repositories/%s/tags/%s", h.config.URL, APIVersion, repo, tag)
	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor repo :%s tag :%s err", repo, tag)
		return nil, err
	}
	var tmpTag Tag
	if err := json.Unmarshal(data, &tmpTag); err != nil {
		logging.GetLogger().Err(err).Msgf("GetImageTag Unmarshal error repo:%v tag:%v", repo, tag)
		return nil, err
	}
	if len(tmpTag.Labels) > 0 && tmpTag.Labels[0].Deleted {
		return nil, err
	}
	return &tmpTag, nil
}

func (h *HarborV1) ListImagesWithAuditLog(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesAuditLog) (*warehouse.ListImagesRes, error) {
	if extender.CreateOrAddRetryCountExtender == nil || extender.CreateImageExtender == nil || extender.DeleteImageRetryExtender == nil {
		return nil, fmt.Errorf("not get CreateOrAddRetryCountExtender or CreateImageExtender or DeleteImageRetryExtender")
	}

	res := new(warehouse.ListImagesRes)
	projects, err := h.ListProjects()
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListImagesWithAuditLog failed because ListProjects")
		return nil, err
	}
	cz := time.FixedZone("CST", 8*3600)
	for _, v := range projects {
		mp := make(map[string]int64)
		pushAuditLog, err := h.ListAuditLog("push", req.StartAt, v.ProjectID)
		if err != nil {
			res.GetAuditLogError = true
			continue
		}
		// 查push日志
		for i := range pushAuditLog { // 先过滤出指定时间内push的镜像，标记时间
			tt, err := time.ParseInLocation(time.RFC3339, pushAuditLog[i].OpTime, time.UTC)
			if err != nil {
				logging.GetLogger().Warn().Msgf("Parse time Error time :%v", pushAuditLog[i].OpTime)
				continue
			}
			createKey := fmt.Sprintf("%s-%s", pushAuditLog[i].RepoName, pushAuditLog[i].RepoTag)

			createTime := tt.In(cz).Unix()
			if mp[createKey] < createTime {
				mp[createKey] = createTime
			}
		}
		// 查删除日志
		deleteAuditLog, err := h.ListAuditLog("delete", req.StartAt, v.ProjectID)
		if err != nil {
			res.GetAuditLogError = true
			continue
		}
		for i := range deleteAuditLog { //  删除时间大于push时间的镜像
			tt, err := time.ParseInLocation(time.RFC3339, deleteAuditLog[i].OpTime, time.UTC)
			if err != nil {
				logging.GetLogger().Warn().Msgf("Parse time Error time :%v", deleteAuditLog[i].OpTime)
				continue
			}
			deleteTime := tt.In(cz).Unix()
			deleteKey := fmt.Sprintf("%s-%s", deleteAuditLog[i].RepoName, deleteAuditLog[i].RepoTag)

			if pushTime, ok := mp[deleteKey]; ok && pushTime < deleteTime {
				mp[deleteKey] = 0
			}
		}
		for _, k := range pushAuditLog {
			createKey := fmt.Sprintf("%s-%s", k.RepoName, k.RepoTag)
			if mp[createKey] <= 0 {
				continue
			}
			tag, err := h.GetImageTag(k.RepoName, k.RepoTag)

			regImage := warehouse.Image{Repository: k.RepoName, Tag: k.RepoTag, RegistryID: h.config.RegistryID}

			if err != nil {
				logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("GetImageTag")
				if err := extender.CreateOrAddRetryCountExtender(ctx, regImage); err != nil {
					logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("createRetryExtender")
				}
				continue
			}
			manifestV1, manifestV2, configBlob, err := h.GetManifest(k.RepoName, *tag)
			if err != nil {
				logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("GetManifest")

				if err := extender.CreateOrAddRetryCountExtender(ctx, regImage); err != nil {
					logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("createRetryExtender")
				}
				continue
			}
			i := h.makeImage(k.RepoName, *tag, manifestV1, manifestV2, configBlob)
			im, err := extender.CreateImageExtender(ctx, i)
			if err != nil {
				logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("createImageExtender")

				if err := extender.CreateOrAddRetryCountExtender(ctx, regImage); err != nil {
					logging.GetLogger().Err(err).Str("RepoName", k.RepoName).Str("Tag", k.RepoTag).Msg("createImageExtender")
				}
				continue
			}
			res.Added = append(res.Added, im.Added...)
		}
	}
	return res, nil
}

func (h *HarborV1) ListImages(ctx context.Context, extender warehouse.Extender, req warehouse.ListImagesRequest) (*warehouse.ListImagesRes, error) {
	if extender.CreateImageExtender == nil || extender.CreateOrAddRetryCountExtender == nil || extender.UpdateImageLastSyncExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender or CreateOrAddRetryCountExtender or UpdateImageLastSyncExtender")
	}
	res := new(warehouse.ListImagesRes)
	cnt := 0
	// get all projects
	projects, err := h.ListProjects()
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListImages.ListProjects")
		return nil, err
	}

	// get all repos
	for _, v := range projects {
		repos, err := h.ListProjectRepos(v.ProjectID)
		if err != nil {
			res.HasErr = true
			// just log and try next project
			logging.GetLogger().Err(err).Str("project", v.Name).Msg("ListImages ListProjectRepos")
			continue
		}

		// get all artifacts in repo
		for _, r := range repos {
			// repo name like 'library/xxx'
			tags, err := h.ListRepoTags(r.Name)
			if err != nil {
				res.HasErr = true
				logging.GetLogger().Err(err).Str("project", v.Name).Str("repoName", r.Name).Msg("ListImages ListRepoTags")
				continue
			}

			for _, t := range tags {
				if t.Name == "" || t.Digest == "" {
					logging.GetLogger().Err(err).Str("project", v.Name).Str("repoName", r.Name).Str("tag", t.Name).Msg("ListImages ListRepoTags has no name or digest")
					continue
				}
				// pull manifest v2
				manifestV1, manifestV2, configBlob, err := h.GetManifest(r.Name, t)
				image := h.makeImage(r.Name, t, manifestV1, manifestV2, configBlob)

				if err != nil {
					if err := extender.UpdateImageLastSyncExtender(ctx, image); err != nil {
						logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", t.Digest).Msg("UpdateImageLastSyncExtender")
					}

					retryImage := warehouse.Image{RegistryID: h.config.RegistryID, Repository: v.Name, Tag: t.Name, Message: err.Error()}
					if err := extender.CreateOrAddRetryCountExtender(ctx, retryImage); err != nil {
						logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", t.Digest).Msg("CreateOrAddRetryCountExtender")
					}

					logging.GetLogger().Err(err).Str("project", v.Name).Str("repoName", r.Name).Str("tag", t.Name).Msg("ListImages GetManifest")
					continue
				}

				cnt++
				im, err := extender.CreateImageExtender(ctx, image)
				if err != nil {
					res.HasErr = true
					logging.GetLogger().Err(err).Str("imageName", fmt.Sprintf("%s:%s", image.Repository, image.Tag)).Msg("ListImages CreateImageExtender")

					retryImage := warehouse.Image{RegistryID: h.config.RegistryID, Repository: v.Name, Tag: t.Name, Message: err.Error()}
					if err := extender.CreateOrAddRetryCountExtender(ctx, retryImage); err != nil {
						logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", t.Digest).Msg("CreateOrAddRetryCountExtender")
					}

					continue
				}
				if req.NeedToReturnAll {
					res.All = append(res.All, im.All...)
				}
				if req.NeedToReturnAdded {
					res.Added = append(res.Added, im.Added...)
				}

			} // end of for artifacts
		} // end of for repos
	}
	logging.GetLogger().Info().Msgf("harborV1 List images count:%d", cnt)

	return res, nil
}

func (h *HarborV1) Ping() error {
	if err := h.registryClient.Ping(); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	if _, err := h.ListProjectsWithPage(1, DefaultPageSize); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}

	return nil
}

func (h *HarborV1) DeleteImages(projectName, repoName, digest string) error {
	panic("not implement")
}

// CreateProject 创建project
func (h *HarborV1) CreateProject(projectName string, public bool) error {
	url := fmt.Sprintf("%s/%s/projects", h.config.URL, APIVersion)
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

// CheckProject 检查project是否存在
func (h *HarborV1) CheckProject(projectName string) error {
	url := fmt.Sprintf("%s/%s/projects?project_name=%s", h.config.URL, APIVersion, projectName)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)

	resp, err := h.client.Do(req.WithContext(h.ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(fmt.Sprintf("status code is %d", resp.StatusCode))
	}
	return nil
}

func (h *HarborV1) SupportIncrementalSync(ctx context.Context) bool {
	return true
}

func (h *HarborV1) makeImage(repositoryName string, t Tag, manifestV1, manifestV2, configBlob string) warehouse.Image {

	i := warehouse.Image{
		RegistryUrl:  h.config.URL,
		RegistryID:   h.config.RegistryID,
		ImageDigest:  t.Digest,
		Repository:   repositoryName,
		Tag:          t.Name,
		Size:         t.Size,
		LastPullTime: t.PullTime,
		LastPushTime: t.PushTime,
		Created:      t.Created,
		ManifestV2:   manifestV2,
		ManifestV1:   manifestV1,
		ConfigJSON:   configBlob,
	}
	return i
}

func (h *HarborV1) pullImageManifestV2(repo, digest string) (string, digest.Digest, error) {
	manifest, err := h.registryClient.ManifestV2(repo, digest)
	if err != nil {
		return "", "", err
	}
	manifestJSON, err := manifest.MarshalJSON()
	if err != nil {
		return "", "", err
	}

	return string(manifestJSON), manifest.Config.Digest, nil
}

func (h *HarborV1) pullImageManifestV1(repo, digest string) (string, error) {
	manifest, err := h.registryClient.Manifest(repo, digest)
	if err != nil {
		return "", err
	}
	manifestJSON, err := manifest.MarshalJSON()
	if err != nil {
		return "", err
	}

	return string(manifestJSON), nil
}

func (h *HarborV1) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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
	err := warehouse.Register(imagesec.HarborV1Version, openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init harborV1 error:%v", err)
	}
	logging.GetLogger().Info().Msg("harborV1 dirver register success")
}

func openRegistry(config warehouse.RegistrableComponentConfig) (warehouse.Registry, error) {
	var h HarborV1

	h.ctx = context.Background()

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.GetLogger().Err(err).Msg("harborV1 marshal config")
		return nil, err
	}
	conf := new(Config)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.GetLogger().Err(err).Msg("harborV1 Unmarshal config")
		return nil, err
	}

	// create client to pull harbor repos and tags
	h.config = *conf
	httpClient := http.Client{}
	if h.config.SkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	h.client = &httpClient

	// create client to pull image manifest and config
	r, err := warehouse.NewDockerRegistryClient(h.config.URL, h.config.Username, h.config.Password, h.config.SkipTLSVerify)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("harbor-v1:new registry client err:%v", err)
		return nil, consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	h.registryClient = r

	return &h, nil
}
