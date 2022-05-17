package harborv2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	registry2 "github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	APIVersion          = "api/v2.0"
	DefaultPageSize int = 100
)

type HarborV2 struct {
	ctx            context.Context
	client         *http.Client // client for pull harbor repos and tags
	config         Config
	registryClient *registry2.Registry // client for pull manifest
}

func (h *HarborV2) reqHarbor(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}
	req.SetBasicAuth(h.config.Username, h.config.Password)
	var resp *http.Response
	resp, err = h.client.Do(req.WithContext(h.ctx))

	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
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
		logging.GetLogger().Err(err).Msg("reqHarbor")
		return nil, err
	}

	return bys, nil
}

func (h *HarborV2) ListProjects() ([]Project, error) {
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
	// 过滤了被删除的镜像
	ans := make([]Project, 0)
	for i := range projects {
		if projects[i].Deleted {
			continue
		}
		ans = append(ans, projects[i])
	}

	// logging.GetLogger().Info().Msgf("repos %+v",repos)
	return ans, nil
}

func (h *HarborV2) ListProjectsWithPage(page, pageSize int) ([]Project, error) {
	url := fmt.Sprintf("%s/%s/projects?page=%d&page_size=%d", h.config.URL, APIVersion, page, pageSize)
	// logging.GetLogger().Info().Msgf("req harbor projects url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor projects err")
		return nil, err
	}

	var projects []Project
	if err := json.Unmarshal(data, &projects); err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor projects err %v", err)
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor projects body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("projects %+v",projects)
	return projects, nil
}

func (h *HarborV2) ListProjectRepos(project string) ([]Repository, error) {
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

func (h *HarborV2) ListProjectReposWithPage(project string, page, pageSize int) ([]Repository, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories?page=%d&page_size=%d", h.config.URL, APIVersion, project, page, pageSize)
	//	logging.GetLogger().Info().Msgf("req harbor repo url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor repos err")
		return nil, err
	}

	var repos []Repository
	if err := json.Unmarshal(data, &repos); err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor projects err %v", err)
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor repos body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("repos %+v",repos)
	return repos, nil
}

func (h *HarborV2) ListRepoArtifacts(project, repo string) ([]Artifact, error) {
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

func (h *HarborV2) ListRepoArtifactsWithPage(project, repo string, page, pageSize int) ([]Artifact, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d", h.config.URL, APIVersion, project, repo, page, pageSize)
	//	logging.GetLogger().Info().Msgf("req harbor repo artifacts url %s", url)

	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor repo artifacts err")
		return nil, err
	}

	var artifacts []Artifact
	if err := json.Unmarshal(data, &artifacts); err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor projects err %v", err)
		return nil, fmt.Errorf(fmt.Sprintf("decode harbor artifacts body err.%v", err.Error()))
	}

	// logging.GetLogger().Info().Msgf("artifacts %v",artifacts)
	return artifacts, nil
}

func (h *HarborV2) ListAuditLogWithPage(ops string, time string, page int, pageSize int) ([]AuditLog, error) {
	url := fmt.Sprintf("%s/%s/audit-logs?q=operation=%s,op_time=%s&page=%d&page_size=%d", h.config.URL, APIVersion, ops, time, page, pageSize)
	url = strings.ReplaceAll(url, " ", "%20")
	logging.GetLogger().Info().Str("url", url).Msg("ListAuditLogWithPage")
	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor auditLog err")
		return nil, err
	}
	var auditLog []AuditLog
	if err := json.Unmarshal(data, &auditLog); err != nil {
		logging.GetLogger().Err(err).Msg("unmarshal harbor auditLog")
		return nil, fmt.Errorf("decode harbor auditLog body err.%v", err)
	}
	return auditLog, nil
}

func (h *HarborV2) ListAuditLog(op []string, startAt, endAt int64) ([]AuditLog, error) {
	if startAt <= 0 || endAt > time.Now().Unix() {
		return nil, fmt.Errorf("startAt:%d,endAt:%d error", startAt, endAt)
	}

	ops := "{"
	for k := range op {
		if k != 0 {
			ops += " "
		}
		ops += op[k]
	}
	ops += "}"
	page := 1
	var auditLogs []AuditLog
	cz := time.FixedZone("CST", 0)
	utcTime := fmt.Sprintf("[%s~%s]", time.Unix(startAt, 0).In(cz).Format("2006-01-02 15:04:05"), time.Unix(endAt, 0).In(cz).Format("2006-01-02 15:04:05"))

	logging.GetLogger().Info().Msgf("utcTime is %s", utcTime)
	for {
		a, err := h.ListAuditLogWithPage(ops, utcTime, page, DefaultPageSize)
		if err != nil {
			return auditLogs, err
		}
		auditLogs = append(auditLogs, a...)
		if len(a) < DefaultPageSize {
			break
		}
		page++
	}
	return auditLogs, nil
}

func (h *HarborV2) ReqSpecialArtifact(project string, repo string, tag string) (Artifact, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s", h.config.URL, APIVersion, project, repo, tag)
	logging.GetLogger().Debug().Str("url", url).Msg("ReqSpecialArtifact")
	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor Artifact err")
		return Artifact{}, err
	}
	var artifact Artifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		logging.GetLogger().Err(err).Msgf("unmarshal harbor artifact err %v", err)
		return Artifact{}, fmt.Errorf("decode harbor artifact body err.%v", err.Error())
	}
	return artifact, nil
}

func (h *HarborV2) ParseImage(image string) (string, string, string) {

	tagIndex := strings.LastIndex(image, ":")
	if tagIndex == -1 {
		return "", "", ""
	}
	repoIndex := strings.Index(image, "/")
	if repoIndex == -1 {
		return "", "", ""
	}
	return image[0:repoIndex], image[repoIndex+1 : tagIndex], image[tagIndex+1:]
}

func (h *HarborV2) ImageRetry(ctx context.Context, extender registry.Extender, req registry.ImageRetryRequest) (*registry.ListImagesRes, error) {
	if extender.CreateOrAddRetryCountExtender == nil || extender.CreateImageExtender == nil || extender.DeleteImageRetryExtender == nil {
		return nil, fmt.Errorf("not get CreateOrAddRetryCountExtender or CreateImageExtender or DeleteImageRetryExtender")
	}

	res := new(registry.ListImagesRes)
	images := req.RetryImages
	for k := range images {
		image := images[k]
		preImage := registry.Image{
			RegistryID: image.RegistryID,
			Repository: image.FullRepoName,
			Tag:        image.Tag,
		}

		index := strings.Index(image.FullRepoName, "/")
		project := image.FullRepoName[:index]
		repo := image.FullRepoName[index+1:]
		a, err := h.ReqSpecialArtifact(project, repo, image.Tag)
		if err != nil {
			preImage.Message = err.Error()
			if err := extender.CreateOrAddRetryCountExtender(ctx, preImage); err != nil {
				logging.GetLogger().Err(err).Msg("CreateOrAddRetryCountExtender")
			}
			continue
		}
		manifestV1, manifestV2, configBlob, err := h.GetManifest(image.FullRepoName, a)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("harbor V2 ImageRetry GetManifest error project:%v repo:%v tag:%v", project, repo, image.Tag)
			preImage.Message = err.Error()
			rErr := extender.CreateOrAddRetryCountExtender(ctx, preImage)
			if rErr != nil {
				logging.GetLogger().Err(err).Msg("CreateOrAddRetryCountExtender")
			}
			continue
		}
		nowTag := Tag{Name: images[k].Tag}
		for i := range a.Tags {
			if a.Tags[i].Name == nowTag.Name {
				nowTag.PushTime = a.Tags[i].PushTime
				nowTag.PullTime = a.Tags[i].PullTime
			}
		}

		i := h.makeImage(repo, a, nowTag, manifestV1, manifestV2, configBlob)

		// do some extend stuff
		im, err := extender.CreateImageExtender(ctx, i)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("harbor V2 ImageRetry insert image_list error project:%v repo:%v tag:%v", project, repo, image.Tag)
			preImage.Message = err.Error()
			rErr := extender.CreateOrAddRetryCountExtender(ctx, preImage)
			if rErr != nil {
				logging.GetLogger().Err(err).Msg("CreateOrAddRetryCountExtender")
			}
			continue
		}
		if err := extender.DeleteImageRetryExtender(ctx, preImage); err != nil {
			logging.GetLogger().Err(err).Msg("DeleteImageRetryExtender")
		}
		res.Added = append(res.Added, im.Added...)
	}
	return res, nil
}

func (h *HarborV2) GetManifest(fullRepoName string, a Artifact) (string, string, string, error) {
	var (
		manifestV2   string
		manifestV1   string
		configBlob   string
		configDigest digest.Digest
	)

	manifestV2, configDigest, err := h.pullImageManifestV2(fullRepoName, a.Digest)
	if err == nil {
		// pull config json
		configBlob, err = h.pullConfigBlob(fullRepoName, configDigest)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ListImages get config blob err, repo %s ,digest %s", fullRepoName, a.Digest)
			return "", "", "", err
		}
	} else {
		// pull manifest v2 err,try v1
		//	logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, r.Name, a.Digest)
		manifestV1, err = h.pullImageManifestV1(fullRepoName, a.Digest)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ListImages get manifest (both v1,v2) err %v, repo %s ,digest %s", err, fullRepoName, a.Digest)
			return "", "", "", err
		}
	}
	return manifestV1, manifestV2, configBlob, nil
}

func (h *HarborV2) SupportIncrementalSync(ctx context.Context) bool {
	return true
}

func (h *HarborV2) ListImagesWithAuditLog(ctx context.Context, extender registry.Extender, req registry.ListImagesAuditLog) (*registry.ListImagesRes, error) {
	if extender.CreateOrAddRetryCountExtender == nil || extender.CreateImageExtender == nil || extender.DeleteImageRetryExtender == nil {
		return nil, fmt.Errorf("not get CreateOrAddRetryCountExtender or CreateImageExtender or DeleteImageRetryExtender")
	}
	res := new(registry.ListImagesRes)
	mpCreate := make(map[string]struct{})
	auditLogs, err := h.ListAuditLog([]string{"create"}, req.StartAt, req.EndAt) // 由于v2的接口delete给的是digest，而查digest需要tag，被删除的返回镜像返回的是404
	if err != nil {
		res.GetAuditLogError = true
		return nil, err
	}

	for _, v := range auditLogs {
		if v.ResourceType == "artifact" {
			mpCreate[v.Resource] = struct{}{}
		}
	}
	for k := range mpCreate {
		logging.GetLogger().Info().Msgf("ListImagesWithAuditLog req specialArtifact :%v", k)
		project, repo, tag := h.ParseImage(k)
		a, err := h.ReqSpecialArtifact(project, repo, tag)
		regImage := registry.Image{Repository: project + "/" + repo, Tag: tag, RegistryID: h.config.RegistryID}
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("Get special artifact error maybe image not in registry :%v %v %v", project, repo, tag)
			rErr := extender.CreateOrAddRetryCountExtender(ctx, regImage)
			if rErr != nil {
				logging.GetLogger().Err(rErr).Msgf("harbor V2 ListImagesWithAuditLog GetManifest error FullRepoName:%v tag:%v", project+"/"+repo, tag)
			}
			continue
		}

		manifestV1, manifestV2, configBlob, err := h.GetManifest(project+"/"+repo, a)
		if err != nil {
			rErr := extender.CreateOrAddRetryCountExtender(ctx, regImage)
			if rErr != nil {
				logging.GetLogger().Err(rErr).Msgf("harbor V2 ListImagesWithAuditLog GetManifest error FullRepoName:%v tag:%v", project+"/"+repo, tag)
			}
			continue
		}

		var useTag Tag
		for _, v := range a.Tags { // 取到当前tag 这里有优化空间
			if v.Name == tag {
				useTag = v
				break
			}
		}
		i := h.makeImage(project+"/"+repo, a, useTag, manifestV1, manifestV2, configBlob)

		im, err := extender.CreateImageExtender(ctx, i)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ListImages HarborV2 Insert imagelist error %v", err)
			rErr := extender.CreateOrAddRetryCountExtender(ctx, regImage)
			if rErr != nil {
				logging.GetLogger().Err(rErr).Msgf("harbor V2 ListImagesWithAuditLog GetManifest error FullRepoName:%v tag:%v", project+"/"+repo, tag)
			}
			continue
		}
		res.Added = append(res.Added, im.Added...)
	}
	return res, nil
}

func (h *HarborV2) ListImages(ctx context.Context, extender registry.Extender, req registry.ListImagesRequest) (*registry.ListImagesRes, error) {
	if extender.CreateImageExtender == nil || extender.CreateOrAddRetryCountExtender == nil {
		return nil, fmt.Errorf("not get CreateImageExtender or CreateOrAddRetryCountExtender")
	}
	res := new(registry.ListImagesRes)
	cnt := 0
	// get all projects
	projects, err := h.ListProjects()
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListImages.ListProjects")
		return nil, err
	}

	// get all repos
	for _, v := range projects {
		repos, err := h.ListProjectRepos(v.Name)
		if err != nil {
			// just log and try next project
			logging.GetLogger().Err(err).Msgf("ListImages project %s get repo err,try next project.", v.Name)
			continue
		}

		// get all artifacts in repo
		for _, r := range repos {
			// repo name like 'library/xxx',we only need 'xxx'
			index := strings.Index(r.Name, "/")
			tmp := r.Name[index+1:]
			if index == -1 {
				logging.GetLogger().Error().Msgf("ListImages repo %s format err", r.Name)
				continue
			}
			repoName := tmp
			project := r.Name[:index]
			artifacts, err := h.ListRepoArtifacts(v.Name, repoName)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("ListImages repo %s get artifacts err,try next repo.", r.Name)
				continue
			}

			for _, a := range artifacts {
				// pull manifest v2
				retryImage := registry.Image{
					RegistryID: h.config.RegistryID,
					Repository: r.Name,
				}

				manifestV1, manifestV2, configBlob, err := h.GetManifest(project+"/"+repoName, a)
				if err != nil {
					for _, tag := range a.Tags {
						retryImage.Tag = tag.Name
						retryImage.Message = err.Error()

						if err := extender.CreateOrAddRetryCountExtender(ctx, retryImage); err != nil {
							logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", a.Digest).Msg("CreateOrAddRetryCountExtender")
						}
					}

					logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", a.Digest).Msg("harbor V2 ListImages GetManifest")
					continue
				}

				for _, t := range a.Tags {
					i := h.makeImage(r.Name, a, t, manifestV1, manifestV2, configBlob)

					// do some extend stuff
					im, err := extender.CreateImageExtender(ctx, i)
					if err != nil {
						logging.GetLogger().Err(err).Msgf("ListImages HarborV2 Insert imagelist")
						retryImage.Tag = t.Name
						retryImage.Message = err.Error()

						if err := extender.CreateOrAddRetryCountExtender(ctx, retryImage); err != nil {
							logging.GetLogger().Err(err).Str("FullRepoName", r.Name).Str("Digest", a.Digest).Msg("CreateOrAddRetryCountExtender")
						}

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
			} // end of for artifacts
		} // end of for repos
	}
	logging.GetLogger().Info().Msgf("harborV2 List images count:%d", cnt)

	return res, nil
}

func (h *HarborV2) Ping() error {
	if err := h.registryClient.Ping(); err != nil {
		return consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	return nil
}

func (h *HarborV2) GetImage(projectName, repoName, tag string) (*registry.Image, error) {
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s", h.config.URL, APIVersion, projectName, repoName, tag)
	// logging.GetLogger().WithContext(h.ctx).Infof(fmt.Sprintf("getImage url:%s", url))
	data, err := h.reqHarbor(url)
	if err != nil {
		logging.GetLogger().Err(err).Msg("req harbor repo artifacts err")
		return nil, err
	}

	var artifact Artifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		logging.GetLogger().Err(err).Msgf("req harbor projects err %v", err)
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
			logging.GetLogger().Err(err).Msgf("get config blob err, repo %s ,digest %s", fullRepoNeme, artifact.Digest)
		}
	} else {
		manifestV1, err = h.pullImageManifestV1(fullRepoNeme, artifact.Digest)
		if err != nil {
			msg := fmt.Sprintf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, fullRepoNeme, artifact.Digest)
			logging.GetLogger().Err(err).Msg(msg)
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
		ConfigJSON:   configBlob,
	}
	return img, nil
}

func (h *HarborV2) DeleteImages(projectName, repoName, digest string) error {
	panic("not implement")
}

// CreateProject 创建project
func (h *HarborV2) CreateProject(projectName string, public bool) error {
	url := fmt.Sprintf("%s/%s/projects", h.config.URL, APIVersion)
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

// CheckProject 检查project是否存在
func (h *HarborV2) CheckProject(projectName string) error {
	url := fmt.Sprintf("%s/%s/projects?project_name=%s", h.config.URL, APIVersion, projectName)
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

func (h *HarborV2) makeImage(repositoryName string, a Artifact, t Tag, manifestV1, manifestV2, configBlob string) registry.Image {
	i := registry.Image{
		ImageDigest:  a.Digest,
		Repository:   repositoryName,
		Tag:          t.Name,
		Size:         a.Size,
		Created:      a.ExtraAttrs.Created,
		LastPullTime: t.PullTime,
		LastPushTime: t.PushTime,
		RegistryUrl:  h.config.URL,
		RegistryID:   h.config.RegistryID,
		FromType:     h.config.UseType,
		ManifestV1:   manifestV1,
		ManifestV2:   manifestV2,
		ConfigJSON:   configBlob,
	}
	return i
}

func (h *HarborV2) pullImageManifestV2(repo, digest string) (string, digest.Digest, error) {
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

func (h *HarborV2) pullImageManifestV1(repo, digest string) (string, error) {
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

func (h *HarborV2) pullConfigBlob(repo string, configDigest digest.Digest) (string, error) {
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
	err := registry.Register(consts.HarborV2Version, openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init harborV2 error")
	}
	logging.GetLogger().Info().Msg("harborV2 dirver register success")
}

func openRegistry(config registry.RegistrableComponentConfig) (registry.Registry, error) {
	var h HarborV2

	h.ctx = context.Background()
	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.GetLogger().Err(err).Err(err).Msg("harborV2 marshal config")
		return nil, err
	}
	conf := new(Config)

	if err := json.Unmarshal(byt, conf); err != nil {
		logging.GetLogger().Err(err).Err(err).Msg("harborV2 Unmarshal config")
		return nil, err
	}

	// create client to pull harbor repos and tags
	httpClient := http.Client{}
	h.config = *conf
	if h.config.SkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	h.client = &httpClient

	// create client to pull image manifest and config
	r, err := registry.NewDockerRegistryClient(h.config.URL, h.config.Username, h.config.Password, h.config.SkipTLSVerify)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("harbor-v2:new registry client err:%v", err)
		return nil, consts.ErrNotConnectOrWrongUsernameOrPasswd
	}
	h.registryClient = r
	return &h, nil
}
