package harbor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go"
	jsoniter "github.com/json-iterator/go"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const AUTOSCANCNDESCRIBE = "当镜像上传后，自动进行扫描漏洞"
const AUTOSCANENDESCRIBE = "Automatically scan for vulnerabilities when the image is uploaded"
const TRUSTCNDESCRIBE = "仅允许部署通过认证的镜像"
const TRUSTENDESCRIBE = "Only certified images are allowed to be deployed"
const PREVENTVULCNDESCRIBE = "阻止潜在漏洞的镜像被拉取"
const PREVENTVULENDESCRIBE = "Prevent images of potential vulnerabilities from being pulled"
const PUBLICCNDESCRIBE = "所有人都可访问公开的项目仓库。"
const PUBLICENDESCRIBE = "Everyone can access the public project repository."
const RESPITEM = "respItem"

type HarborRESTClient struct {
	address          string // like "https://localhost:30003"
	username         string
	password         string
	skipTLSVerify    bool
	apiVersionString string
	respItemCache    *cache.Cache
	httpCli          *http.Client
}

func NewHarborRESTClient(ctx context.Context, harborOpts *flag.HarborOpts) (*HarborRESTClient, error) {
	h := &HarborRESTClient{
		address:          harborOpts.URL,
		username:         harborOpts.Username,
		password:         harborOpts.Password,
		skipTLSVerify:    harborOpts.SkipTLSVerify,
		apiVersionString: "api/v2.0",
		respItemCache:    cache.New(24*time.Hour, 24*time.Hour),
	}
	httpClient := http.Client{}
	if h.skipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	h.httpCli = &httpClient
	return h, nil
}

type harborHTTPSubError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type harborHTTPErrorResp struct {
	Errors []harborHTTPSubError `json:"errors"`
}

func (h HarborRESTClient) ScanAll(ctx context.Context) error {
	// Example curl request:
	// curl -X POST -u tensorsec:Tensorsec123 -H "Content-type: application/json" -k -i -d '{"schedule": {"type": "Manual"}}'  https://localhost:30003/api/%s/system/scanAll/schedule

	type ScheduleType struct {
		Type string `json:"type"`
	}

	type ScheduleReq struct {
		Schedule ScheduleType `json:"schedule"`
	}

	// "Type: "Manual"" is not docummented in Harbor's API doc (v2.0), but it is
	// sent by Harbor portal when pressing "Scan all" button.
	payload := ScheduleReq{Schedule: ScheduleType{Type: "Manual"}}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal scan all request to Harbor: %w", err))
	}

	url := fmt.Sprintf("%s/%s/system/scanAll/schedule", h.address, h.apiVersionString)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare scan all request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send scan all request to Harbor: %w", err))
		}

		// Harbor's API doc doesn't mention 201 return code, but it is returned
		// to Harbor portal upon pressing "Scan all" button.
		// Just in case, we assume both 200 and 201 status codes are OK.
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {

			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = json.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				log.Error().Err(err).Str("rawBody", rawBodyBuf.String()).Msgf("Failed to decode error message from Harbor")
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
			}

			if resp.StatusCode == http.StatusUnauthorized {
				return NewHarborUnauthorizedError(resp.StatusCode, fmt.Errorf("Harbor API returned status Unauthorized: %+v", errorResp))
			} else if resp.StatusCode == http.StatusForbidden {
				return NewHarborForbiddenError(resp.StatusCode, fmt.Errorf("Harbor API returned status Forbidden: %+v", errorResp))
			} else if resp.StatusCode == http.StatusConflict {
				// 409 is documented as "harbor scan already in progress", 412 is undocumented
				return NewHarborScanAllInProgressError(resp.StatusCode, fmt.Errorf("Harbor scan already in progress: %+v", errorResp))
			} else if resp.StatusCode == http.StatusServiceUnavailable {
				return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error, potentially no scanners detected: %+v", errorResp))
			} else {
				return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
			}
		}
		return nil
	}
	return util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
}

func (h HarborRESTClient) GetScanAllStatus(ctx context.Context) (ScanAllStatus, error) {
	var scanAllStatus ScanAllStatus

	// if URL suddenly is wrong, they possibly changed it to /scans/schedule/metrics
	url := fmt.Sprintf("%s/%s/scans/all/metrics", h.address, h.apiVersionString)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return scanAllStatus, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare get scan all status request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	// function for how to handle response or error
	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send get scan all status request to Harbor: %w", err))
		}
		if resp.StatusCode != http.StatusOK {
			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = json.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				log.Error().Err(err).Str("rawBody", rawBodyBuf.String()).Msgf("Failed to decode error message from Harbor")
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
			}
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
		}

		err = json.NewDecoder(resp.Body).Decode(&scanAllStatus)
		if err != nil {
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode message from Harbor: %w", err))
		}
		return nil
	}
	err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))

	return scanAllStatus, err
}

func (h HarborRESTClient) ScanOne(ctx context.Context, projectName, repositoryName, tag string) error {
	//v2 :/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan
	//v1 :/api/repositories/docker_contenttrust/myshop/tags/v1/scan
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s/scan", h.address, h.apiVersionString, projectName, repositoryName, tag)
	if h.apiVersionString == "api" {
		url = fmt.Sprintf("%s/%s/repositories/%s/%s/tags/%s/scan", h.address, h.apiVersionString, projectName, repositoryName, tag)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(nil))
	if err != nil {
		return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("failed to prepare scan all request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewHarborError(http.StatusInternalServerError, fmt.Errorf("request harbor scanone error: %v.", err))
		}
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = jsoniter.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				return NewFieldError(http.StatusInternalServerError, fmt.Errorf("failed to decode error message from Harbor: %w", err))
			}

			if resp.StatusCode == http.StatusUnauthorized {
				return NewHarborUnauthorizedError(http.StatusInternalServerError, fmt.Errorf("harbor API returned status Unauthorized: %+v", errorResp))
			} else if resp.StatusCode == http.StatusForbidden {
				return NewHarborForbiddenError(http.StatusInternalServerError, fmt.Errorf("harbor API returned status Forbidden: %+v", errorResp))
			} else if resp.StatusCode == http.StatusConflict {
				return NewHarborScanAllInProgressError(http.StatusInternalServerError, fmt.Errorf("harbor scan already in progress: %+v", errorResp))
			} else if resp.StatusCode == http.StatusServiceUnavailable {
				return NewHarborError(http.StatusInternalServerError, fmt.Errorf("harbor API returned error, potentially no scanners detected: %+v", errorResp))
			} else {
				return NewHarborError(http.StatusInternalServerError, fmt.Errorf("harbor API returned error: %+v", errorResp))
			}
		}
		return nil
	}

	return util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
}

func (h HarborRESTClient) ScanOneStatus(ctx context.Context, projectName, repositoryName, tag, digest string) (time.Time, string, error) {
	// v2: /api/v2.0/projects/docker_contenttrust/repositories/myshop/artifacts/v1?with_scan_overview=t
	// v1: /api/repositories/docker_contenttrust/myshop/tags/v1
	if digest == "" {
		digest = tag
	}
	url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s?with_scan_overview=true", h.address, h.apiVersionString, projectName, repositoryName, digest)
	if h.apiVersionString == "api" {
		url = fmt.Sprintf("%s/%s/repositories/%s/%s/tags/%s", h.address, h.apiVersionString, projectName, repositoryName, tag)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return time.Now(), "", NewConnectionError(http.StatusInternalServerError, fmt.Errorf("failed to send get scan all status request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	var scanOneStatus ScanOneStatus
	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewHTTPResponseError(http.StatusInternalServerError, fmt.Errorf("failed to send get scan all status request to Harbor: %w", err))
		}
		if resp.StatusCode != http.StatusOK {
			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = jsoniter.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("failed to decode error message from Harbor: %+v", err))
			}
			return NewHarborError(http.StatusInternalServerError, fmt.Errorf("harbor API returned error: %+v", errorResp))
		}
		result, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return NewFieldError(http.StatusInternalServerError, fmt.Errorf("failed to readall  message from body: %w", err))
		}
		err = jsoniter.Unmarshal(result, &scanOneStatus)
		if err != nil {
			return NewFieldError(http.StatusInternalServerError, fmt.Errorf("json Unmarshal error: %w", err))
		}
		if scanOneStatus.ScanOverview.Version.ScanStatus == "" {
			scanOneStatus.ScanOverview.Version.ScanStatus = "not_scan"
		}
		return nil
	}
	err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
	if err != nil {
		return time.Now(), "", err
	}

	return scanOneStatus.ScanOverview.Version.EndTime, scanOneStatus.ScanOverview.Version.ScanStatus, nil
}

func (h HarborRESTClient) GetHarborScanResultsLink(ctx context.Context, fullRepoName, shaDigest, tag string) (string, error) {

	// if fullRepoName == tensorsecns/tensorsec-console then returns something like https://localhost:30003/harbor/projects/2/repositories/tensorsec-console/artifacts/sha256:ebf90b1ae8550ec6962e070344c857cf4a510477eadaf83988bae043156c4465
	// if fullRepoName == library/ccc/dddd then returns something like https://registry.tensorsecurity.cn/harbor/projects/1/repositories/ccc%2Fdddd/artifacts/sha256:fb73cb48778e98f59eb2857e028c9e97efb26862a109ff885a8a8402baa75e14
	projectNameRepoName := strings.SplitN(fullRepoName, "/", 2)
	projectName := projectNameRepoName[0]
	repoName := projectNameRepoName[1]
	repoName = strings.ReplaceAll(repoName, "/", "%2F")

	respitem, ok := h.respItemCache.Get(RESPITEM)
	if ok {
		r, ok := respitem.([]RespItemT)
		if ok {
			for _, item := range r {
				if item.Name == projectName {
					if h.apiVersionString == "api" {
						return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/%s/tags/%s", h.address, item.ProjectID, item.Name, repoName, tag), nil
					}
					return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s", h.address, item.ProjectID, repoName, shaDigest), nil
				}
			}
		}
	}

	respItems, _, err := h.GetHarborProject(ctx)
	if err != nil {
		return "", HarborGetProgressError(http.StatusInternalServerError, fmt.Errorf("Get project in Harbor error:%+v", err))
	}

	for _, item := range respItems {
		if item.Name == projectName {
			h.respItemCache.Set(RESPITEM, respItems, -1)
			if h.apiVersionString == "api" {
				return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/%s/tags/%s", h.address, item.ProjectID, item.Name, repoName, tag), nil
			}
			return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s", h.address, item.ProjectID, repoName, shaDigest), nil
		}
	}

	log.Error().
		Str("respItems", fmt.Sprintf("%+v", respItems)).
		Str("projectName", fmt.Sprintf("%+v", projectName)).
		Str("repoName", fmt.Sprintf("%+v", repoName)).
		Msgf("Didn't match project")

	return "", NewHarborForbiddenError(http.StatusInternalServerError, fmt.Errorf("Didn't find such project in Harbor, get item error"))
}

func (h HarborRESTClient) GetHarborFullScanConfigURL() string {
	return fmt.Sprintf("%s/harbor/interrogation-services/vulnerability", h.address)
}

func (h HarborRESTClient) GetHarborProjectConfig(ctx context.Context, projectId int) ([]model.CfgScan, error) {
	var projectConfig model.ProjectCfg
	cfgScanData := make([]model.CfgScan, 0)
	url := fmt.Sprintf("%s/%s/projects/%d", h.address, h.apiVersionString, projectId)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return cfgScanData, NewAnError(http.StatusInternalServerError, fmt.Errorf("failed to prepare get projects request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("failed to send get projects config request to Harbor: %w", err))
		}
		defer util.CloseBodyWithLog(resp.Body)

		if resp.StatusCode != http.StatusOK {
			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = jsoniter.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
			}
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
		}
		err = json.NewDecoder(resp.Body).Decode(&projectConfig)

		if err != nil {
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode message from Harbor: %w", err))
		}
		return nil
	}
	err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
	if err != nil {
		return cfgScanData, err
	}

	//set Describe
	cfgScanData = append(cfgScanData, model.CfgScan{RuleName: "Public", RuleDescEn: PUBLICENDESCRIBE, RuleDescCn: PUBLICCNDESCRIBE, Status: projectConfig.Metadata.Public, HarborConfigLink: h.GetHarborProjectConfigLink(projectId)})
	cfgScanData = append(cfgScanData, model.CfgScan{RuleName: "AutoScan", RuleDescEn: AUTOSCANENDESCRIBE, RuleDescCn: AUTOSCANCNDESCRIBE, Status: projectConfig.Metadata.AutoScan, HarborConfigLink: h.GetHarborProjectConfigLink(projectId)})
	cfgScanData = append(cfgScanData, model.CfgScan{RuleName: "EnableContentTrust", RuleDescEn: TRUSTENDESCRIBE, RuleDescCn: TRUSTCNDESCRIBE, Status: projectConfig.Metadata.EnableContentTrust, HarborConfigLink: h.GetHarborProjectConfigLink(projectId)})
	cfgScanData = append(cfgScanData, model.CfgScan{RuleName: "PreventVul", RuleDescEn: PREVENTVULENDESCRIBE, RuleDescCn: PREVENTVULCNDESCRIBE, Status: projectConfig.Metadata.PreventVul, HarborConfigLink: h.GetHarborProjectConfigLink(projectId)})

	return cfgScanData, nil
}

func (h HarborRESTClient) GetHarborProjectConfigLink(projectId int) string {
	return fmt.Sprintf("%sharbor/projects/%d/configs", h.address, projectId)
}

func (h *HarborRESTClient) TestConnectionAndAdminPrivileges(ctx context.Context, canDowngrade bool) error {
	// GET /users endpoint requires admin role, so let's try to use it

	url := fmt.Sprintf("%s/%s/users", h.address, h.apiVersionString)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare get users request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	respHandle := func(resp *http.Response, err error) error {
		if err != nil {
			return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send get users request to Harbor: %w", err))
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusNotFound && canDowngrade {
				h.apiVersionString = "api"
				canDowngrade = false
				log.Warn().Err(err).Msgf("Harbor connectivity check got 404, will try to downgrade API version")
				return h.TestConnectionAndAdminPrivileges(ctx, canDowngrade)
			}

			var errorResp harborHTTPErrorResp
			var rawBodyBuf bytes.Buffer
			teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
			err = json.NewDecoder(teeReader).Decode(&errorResp)
			if err != nil {
				log.Error().Err(err).Str("rawBody", rawBodyBuf.String()).Msgf("Failed to decode error message from Harbor")
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
			}

			if resp.StatusCode == http.StatusUnauthorized {
				return NewHarborUnauthorizedError(resp.StatusCode, fmt.Errorf("Harbor API returned status Unauthorized: %+v", errorResp))
			} else if resp.StatusCode == http.StatusForbidden {
				return NewHarborForbiddenError(resp.StatusCode, fmt.Errorf("Harbor API returned status Forbidden: %+v", errorResp))
			} else {
				return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
			}
		}
		return nil
	}
	return util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
}

func (h HarborRESTClient) GetHarborProject(ctx context.Context) ([]RespItemT, string, error) {
	var (
		respItems []RespItemT
		page      = 1
		loop      = true
	)

	for loop {
		url := fmt.Sprintf("%s/%s/projects?page="+strconv.Itoa(page)+"&page_size=100", h.address, h.apiVersionString)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare get projects request to Harbor: %+v", err))
		}
		req.SetBasicAuth(h.username, h.password)

		respHandle := func(resp *http.Response, err error) error {
			if err != nil {
				return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send get projects request to Harbor: %+v", err))
			}
			if resp.StatusCode != http.StatusOK {
				var errorResp harborHTTPErrorResp
				var rawBodyBuf bytes.Buffer
				teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
				err = json.NewDecoder(teeReader).Decode(&errorResp)
				if err != nil {
					log.Error().Err(err).Str("rawBody", rawBodyBuf.String()).Msgf("Failed to decode error message from Harbor:%+v", err)
					return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
				}

				return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
			}
			var respItemsTmp []RespItemT
			err = json.NewDecoder(resp.Body).Decode(&respItemsTmp)
			if err != nil {
				return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode message from Harbor: %w", err))
			}
			respItems = append(respItems, respItemsTmp...)
			if len(respItemsTmp) < 100 {
				loop = false
			} else {
				page++
			}
			return nil
		}
		err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
		if err != nil {
			return nil, "", err
		}
	}

	return respItems, h.address, nil
}

func (h HarborRESTClient) GetRepositories(ctx context.Context, rest []RespItemT) ([]Repositories, error) {
	//api/v2.0/projects/tensorsecurity/repositories?page_size=15&page=1 v2
	//api/repositories?page=1&page_size=15&project_id=2 v1
	var repositoriesSlice []Repositories
	var err error

	for _, v := range rest {
		var (
			page = 1
			loop = true
		)
		for loop {
			url := fmt.Sprintf("%s/%s/projects/%s/repositories?page="+strconv.Itoa(page)+"&page_size=100", h.address, h.apiVersionString, v.Name)
			if h.apiVersionString == "api" {
				url = fmt.Sprintf("%s/%s/repositories?page="+strconv.Itoa(page)+"&page_size=100&project_id=%d", h.address, h.apiVersionString, v.ProjectID)
			}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				logging.GetLogger().Error().Msgf("Failed to repositories get projects request to Harbor: %w", err)
				loop = false
				continue

			}
			req.SetBasicAuth(h.username, h.password)

			respHandle := func(resp *http.Response, err error) error {
				if err != nil {
					logging.GetLogger().Error().Msgf("Failed to send get repositories request to Harbor: %w", err)
					loop = false
					return err
				}
				if resp.StatusCode != http.StatusOK {
					var errorResp harborHTTPErrorResp
					var rawBodyBuf bytes.Buffer
					teeReader := io.TeeReader(resp.Body, &rawBodyBuf)
					err = json.NewDecoder(teeReader).Decode(&errorResp)
					if err != nil {
						logging.GetLogger().Error().Msgf("Failed to decode error message from Harbor:%+w", err)
						loop = false
						return err
					}
					logging.GetLogger().Error().Msgf("Harbor API returned error: %+v", errorResp)
					loop = false
					return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
				}
				var repos []Repositories

				err = json.NewDecoder(resp.Body).Decode(&repos)
				if err != nil {
					logging.GetLogger().Error().Msgf("Failed to decode message from Harbor: %w", err)
					loop = false
					return err
				}

				repositoriesSlice = append(repositoriesSlice, repos...)
				if len(repos) < 100 {
					loop = false
				} else {
					page++
				}
				return nil
			}
			err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
			if err != nil {
				return repositoriesSlice, err
			}

		}
	}
	return repositoriesSlice, err
}

func (h HarborRESTClient) GetAllArtifacts(ctx context.Context, repo []Repositories) (model.Artifacts, error) {
	var artifactsSlice model.Artifacts

	for _, v := range repo {
		var (
			page = 1
			loop = true
		)
		for loop {
			resp := v.Name[:strings.Index(v.Name, "/")]
			repo := v.Name[strings.Index(v.Name, "/")+1:]

			frepo := strings.Replace(repo, "/", "%252F", -1)

			url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts?with_tag=true&with_scan_overview=true&with_label=true&page="+strconv.Itoa(page)+"&page_size=100", h.address, h.apiVersionString, resp, frepo)
			if h.apiVersionString == "api" {
				//https://152.136.147.241:8443/api/repositories/tensorsecurity/faulty/tags?detail=true
				url = fmt.Sprintf("%s/%s/repositories/%s/tags?detail=true", h.address, h.apiVersionString, v.Name)
				loop = false
			}

			req, err := http.NewRequest("GET", url, nil)

			if err != nil {
				logging.GetLogger().Error().Msgf("Failed to repositories get projects request to Harbor: %w", err)
				loop = false
				continue
			}
			req.SetBasicAuth(h.username, h.password)

			respHandle := func(response *http.Response, err error) error {
				if err != nil {
					logging.GetLogger().Error().Msgf("Failed to send get repositories request to Harbor: %w", err)
					loop = false
					return err
				}

				if response.StatusCode != http.StatusOK {
					var errorResp harborHTTPErrorResp
					var rawBodyBuf bytes.Buffer
					teeReader := io.TeeReader(response.Body, &rawBodyBuf)
					err = json.NewDecoder(teeReader).Decode(&errorResp)
					if err != nil {
						logging.GetLogger().Error().Msgf("Failed to decode error message from Harbor:%+w", err)
						loop = false
						return err
					}
					logging.GetLogger().Error().Msgf("Harbor API returned error: %+v", errorResp)
					loop = false
					return NewHarborError(response.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
				}

				if h.apiVersionString != "api" { //v2
					var artif []model.Artifacts2
					err = json.NewDecoder(response.Body).Decode(&artif)
					if err != nil {
						logging.GetLogger().Error().Msgf("Failed to decode message from Harbor: %w", err)
						loop = false
						return err
					}
					for i := range artif {
						artif[i].FullRepoName = v.Name
					}
					artifactsSlice.Af2 = append(artifactsSlice.Af2, artif...)
					if h.apiVersionString != "api" {
						if len(artif) < 100 {
							loop = false
						} else {
							page++
						}
					}
				} else {
					var artif []model.Artifacts1

					err = json.NewDecoder(response.Body).Decode(&artif)
					if err != nil {
						logging.GetLogger().Error().Msgf("Failed to decode message from Harbor: %w", err)
						loop = false
						return err
					}
					for i := range artif {
						artif[i].FullRepoName = v.Name
					}
					artifactsSlice.Af1 = append(artifactsSlice.Af1, artif...)
				}
				return nil
			}
			err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
			if err != nil {
				return artifactsSlice, err
			}
		}
	}

	return artifactsSlice, nil

}

func (h HarborRESTClient) GetOneArtifacts(fullRepoName string) (model.Artifacts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	var (
		page           = 1
		loop           = true
		artifactsSlice model.Artifacts
	)

	for loop {
		projectNameRepoName := strings.SplitN(fullRepoName, "/", 2)
		projectName := projectNameRepoName[0]
		repoName := projectNameRepoName[1]
		repoName = strings.ReplaceAll(repoName, "/", "%2F")

		url := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts?with_tag=true&with_scan_overview=true&with_label=true&?page="+strconv.Itoa(page)+"&page_size=100", h.address, h.apiVersionString, projectName, repoName)
		if h.apiVersionString == "api" {
			//https://152.136.147.241:8443/api/repositories/tensorsecurity/faulty/tags?detail=true
			url = fmt.Sprintf("%s/%s/repositories/%s/tags?detail=true", h.address, h.apiVersionString, fullRepoName)
			loop = false
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logging.GetLogger().Error().Msgf("Failed to repositories get projects request to Harbor: %w", err)
			loop = false
			break
		}
		req.SetBasicAuth(h.username, h.password)

		respHandle := func(response *http.Response, err error) error {
			if err != nil {
				logging.GetLogger().Error().Msgf("Failed to send get repositories request to Harbor: %w", err)
				loop = false
				return err
			}

			if response.StatusCode != http.StatusOK {
				var errorResp harborHTTPErrorResp
				var rawBodyBuf bytes.Buffer
				teeReader := io.TeeReader(response.Body, &rawBodyBuf)
				err = json.NewDecoder(teeReader).Decode(&errorResp)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("Failed to decode error message from Harbor")
					loop = false
					return err
				}
				logging.GetLogger().Error().Msgf("Harbor API returned error: %+v", errorResp)
				loop = false
				return NewHarborError(response.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
			}

			if h.apiVersionString != "api" { //v2
				var artif []model.Artifacts2
				err = json.NewDecoder(response.Body).Decode(&artif)
				if err != nil {
					logging.GetLogger().Error().Msgf("Failed to decode message from Harbor: %w", err)
					loop = false
					return err
				}
				for i := range artif {
					artif[i].FullRepoName = fullRepoName
				}
				artifactsSlice.Af2 = append(artifactsSlice.Af2, artif...)
				if h.apiVersionString != "api" {
					if len(artif) < 100 {
						loop = false
					} else {
						page++
					}
				}
			} else {
				var artif []model.Artifacts1

				err = json.NewDecoder(response.Body).Decode(&artif)
				if err != nil {
					logging.GetLogger().Error().Msgf("Failed to decode message from Harbor: %w", err)
					loop = false
					return err
				}
				for i := range artif {
					artif[i].FullRepoName = fullRepoName
				}
				artifactsSlice.Af1 = append(artifactsSlice.Af1, artif...)
			}
			return nil
		}
		err = util.HTTPRequest(ctx, h.httpCli, req, respHandle, retry.Attempts(3))
		if err != nil {
			return artifactsSlice, err
		}

	}
	return artifactsSlice, nil
}

func (h HarborRESTClient) GetApiVersionString() string {
	return h.apiVersionString
}

func (h HarborRESTClient) GetAddressString() string {
	return h.address
}
