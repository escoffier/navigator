package codesec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	"gitlab.com/security-rd/go-pkg/logging"
)

type CreateProjectParam struct {
	ProjectBody  Project
	AccessSecret string
	AccessKey    string
}
type DeleteProjectParam struct {
	ProjectUuid  string
	AccessSecret string
	AccessKey    string
}

// Project 定义请求结构体
type Project struct {
	ProjectName          string `json:"projectName,omitempty"`
	Url                  string `json:"url,omitempty"`
	GitType              int    `json:"gitType,omitempty"`              // git类型  1 : gitlab  2 : github  3 : gitee  6 : gerrit  7 : bitbucket
	UrlHead              int    `json:"urlHead,omitempty"`              // git地址是否以https开头 0：否    1：是
	AuthenticationMethod int    `json:"authenticationMethod,omitempty"` // git 认证类型  0.用户名密码认证（默认）  1.token认证 2.SSH密钥  凭据认证
	Token                string `json:"token,omitempty"`
	ProjectDesc          string `json:"projectDesc,omitempty"`
	Branch               string `json:"branch,omitempty"` // 分支名
	Tag                  string `json:"tag,omitempty"`
}

func (s *Project) ConvToMap() map[string]interface{} {
	res := map[string]interface{}{}
	if s.ProjectName != "" {
		res["projectName"] = s.ProjectName
	}
	if s.Url != "" {
		res["url"] = s.Url
	}
	if s.GitType != 0 {
		res["gitType"] = s.GitType
	}
	if s.UrlHead != 0 {
		res["urlHead"] = s.UrlHead
	}
	if s.AuthenticationMethod != 0 {
		res["authenticationMethod"] = s.AuthenticationMethod
	}
	if s.Token != "" {
		res["token"] = s.Token
	}
	if s.ProjectDesc != "" {
		res["projectDesc"] = s.ProjectDesc
	}
	if s.Branch != "" {
		res["branch"] = s.Branch
	}
	if s.Tag != "" {
		res["tag"] = s.Tag
	}
	return res
}

func (s *Project) Serializer() {
	s.ProjectName = strings.TrimSpace(s.ProjectName)
	s.Url = strings.TrimSpace(s.Url)
	s.Token = strings.TrimSpace(s.Token)
	s.AuthenticationMethod = consts.ProjectGitAuthMethodToken
	s.ProjectDesc = strings.TrimSpace(s.ProjectDesc)
	s.Branch = strings.TrimSpace(s.Branch)
}

func (s *Project) Check() error {
	if s.ProjectName == "" {
		return fmt.Errorf("project name is empty")
	}
	if s.Url == "" {
		return fmt.Errorf("project url is empty")
	}
	if s.Token == "" {
		return fmt.Errorf("project token is empty")
	}
	return nil
}

type SpecifiedMember struct {
	UserID         string `json:"userId"`
	RoleID         int    `json:"roleId"`
	PermissionType int    `json:"permissionType,omitempty"`
}

// CreateProjectResponse 定义响应结构体
type CreateProjectResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		ProjectUuid string `json:"projectUuid"` // 项目uuid
		OrgUuid     string `json:"orgUuid"`     // 团队uuid
		AppId       string `json:"appId"`       // 扫描任务 ID
	} `json:"data"`
}

func CreateProject(baseUrl string, param *CreateProjectParam) (*CreateProjectResponse, error) {
	// 定义请求URL
	apiURL := fmt.Sprintf("%s/%s", baseUrl, "cs/api/v4/project/createProjectByGitInfo")
	pro := param.ProjectBody
	pro.Serializer()
	if err := pro.Check(); err != nil {
		return nil, err
	}

	// 将请求体转换为JSON格式
	jsonData, err := json.Marshal(pro)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	data := pro.ConvToMap()
	// 创建HTTP请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	header := utils.BuildV2Header(data, param.AccessKey, param.AccessSecret, nil)

	// 设置自定义请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 解析响应体
	response := &CreateProjectResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Str("url", apiURL).Str("res", string(all)).Msg("Codesec resp")
	if err := json.Unmarshal(all, response); err != nil {
		return nil, err
	}
	if !response.Status {
		return response, fmt.Errorf("create project failed: %s", response.Message)
	}
	return response, nil
}

func UpdateProject(baseUrl string, proUUID string, param *CreateProjectParam) error {
	// 定义请求URL

	apiURL := fmt.Sprintf("%s/cs/api/v4/project/%s/editGitProject", baseUrl, proUUID)
	pro := param.ProjectBody
	pro.Serializer()
	if err := pro.Check(); err != nil {
		return err
	}

	// 将请求体转换为JSON格式
	jsonData, err := json.Marshal(pro)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}
	data := pro.ConvToMap()
	// 创建HTTP请求
	req, err := http.NewRequest(http.MethodPut, apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	header := utils.BuildV2Header(data, param.AccessKey, param.AccessSecret, []string{proUUID})

	// 设置自定义请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// 解析响应体
	response := &CreateProjectResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	logging.Get().Info().Str("url", apiURL).Str("res", string(all)).Msg("Codesec resp")
	if err := json.Unmarshal(all, response); err != nil {
		return err
	}
	if !response.Status {
		return fmt.Errorf("update project failed: %s", response.Message)
	}
	return nil
}
func DeleteProject(baseUrl string, param DeleteProjectParam) (*CreateProjectResponse, error) {
	// 定义请求URL
	apiURL := fmt.Sprintf("%s/cs/api/v4/project/%s/deleteProject", baseUrl, param.ProjectUuid)

	// 创建HTTP请求
	req, err := http.NewRequest(http.MethodDelete, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	header := utils.BuildV2Header(nil, param.AccessKey, param.AccessSecret, []string{param.ProjectUuid})

	// 设置自定义请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 解析响应体
	response := &CreateProjectResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Str("url", apiURL).Str("res", string(all)).Msg("Codesec resp")
	if err := json.Unmarshal(all, response); err != nil {
		return nil, err
	}
	if response.Status {
		return response, nil
	}

	if strings.Contains(response.Message, "项目不存在") {
		return nil, nil
	}
	return nil, fmt.Errorf("delete project failed: %s", response.Message)
}

// git地址是否以https开头
// 0：否    1：是
func urlHead(url string) int {
	if strings.HasPrefix(url, "https://") {
		return 1
	}
	return 0
}

type CodesecProject struct {
	ProjectName          string `json:"projectName"`
	Url                  string `json:"url"`
	GitType              int    `json:"gitType"`              // git类型  1 : gitlab  2 : github  3 : gitee  6 : gerrit  7 : bitbucket
	UrlHead              int    `json:"urlHead,omitempty"`    // git地址是否以https开头 0：否    1：是
	AuthenticationMethod int    `json:"authenticationMethod"` // git 认证类型  0.用户名密码认证（默认）  1.token认证 2.SSH密钥  凭据认证
	Token                string `json:"token"`
}
