package sourceCheck

import (
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
)

type GetTokenReq struct {
	Title          string `json:"title"`
	ExpirationTime int64  `json:"expirationTime"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type GetTokenResp struct {
	Status int `json:"status"`
	Data   struct {
		ExpirationTime int64  `json:"expirationTime"`
		Token          string `json:"token"`
		TokenUuid      string `json:"tokenUuid"`
	} `json:"data"`
	Msg string `json:"msg"`
}

type User struct {
	Email    string `json:"email"`
	LastName string `json:"lastName"`
	Name     string `json:"name"`
	Password string `json:"password"` // 原始密码，不需要加密
}

type Project struct {
	AppUuid string `json:"appUuid,omitempty"`
	AppName string `json:"appName"`
	// ProjectUuid string `json:"projectUuid"` // 创建时不可以传这个值
	Type string `json:"type"` // 只支持 git:1
	// 以下参数非必传
	GitType string `json:"gitType"` // git类型 type是git的时候该字段必输 值为 github/gitlab/gitee
	// gitlab版本 当gitType为gitlab必填 枚举值有   V3、V4 说明：在GitLab 9.0及更高版本中，请选择 API V4版本
	GitlabApiVersion string `json:"gitlabApiVersion"` // 当gitType为gitlab必填 值有：V3， V4
	// GitLabHead  string `json:"gitLabHead"`
	Protocol    string `json:"protocol"`   // 当 Type 是git 是必传， 值是：https,ssh
	GitLabPort  string `json:"gitLabPort"` // 当 protocol 是 ssh时必传,默认22
	PullWay     int    `json:"pullWay"`    // 默认是 2,也就是用 token 拉取代码
	AccessToken string `json:"accessToken"`
	Url         string `json:"url"`
	Branch      string `json:"branch"` // 分支 必传
	GitLabHead  string `json:"gitLabHead"`
}

func (s *Project) Serializer() {
	s.Type = consts.GitTypeGit
	if s.GitlabApiVersion == "" {
		s.GitlabApiVersion = consts.GitlabApiVersionV4
	}
	if s.Protocol == "" {
		s.Protocol = "22"
	}
	s.PullWay = consts.SourceCheckPullWayToken
	s.Url = strings.TrimSpace(s.Url)
	s.Branch = strings.TrimSpace(s.Branch)
}

func (s *Project) Check() error {
	if s.Url == "" {
		return fmt.Errorf("not get url")
	}
	if s.AccessToken == "" { // 修正字段名
		return fmt.Errorf("not get accessToken")
	}
	// if s.Branch == "" { // 补充必传字段校验
	// 	return fmt.Errorf("not get branch")
	// }
	// 根据结构体注释补充其他校验
	if s.Type == consts.GitTypeGit && s.Protocol == "" {
		return fmt.Errorf("protocol is required for git type")
	}
	return nil
}

type CreateProjectResponse struct {
	Status int `json:"status"`
	Data   struct {
		AppUuid string `json:"appUuid"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// HighRiskComponent 高危组件top10
type HighRiskComponent struct {
	ComponentName string `json:"componentName"`
	ComponentId   string `json:"componentId"`
	Grade         int    `json:"grade"`
	GradeName     string `json:"gradeName"`
	// AppVersionId      string `json:"appVersionId"`
	VulNum int `json:"vulNum"`
	// ControlStatus     string `json:"controlStatus"`
	// ControlStatusName string `json:"controlStatusName"`
	// CreateTime        string `json:"createTime"`
}

// MostUsedComponent 被引用最多的组件top10统计数据
type MostUsedComponent struct {
	Value       string `json:"value"`
	Count       int64  `json:"count"`
	Name        string `json:"name"`
	ComponentId string `json:"componentId"`
}

type LicenseStat struct {
	Label  string `json:"label"`
	Value  int    `json:"value"`
	Number int    `json:"number"`
}

type StatisticsRequest struct {
	ProjectTagIds []string `json:"projectTagIds,omitempty"`
	DepSources    []string `json:"depSources,omitempty"`
	StartTime     string   `json:"startTime,omitempty"`
	EndTime       string   `json:"endTime,omitempty"`
	Type          string   `json:"type,omitempty"`
	ProjectFlag   string   `json:"projectFlag"`
}

// ShareAppRequest 应用分享请求参数
type ShareAppRequest struct {
	AppUuid  string `json:"appUuid"`  // 应用UUID
	UserUuid string `json:"userUuid"` // 用户UUID
	Auth     string `json:"auth"`
}

type BaseResponse struct {
	Msg    string `json:"msg"`
	Status int64  `json:"status"`
}
