package service

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/codesec"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/config"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/sourceCheck"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/token"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	model "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type ProjectService interface {
	SearchProject(ctx context.Context, param model.SearchProjectParam) ([]*model.Project, int64, error)
	CreateProject(ctx context.Context, project *model.Project) error
	UpdateProject(ctx context.Context, id int64, project *model.Project) error
	DeleteProject(ctx context.Context, id int64) error
}

type projectService struct {
	store          store.ProjectStore
	Log            *scannerUtils.LogEvent
	codesecURL     string
	sourceCheckRUL string
}

func NewProjectService(store store.ProjectStore) ProjectService {
	return &projectService{
		store: store,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("Project"),
			scannerUtils.WithSubModule("project")),
		codesecURL:     config.GetConfig().CodeSec.Addr,
		sourceCheckRUL: config.GetConfig().SourceCheck.Addr,
	}
}

func (s *projectService) SearchProject(ctx context.Context, param model.SearchProjectParam) ([]*model.Project, int64, error) {
	p := token.GetPayload(ctx)
	param.UserID = p.ID
	if p.Role == model.UserRoleAdmin {
		param.UserID = 0
	}

	projects, cnt, err := s.store.SearchProject(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("Search projects failed")
		return nil, 0, portalI18.SearchProjectFail(err)
	}
	return projects, cnt, nil
}

// CreateProject
// sourceCheck 需要用企业管理员的权限去创建用户，创建的用户是普通用户，用这个用户去新建项目之后，之个项目就只在这个用户权限下展示
// 当然如是登录是企业管理员权限，他可以查看所有项目。
// codesec 要用企业管理员的权限去创建用户，创建的用户是团队管理员的角色，
// 创建项目时，需要使用团队管理员的权限去创建项目,也就是使用新增加的用户去创建项目。
// codesec 团队管理员可以创建项目
func (s *projectService) CreateProject(ctx context.Context, project *model.Project) error {
	if err := project.Check(); err != nil {
		s.Log.Err(err).Interface("project", project).Msg("Invalid project data")
		return portalI18.CreateProjectFail(err)
	}
	p := token.GetPayload(ctx)
	if p.CodesecKey == "" || p.CodesecSecret == "" || p.SourceCheckToken == "" {
		s.Log.Error().Msg("Invalid codesec key")
		return portalI18.NotLogin(fmt.Errorf("invalid codesec key"))
	}
	//  创建项目时先去数据库查询，如该用户下这个项目名存在，则提示项目已经存在
	projects, _, err := s.store.SearchProject(ctx, model.SearchProjectParam{Name: project.Name, UserID: p.ID})
	if err != nil || len(projects) > 0 {
		s.Log.Err(err).Interface("project", project).Msg("Search projects failed")
		return portalI18.ProjectExit(err)
	}

	param1 := &codesec.CreateProjectParam{
		ProjectBody: codesec.Project{
			ProjectName:          project.Name,
			Url:                  project.Url,
			GitType:              codeSecGitType(project.GitType),
			Token:                project.Token,
			ProjectDesc:          project.Description,
			Branch:               project.Branch,
			AuthenticationMethod: consts.ProjectGitAuthMethodToken,
		},
		AccessSecret: p.CodesecSecret,
		AccessKey:    p.CodesecKey,
	}

	res1, err := codesec.CreateProject(s.codesecURL, param1)
	if err != nil {
		s.Log.Err(err).Interface("param", param1).Msg("Create project failed")
		return portalI18.CreateProjectFail(err)
	}
	project.CodesecUUID = res1.Data.ProjectUuid
	// 向sourceCheck注册用户
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	param2 := &sourceCheck.Project{
		Type:             consts.SourceCheckProjectTypeGit,
		AppName:          project.Name,
		GitType:          GetGitType(project.GitType),
		GitlabApiVersion: GetGitlabVersion(project.GitType),
		Protocol:         GetProtocol(project.Url),
		AccessToken:      project.Token,
		Url:              project.Url,
		Branch:           project.Branch,
		PullWay:          consts.SourceCheckPullWayToken,
		GitLabHead:       project.Url, // 不知道写个啥
	}

	res2, err := api1.CreateProject(ctx, param2)
	if err != nil {
		// 删除codesec项目
		_, err := codesec.DeleteProject(s.codesecURL, codesec.DeleteProjectParam{
			ProjectUuid:  project.CodesecUUID,
			AccessSecret: p.CodesecSecret,
			AccessKey:    p.CodesecKey,
		})
		if err != nil {
			s.Log.Err(err).Interface("codesecUUID", project.CodesecUUID).Msg("create sourceCheck project failed,and  Delete codesec project failed")
		}

		s.Log.Err(err).Interface("param", param2).Msg("Create project failed")
		return portalI18.CreateProjectFail(err)
	}
	project.SourceCheckUUID = res2.Data.AppUuid
	project.UserID = p.ID
	if err := s.store.CreateProject(ctx, project); err != nil {
		s.Log.Err(err).Interface("project", project).Msg("Create project failed")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return portalI18.ProjectExit(err)
		}
		return portalI18.CreateProjectFail(err)
	}
	s.Log.Info().Interface("project", project).Msg("Create project success")
	// 构建分享请求
	sourceCheckConfig := config.GetConfig().SourceCheck
	shareReq := sourceCheck.ShareAppRequest{
		AppUuid:  project.SourceCheckUUID,
		UserUuid: sourceCheckConfig.OrgUser.UserUUID,
		Auth:     "1", // 文档中也没有写是啥意思，不加这个就不得行
	}
	s.Log.Info().Interface("shareReq", shareReq).Msg("Share project request")

	// 调用分享API
	if err := api1.ShareApp(ctx, shareReq); err != nil {
		return fmt.Errorf("share project failed: %w", err)
	}

	s.Log.Info().Interface("shareReq", shareReq).Str("orgUserEmail", sourceCheckConfig.OrgUser.Email).Msg("Project shared to org user successfully")
	return nil
}

// UpdateProject 团队管理员可以自已团队的项目，不能更新其他团队更新项目
func (s *projectService) UpdateProject(ctx context.Context, id int64, project *model.Project) error {

	if err := project.Check(); err != nil {
		s.Log.Err(err).Interface("project", project).Msg("Invalid project data")
		return portalI18.UpdateProjectFail(err)
	}
	p := token.GetPayload(ctx)
	if p.CodesecKey == "" || p.CodesecSecret == "" || p.SourceCheckToken == "" {
		s.Log.Error().Msg("Invalid codesec key")
		return portalI18.NotLogin(fmt.Errorf("invalid codesec key"))
	}
	// if p.Role == model.UserRoleAdmin {
	// return portalI18.NotHasPermission(fmt.Errorf("admin user can not create project"))
	// }
	// 更新 sourceCheck 项目
	proj, _, err := s.SearchProject(ctx, model.SearchProjectParam{ID: id})
	if err != nil {
		s.Log.Err(err).Interface("id", id).Msg("Search projects failed")
		return portalI18.UpdateProjectFail(err)
	}
	if len(proj) == 0 {
		return nil
	}
	pro := proj[0]
	if p.Role != model.UserRoleAdmin && pro.UserID != p.ID {
		return portalI18.NotHasPermission(fmt.Errorf("user has no permission to update project"))
	}

	project.Serialize()

	param1 := &codesec.CreateProjectParam{
		ProjectBody: codesec.Project{
			ProjectName:          project.Name,
			Url:                  project.Url,
			GitType:              codeSecGitType(project.GitType),
			Token:                project.Token,
			ProjectDesc:          project.Description,
			AuthenticationMethod: consts.ProjectGitAuthMethodToken,
			Branch:               project.Branch,
			Tag:                  project.Tag,
		},
		AccessSecret: p.CodesecSecret,
		AccessKey:    p.CodesecKey,
	}

	if err := codesec.UpdateProject(s.codesecURL, pro.CodesecUUID, param1); err != nil {
		s.Log.Err(err).Interface("param", param1).Msg("update project failed")
		return portalI18.UpdateProjectFail(err)
	}

	param2 := &sourceCheck.Project{
		Type:             consts.SourceCheckProjectTypeGit,
		AppName:          project.Name,
		GitType:          GetGitType(project.GitType),
		GitlabApiVersion: GetGitlabVersion(project.GitType),
		Protocol:         GetProtocol(project.Url),
		AccessToken:      project.Token,
		PullWay:          consts.SourceCheckPullWayToken,
		Url:              project.Url,
		Branch:           project.Branch, // 接口文档中只有 branch
		GitLabHead:       project.Url,    // 不知道写个啥
	}
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	if err := api1.UpdateProject(ctx, pro.SourceCheckUUID, param2); err != nil {
		s.Log.Err(err).Interface("param", param2).Msg("Create project failed")
		return portalI18.UpdateProjectFail(err)
	}

	updater := project.ToUpdater()
	err = s.store.UpdateProject(ctx, model.UpdateProjectParam{ID: id, Updater: updater})
	if err != nil {
		s.Log.Err(err).Int64("projectID", id).Interface("updater", updater).Msg("Update project failed")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return portalI18.ProjectExit(err)
		}
		return portalI18.UpdateProjectFail(err)
	}
	s.Log.Info().Int64("projectID", id).Interface("updater", updater).Msg("Update project success")
	return nil
}

func (s *projectService) DeleteProject(ctx context.Context, id int64) error {
	p := token.GetPayload(ctx)
	if p.CodesecKey == "" || p.CodesecSecret == "" {
		s.Log.Error().Msg("Invalid codesec key")
		return portalI18.NotLogin(fmt.Errorf("invalid codesec key"))
	}

	projects, _, err := s.store.SearchProject(ctx, model.SearchProjectParam{ID: id})
	if err != nil {
		s.Log.Err(err).Interface("id", id).Msg("Search projects failed")
		return portalI18.DeleteProjectFail(err)
	}
	if len(projects) == 0 {
		s.Log.Error().Int64("id", id).Msg("Project not found")
		return nil
	}
	pro := projects[0]
	// codesec 只有项目管理员才能操作
	if p.Role != model.UserRoleAdmin && pro.UserID != p.ID {
		return portalI18.NotHasPermission(fmt.Errorf("user has no permission to delete project"))
	}
	param1 := codesec.DeleteProjectParam{
		ProjectUuid:  pro.CodesecUUID,
		AccessSecret: p.CodesecSecret,
		AccessKey:    p.CodesecKey,
	}

	_, err = codesec.DeleteProject(s.codesecURL, param1)
	if err != nil {
		s.Log.Err(err).Interface("param", param1).Msg("Create project failed")
		// return portalI18.DeleteProjectFail(err)
	}

	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	if err := api1.DeleteProject(ctx, pro.SourceCheckUUID); err != nil {
		s.Log.Err(err).Interface("id", id).Msg("Delete project failed")
		// return portalI18.DeleteProjectFail(err)
	}

	if err := s.store.DeleteProject(ctx, id); err != nil {
		s.Log.Err(err).Int64("projectID", id).Msg("Delete project failed")
		return portalI18.DeleteProjectFail(err)
	}
	s.Log.Info().Int64("projectID", id).Msg("Delete project success")

	return nil
}

func codeSecGitType(t string) int {
	switch t {
	case model.GitTypeGitlabV3, model.GitTypeGitlabV4:
		return 1
	case model.GitTypeGitHub:
		return 2
	case model.GitTypeGitee:
		return 3
	}
	return 1
}

func GetGitlabVersion(s string) string {
	switch s {
	case model.GitTypeGitlabV3:
		return consts.GitlabApiVersionV3
	}
	return consts.GitlabApiVersionV4
}
func GetGitType(s string) string {
	switch s {
	case model.GitTypeGitlabV3, model.GitTypeGitlabV4:
		return model.GitTypeGitlab
	case model.GitTypeGitHub:
		return model.GitTypeGitHub
	case model.GitTypeGitee:
		return model.GitTypeGitee
	}
	return model.GitTypeGitlab
}

func GetProtocol(s string) string {
	if strings.Contains(s, "https") {
		return "HTTPS"
	}
	return "SSH"
}
