package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/codesec"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/config"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/sourceCheck"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/token"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type UserService interface {
	CreateUser(ctx context.Context, user *portal.User) error
	LoginUser(ctx context.Context, user *portal.User) (*portal.LoginResponse, error)
	UpdateUser(ctx context.Context, up portal.UpdateUserParam) error
	DeleteUser(ctx context.Context, userID int64) error
	SearchUser(ctx context.Context, param portal.SearchUserParam) ([]*portal.User, int64, error)
	GetUserAuthCode(ctx context.Context, param portal.SearchUserParam) (string, error)
}

type userService struct {
	authCodes      map[string]int64 // 授权码存储
	mu             sync.RWMutex     // 保护 authCodes 的并发访问
	tokenManager   token.Manager
	userStore      store.UserDal
	codesecURL     string
	sourceCheckRUL string

	Log *scannerUtils.LogEvent
}

func NewUserService(userStore store.UserDal) UserService {
	s := &userService{
		authCodes:      map[string]int64{},
		mu:             sync.RWMutex{},
		tokenManager:   token.NewJWTTokenManager(userStore),
		userStore:      userStore,
		codesecURL:     config.GetConfig().CodeSec.Addr,
		sourceCheckRUL: config.GetConfig().SourceCheck.Addr,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("User"),
			scannerUtils.WithSubModule("user"),
		),
	}
	// 把管理员写入进去
	_ = s.CreateAdminUser(context.Background())

	return s
}

// CreateUser
// sourceCheck 需要用企业管理员的权限去创建用户，创建的用户是普通用户，用这个用户去新建项目之后，之个项目就只在这个用户权限下展示
// 当然如是登录是企业管理员权限，他可以查看所有项目。
// codesec 要用企业管理员的权限去创建用户，创建的用户是团队管理员的角色，
// 创建项目时，需要使用团队管理员的权限去创建项目。
func (s *userService) CreateUser(ctx context.Context, data *portal.User) error {
	// 查询当前用户是否是管理员
	p := token.GetPayload(ctx)
	if p.Role != portal.UserRoleAdmin {
		return portalI18.NotHasPermission(fmt.Errorf("not has permission"))
	}

	data.Status = portal.UserNormal
	data.Pwd = data.EncryptPwd(data.PwdString)
	data.Role = portal.UserRoleOperator
	data.CodesecPwd = data.PwdString
	data.SourceCheckPwd = data.PwdString

	if err := data.Check(); err != nil {
		return err
	}
	//  创建用户时先去数据库查询，如果用户名和邮箱存在，则提示用户已经存在
	users, _, err := s.userStore.SearchUser(ctx, portal.SearchUserParam{Status: portal.UserNormal})
	if err != nil {
		s.Log.Err(err).Msg("search user")
		return portalI18.UserUsernameExit(err)
	}
	for _, u := range users {
		if u.PortalEmail == data.PortalEmail {
			return portalI18.UserEmailExit(fmt.Errorf("user exit"))
		}
		if u.Name == data.Name {
			return portalI18.UserUsernameExit(fmt.Errorf("user exit"))
		}
	}

	// 向sourceCheck注册用户()
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	createUserReq1 := sourceCheck.User{
		Email:    data.PortalEmail,
		LastName: data.Name,
		Name:     data.Name,
		Password: data.SourceCheckPwd, // 原密码,
	}

	if err := api1.CreateUser(ctx, createUserReq1); err != nil {
		s.Log.Err(err).Str("Type", consts.ModelSourceCheck).Msg("can not create user to sourceCheck")
		return err
	}
	param1 := codesec.CreateUserParam{
		User: codesec.User{
			UserName:  data.Name,
			UserEmail: data.PortalEmail,
			Password:  data.PwdString, // 请使用SHA256加密后的密码,
		},

		AccessSecret: config.GetConfig().CodeSec.OrgUser.AccessSecret,
		AccessKey:    config.GetConfig().CodeSec.OrgUser.AccessKey,
	}
	hash := sha256.Sum256([]byte(param1.User.Password))

	signature := hex.EncodeToString(hash[:])
	param1.User.Password = signature

	resp, err := codesec.CreateUser(s.codesecURL, param1)
	if err != nil || resp.Data.AccessKey == "" {
		s.Log.Err(err).Str("Type", consts.ModelCodesec).Msg("can not create user to codesec")
		return err
	}
	data.CodesecSk = resp.Data.AccessKey
	data.CodesecAk = resp.Data.AccessSecret
	s.Log.Info().Interface("user", data).Msg("create user success")
	return nil
}

func (s *userService) LoginUser(ctx context.Context, req *portal.User) (*portal.LoginResponse, error) {
	users, _, err := s.userStore.SearchUser(ctx, portal.SearchUserParam{PortalEmail: req.PortalEmail, Status: portal.UserNormal})
	if err != nil || len(users) == 0 {
		return nil, errors.New("user not found")
	}
	use := users[0]
	after := req.EncryptPwd(req.PwdString)
	if use.Pwd != after {
		return nil, portalI18.NotCorrectPwd(fmt.Errorf("password error"))
	}
	// 现sourceCheck去请求一个 token
	if use.SourceCheckToken == "" {
		// 向sourceCheck注册用户
		api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL))
		p1 := sourceCheck.GetTokenReq{
			Title:          "sourceCheckToken",
			ExpirationTime: time.Now().UnixMilli() + 5*365*24*60*60*1000, // 设置5年的过期时间
			Username:       use.SourceCheckEmail,
			Password:       use.SourceCheckPwd,
		}
		getToken, err := api1.CreateToken(ctx, p1)
		if err != nil || getToken.Data.Token == "" {
			return nil, portalI18.LoginFail(fmt.Errorf("login sourceCheck error"))
		}
		up := map[string]interface{}{
			"source_check_token": getToken.Data.Token,
		}
		use.SourceCheckToken = getToken.Data.Token
		_ = s.userStore.UpdateUser(ctx, portal.UpdateUserParam{ID: use.ID, Updater: up})
	}

	pa := token.Payload{
		ID:               use.ID,
		Mobile:           use.Mobile,
		PortalEmail:      use.PortalEmail,
		Role:             use.Role,
		Status:           use.Status,
		SourceCheckToken: use.SourceCheckToken,
		CodesecKey:       use.CodesecSk,
		CodesecSecret:    use.CodesecAk,
	}
	// 管理token
	to, err := s.tokenManager.IssueTo(pa)
	if err != nil {
		return nil, portalI18.LoginFail(err)
	}
	up := map[string]interface{}{
		"token":        to,
		"token_exp_at": time.Now().Unix() + s.tokenManager.Exp(),
	}
	if err := s.userStore.UpdateUser(ctx, portal.UpdateUserParam{ID: use.ID, Updater: up}); err != nil {
		s.Log.Err(err).Interface("user", use).Msg("can not update user")
		return nil, portalI18.LoginFail(err)
	}

	res := &portal.LoginResponse{
		ID:          use.ID,
		PortalEmail: use.PortalEmail,
		Token:       to,
	}
	s.Log.Info().Interface("user", use).Interface("res", res).Msg("login success")
	return res, nil
}

// UpdateUser 更新用户
func (s *userService) UpdateUser(ctx context.Context, up portal.UpdateUserParam) error {
	if up.ID <= 0 {
		return errors.New("user id is empty")
	}
	users, _, err := s.userStore.SearchUser(ctx, portal.SearchUserParam{ID: up.ID, Status: portal.UserNormal})
	if err != nil || len(users) == 0 {
		return portalI18.NotGetUser(fmt.Errorf("not get user"))
	}

	if err := s.userStore.UpdateUser(ctx, up); err != nil {
		s.Log.Err(err).Int64("UserID", up.ID).Msg("update user")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return portalI18.UserUsernameExit(err)
		}
		return portalI18.UpdateUserFail(err)
	}
	s.Log.Info().Int64("UserID", up.ID).Interface("up", up).Msg("update user success")
	return nil
}

func (s *userService) DeleteUser(ctx context.Context, userID int64) error {
	p := token.GetPayload(ctx)
	if p.Role != portal.UserRoleAdmin {
		return portalI18.NotHasPermission(fmt.Errorf("have no permission to delete user"))
	}

	up := map[string]interface{}{
		"status": portal.UserDeleted,
	}

	err := s.userStore.UpdateUser(ctx, portal.UpdateUserParam{ID: userID, Updater: up})
	if err != nil {
		s.Log.Err(err).Int64("UserID", userID).Msg("Delete user")
		return portalI18.DeleteUserFail(err)
	}
	s.Log.Info().Int64("UserID", userID).Msg("Delete user success")
	return nil
}

func (s *userService) GetUserAuthCode(ctx context.Context, param portal.SearchUserParam) (string, error) {
	use, _, err := s.SearchUser(ctx, param)
	if err != nil || len(use) == 0 {
		return "", portalI18.NotGetUser(fmt.Errorf("user not found"))
	}

	code := utils.GenerateRandomString(32)
	s.setUserCode(use[0].ID, code)
	s.Log.Info().Int64("UserID", use[0].ID).Str("code", code).Msg("get user auth code success")
	return code, nil
}

// 用户列表
func (s *userService) SearchUser(ctx context.Context, param portal.SearchUserParam) ([]*portal.User, int64, error) {
	param.Status = portal.UserNormal

	if param.AuthCode != "" {
		param.ID = s.getUidFromCode(param.AuthCode)
		if param.ID == 0 {
			return nil, 0, fmt.Errorf("not get user")
		}
	}

	user, cnt, err := s.userStore.SearchUser(ctx, param)
	if err != nil {
		s.Log.Err(err).Msg("get user")
		return nil, 0, err
	}
	return user, cnt, nil
}

func (s *userService) CreateAdminUser(ctx context.Context) error {
	cfg := config.GetConfig()
	ad := &portal.User{
		Name:             consts.PortalAdminName,
		PwdString:        cfg.Portal.AdminPassword,
		Role:             portal.UserRoleAdmin,
		PortalEmail:      cfg.Portal.AdminEmail,
		Status:           portal.UserNormal,
		SourceCheckToken: cfg.SourceCheck.OrgUser.Token,
		SourceCheckEmail: cfg.SourceCheck.OrgUser.Email,
		SourceCheckPwd:   cfg.SourceCheck.OrgUser.Password,
		CodesecAk:        cfg.CodeSec.OrgUser.AccessSecret,
		CodesecSk:        cfg.CodeSec.OrgUser.AccessKey,
		CodesecPwd:       cfg.CodeSec.OrgUser.Password,
		CodesecEmail:     cfg.CodeSec.OrgUser.Email,
		TensorEmail:      cfg.Tensor.Email,
		TensorPwd:        cfg.Tensor.Pwd,
	}
	ad.Serialize()
	// 检查是否存在
	users, _, err := s.userStore.SearchUser(ctx, portal.SearchUserParam{PortalEmail: ad.PortalEmail, Status: portal.UserNormal})
	if err != nil {
		s.Log.Err(err).Msg("search admin user")
		return err
	}
	if len(users) > 0 && ad.Same(users[0]) {
		return nil
	}
	// 先删除
	if len(users) > 0 {
		if err := s.userStore.DeleteUser(ctx, users[0].ID); err != nil {
			s.Log.Err(err).Msg("delete admin user")
			return err
		}
	}

	if err := s.userStore.CreateUser(ctx, ad); err != nil {
		s.Log.Err(err).Msg("create admin user")
		return err
	}
	return nil
}

func (s *userService) setUserCode(uid int64, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = uid
}

func (s *userService) getUidFromCode(co string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authCodes[co]
}

func (s *userService) deleteAuthCode(co string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authCodes, co)
}
