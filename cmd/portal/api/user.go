package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/token"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type UserAPI struct {
	userService  service.UserService
	tokenManager token.Manager
}

func NewUserAPI(userService service.UserService) *UserAPI {
	return &UserAPI{userService: userService}
}

// 注册用户
func (u *UserAPI) CreateUser(ctx *gin.Context) {
	req := &model.User{}
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	req.Serialize()

	if err := u.userService.CreateUser(ctx, req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// 登录用户
func (u *UserAPI) LoginUser(ctx *gin.Context) {
	req := &model.User{}
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	res, err := u.userService.LoginUser(ctx, req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(res))
}

func (u *UserAPI) UpdateUser(ctx *gin.Context) {
	req := &model.User{}
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	userID := util.GetInt64FromQuery(ctx, "id")
	param := model.UpdateUserParam{
		ID:      userID,
		Updater: req.ToUpdater(),
	}
	if err := u.userService.UpdateUser(ctx, param); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (u *UserAPI) GetUser(ctx *gin.Context) {
	authCode := util.GetKeywordFromQuery(ctx, "authCode")
	userID := util.GetInt64FromQuery(ctx, "id")
	if authCode == "" && userID <= 0 {
		response.JSONError(ctx, fmt.Errorf("userID or authCode is required"))
		return
	}

	users, _, err := u.userService.SearchUser(ctx, model.SearchUserParam{
		ID:       userID,
		AuthCode: authCode,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(users) == 0 {
		response.JSONError(ctx, fmt.Errorf("not fond user"))
		return
	}
	response.JSONOK(ctx, response.WithItem(users[0]))
}

func (u *UserAPI) SearchUser(ctx *gin.Context) {
	mobile := util.GetKeywordFromQuery(ctx, "mobile")
	email := util.GetKeywordFromQuery(ctx, "email")
	name := util.GetKeywordFromQuery(ctx, "name")
	filter := imagesec.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)
	users, cnt, err := u.userService.SearchUser(ctx, model.SearchUserParam{
		Name:        name,
		Mobile:      mobile,
		PortalEmail: email,
		Filter:      filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	for i := range users {
		users[i].Pwd = ""
		users[i].PwdString = ""
		users[i].SourceCheckPwd = ""
		users[i].CodesecPwd = ""
		users[i].TensorPwd = ""
	}

	response.JSONOK(ctx, response.WithItems(users),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (u *UserAPI) GetUserAuthCode(ctx *gin.Context) {
	userID := util.GetInt64FromQuery(ctx, "id")
	email := util.GetKeywordFromQuery(ctx, "portalEmail")
	if userID <= 0 && email == "" {
		response.JSONError(ctx, fmt.Errorf("userID or portalEmail is required"))
		return
	}
	code, err := u.userService.GetUserAuthCode(ctx, model.SearchUserParam{ID: userID, PortalEmail: email})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := model.AuthCode{
		AuthCode: code,
		UserID:   userID,
	}
	response.JSONOK(ctx, response.WithItem(res))
}

func (u *UserAPI) DeleteUser(ctx *gin.Context) {
	userID := util.GetInt64FromQuery(ctx, "id")
	if userID == 0 {
		response.JSONError(ctx, fmt.Errorf("userID is required"))
		return
	}
	if err := u.userService.DeleteUser(ctx, userID); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx)
}

func (u *UserAPI) ResetPasswd(ctx *gin.Context) {
	req := &ChangePasswdReq{}
	id := util.GetInt64FromQuery(ctx, "id")
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if id <= 0 && req.Id > 0 {
		id = req.Id
	}
	if req.Id == 0 {
		response.JSONError(ctx, fmt.Errorf("id is required"))
		return
	}

	us := &model.User{}
	// 查询当前用户是否是管理员
	p := token.GetPayload(ctx)
	if p.Role != model.UserRoleAdmin {
		response.JSONError(ctx, fmt.Errorf("have no permission"))
		return
	}
	// 校验管理员的密码
	user, _, err := u.userService.SearchUser(ctx, model.SearchUserParam{PortalEmail: p.PortalEmail})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(user) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get admin user"))
		return
	}
	ad := user[0]
	if ad.Pwd != us.EncryptPwd(req.Pwd) {
		response.JSONError(ctx, portalI18.NotCorrectPwd(fmt.Errorf("password error")))
		return
	}
	// 生成随机密码
	pwd := utils.GenerateRandomPwd(12)

	up := map[string]interface{}{
		"pwd": us.EncryptPwd(pwd),
	}
	param := model.UpdateUserParam{
		ID:      id,
		Updater: up,
	}
	if err := u.userService.UpdateUser(ctx, param); err != nil {
		response.JSONError(ctx, err)
		return
	}
	req.Pwd = pwd
	response.JSONOK(ctx, response.WithItem(req))
}

func (u *UserAPI) CheckPasswd(ctx *gin.Context) {
	req := &ChangePasswdReq{}
	id := util.GetInt64FromQuery(ctx, "id")
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if id <= 0 && req.Id > 0 {
		id = req.Id
	}
	if req.Id == 0 {
		response.JSONError(ctx, fmt.Errorf("id is required"))
		return
	}
	user, _, err := u.userService.SearchUser(ctx, model.SearchUserParam{ID: id})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(user) == 0 {
		response.JSONError(ctx, portalI18.NotGetUser(fmt.Errorf("id:%d", id)))
		return
	}
	// 验证密码是否正确
	us := user[0]
	if us.Pwd != us.EncryptPwd(req.Pwd) {
		response.JSONError(ctx, portalI18.NotCorrectPwd(fmt.Errorf("password error")))
		return
	}

	response.JSONOK(ctx)
}

func (u *UserAPI) ChangePasswd(ctx *gin.Context) {
	p := token.GetPayload(ctx)
	if p.ID <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get user"))
		return
	}
	req := &ChangePasswdReq{}
	id := util.GetInt64FromQuery(ctx, "id")
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if req.NewPwd1 != req.NewPwd2 || req.NewPwd1 == "" {
		response.JSONError(ctx, fmt.Errorf("new pwd not equal"))
		return
	}

	user, _, err := u.userService.SearchUser(ctx, model.SearchUserParam{ID: p.ID})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(user) == 0 {
		e := portalI18.NotGetUser(fmt.Errorf("not get user"))
		response.JSONError(ctx, e)
		return
	}
	us := &model.User{}
	if user[0].Pwd != us.EncryptPwd(req.OldPwd) {
		e := portalI18.NotCorrectPwd(fmt.Errorf("old pwd incorrect"))
		response.JSONError(ctx, e)
		return
	}
	up := map[string]interface{}{
		"pwd": us.EncryptPwd(req.NewPwd1),
	}
	param := model.UpdateUserParam{
		ID:      id,
		Updater: up,
	}
	if err := u.userService.UpdateUser(ctx, param); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx)
}

type ChangePasswdReq struct {
	Id      int64  `json:"id"`      // 用户 ID
	Pwd     string `json:"pwd"`     // 管理员重置密码时使用
	OldPwd  string `json:"oldPwd"`  // 旧密
	NewPwd1 string `json:"newPwd1"` // 新密码1
	NewPwd2 string `json:"newPwd2"` // 新密码2
}
