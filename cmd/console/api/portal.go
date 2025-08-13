package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	param "github.com/oceanicdev/chi-param"
	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

func (api *api) loginByAuthcode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()

		authCode, _ := param.QueryString(r, "authCode")

		// 通过portal接口验证authCode
		portalUser, err := api.GetPortalUser(authCode)
		if err != nil || portalUser.TensorEmail == "" {
			RespAndLog(w, ctx, LoginError(http.StatusUnauthorized,
				fmt.Errorf("not get portal user: %w", err)))
			return
		}

		// 查询或创建console用户
		consoleUser, err := api.getConsoleUser(ctx, portalUser)
		if err != nil {
			RespAndLog(w, ctx, LoginError(http.StatusInternalServerError,
				fmt.Errorf("用户同步失败: %w", err)))
			return
		}
		logging.Get().Info().Interface("user", consoleUser).Msg("loginByAuthcode")
		// 生成JWT令牌
		tokenString, err := api.issueJWTToken(ctx, consoleUser, r.UserAgent(), false)
		if err != nil {
			RespAndLog(w, ctx, LoginError(http.StatusInternalServerError,
				fmt.Errorf("令牌生成失败: %w", err)))
			return
		}
		logging.Get().Info().Str("token", tokenString).Msg("issueJWTToken")
		res := LoginResponse{
			Username: consoleUser.UserName,
			Account:  consoleUser.Account,
			Status:   "ok",
			Role:     consoleUser.Role,
			ModuleID: json.RawMessage("[]"),
			Type:     AccountTypePortal,
			Token:    tokenString,
		}
		if consoleUser.ModuleID != "" {
			res.ModuleID = json.RawMessage(consoleUser.ModuleID)
		}
		// 返回登录结果
		response.Ok(w, response.WithItem(res))
	}
}

// 获取或创建用户
func (api *api) getConsoleUser(ctx context.Context, req *portal.User) (*model.User, error) {
	// 尝试查询现有用户
	_, user, err := dal.SelectUserByAccount(ctx, api.rdb.Get(), req.TensorEmail)
	if err == nil && user != nil && user.Account == req.TensorEmail {
		return user, nil
	}

	var modules []model.ModuleGroup
	if err := api.rdb.Get().Find(&modules).Error; err != nil {
		return nil, err
	}
	md := make([]string, 0)
	for _, m := range modules {
		if m.ModuleNameEn == "User Center" {
			continue
		}
		md = append(md, fmt.Sprintf("%d", m.Id))
	}

	err = api.rdb.Get().Transaction(func(tx *gorm.DB) error {
		newu, innerErr := dal.InsertInactiveUser(ctx, tx, req.TensorEmail, model.RoleTypeAdmin, md,
			false, portal.UserAdminName, req.Mobile)
		if innerErr != nil {
			if util.IsPostgresDuplicateError(innerErr) {
				return ErrUserAlreadyExists
			}
			return innerErr
		}
		_, innerErr = dal.ActiveUser(ctx, tx, newu.UserName, model.DefaultPassword, false)
		return innerErr
	})
	if err != nil {
		logging.Get().Error().Err(err).Interface("user", req).Msg("failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	_, user, err = dal.SelectUserByAccount(ctx, api.rdb.Get(), req.TensorEmail)
	if err == nil && user != nil && user.Account == req.TensorEmail {
		return user, nil
	}
	return nil, fmt.Errorf("failed to create user: %w", err)
}

func GetAllModuleGroups(db *gorm.DB) ([]model.ModuleGroup, error) {
	var modules []model.ModuleGroup
	if err := db.Find(&modules).Error; err != nil {
		return nil, err
	}
	return modules, nil
}

func (api *api) GetPortalUser(authCode string) (*portal.User, error) {
	url := fmt.Sprintf("%s/api/v1/user/authCode?authCode=%s", api.PortalURL, authCode)
	logging.Get().Info().Str("url", url).Msg("GetPortalUser")
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		ApiVersion string `json:"apiVersion"`
		Data       struct {
			Status int          `json:"status"`
			Item   *portal.User `json:"item"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	logging.Get().Info().Interface("user", resp.Data.Item).Msg("GetPortalUser")
	us := resp.Data.Item
	if us == nil || us.TensorEmail == "" {
		return nil, fmt.Errorf("user not found")
	}
	return resp.Data.Item, nil
}
