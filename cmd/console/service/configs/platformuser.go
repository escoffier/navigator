package configs

import (
	"context"
	"encoding/json"

	"gorm.io/gorm/clause"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
)

// platform user
type UserOperator struct {
	rdb *databases.RDBInstance
}

type exportUserInfo struct {
	UserName        string         `json:"userName"`
	Account         string         `json:"account"`
	Nickname        string         `json:"nickname"`
	Pwd             string         `json:"pwd"`
	Salt            string         `json:"salt"`
	Role            model.RoleType `json:"role"`
	ModuleID        string         `json:"moduleId"`
	CreatedAt       int64          `json:"createdAt"`
	Creator         string         `json:"creator"`
	Platform        string         `json:"platform"`
	Status          int            `json:"status"`
	MustChangePwd   bool           `json:"mustChangePwd"`
	LastChangePwdAt int64          `json:"lastChangePwdAt"`
	MfaSecret       string         `json:"mfaSecret"`
	MfaStatus       bool           `json:"mfaStatus"`
}

// Export 导出
func (u *UserOperator) Export(ctx context.Context) ([]byte, error) {
	users := make([]*model.User, 0)
	err := u.rdb.GetReadDB().WithContext(ctx).Find(&users).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("gets all users failed")
		return nil, err
	}

	configs := make([]exportUserInfo, len(users))
	for i, v := range users {
		configs[i] = exportUserInfo{
			UserName:        v.UserName,
			Account:         v.Account,
			Nickname:        v.Nickname,
			Pwd:             v.Pwd,
			Salt:            v.Salt,
			Role:            v.Role,
			ModuleID:        v.ModuleID,
			CreatedAt:       v.CreatedAt,
			Creator:         v.Creator,
			Platform:        v.Platform,
			Status:          v.Status,
			MustChangePwd:   v.MustChangePwd,
			LastChangePwdAt: v.LastChangePwdAt,
			MfaSecret:       v.MfaSecret,
			MfaStatus:       v.MfaStatus,
		}
	}

	return json.Marshal(configs)
}

// Import 导入
func (u *UserOperator) Import(ctx context.Context, config []byte) error {
	configs := make([]*exportUserInfo, 0)

	err := json.Unmarshal(config, &configs)
	if err != nil {
		logging.Get().Error().Err(err).
			Str("rowJson", string(config)).Msg("json unmarshal failed")
		return err
	}

	users := make([]*model.User, len(configs))
	for i, v := range configs {
		users[i] = &model.User{
			UserName:        v.UserName,
			Account:         v.Account,
			Nickname:        v.Nickname,
			Pwd:             v.Pwd,
			Salt:            v.Salt,
			Role:            v.Role,
			ModuleID:        v.ModuleID,
			CreatedAt:       v.CreatedAt,
			Creator:         v.Creator,
			Platform:        v.Platform,
			Status:          v.Status,
			MustChangePwd:   v.MustChangePwd,
			LastChangePwdAt: v.LastChangePwdAt,
			MfaSecret:       v.MfaSecret,
			MfaStatus:       v.MfaStatus,
		}
	}

	if err = u.rdb.Get().WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account"}},
		DoNothing: true,
	}).CreateInBatches(&users, 500).Error; err != nil {
		logging.Get().Error().Err(err).Msg("")
	}

	return err
}
func (u *UserOperator) SetAperator(username string) {
}
