package store

import (
	"context"
	"fmt"
	"time"

	portal "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
)

type UserDal interface {
	CreateUser(ctx context.Context, user *portal.User) error
	GetUser(ctx context.Context, param portal.SearchUserParam) (*portal.User, error)
	SearchUser(ctx context.Context, param portal.SearchUserParam) ([]*portal.User, int64, error)
	UpdateUser(ctx context.Context, up portal.UpdateUserParam) error
	DeleteUser(ctx context.Context, userID int64) error
	AddUserToConsole(ctx context.Context, user *portal.User) error
}

type UserStore struct {
	db *databases.RDBInstance
}

func NewUserStore(db *databases.RDBInstance) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) GetUser(ctx context.Context, param portal.SearchUserParam) (*portal.User, error) {
	if param.ID <= 0 && param.PortalEmail == "" {
		return nil, fmt.Errorf("not get userID or userEmail")
	}
	pa := portal.SearchUserParam{ID: param.ID, PortalEmail: param.PortalEmail}
	user, _, err := s.SearchUser(ctx, pa)
	if err != nil || len(user) == 0 {
		return nil, fmt.Errorf("not get user:%d,%s", pa.ID, pa.PortalEmail)
	}
	return user[0], nil
}

func (s *UserStore) CreateUser(ctx context.Context, user *portal.User) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := user.Check(); err != nil {
		return err
	}
	user.Serialize()
	if err := s.db.Get().WithContext(timeoutCtx).Create(user).Error; err != nil {
		return err
	}
	return nil
}

func (s *UserStore) SearchUser(ctx context.Context, param portal.SearchUserParam) ([]*portal.User, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	res := make([]*portal.User, 0)
	db := s.db.Get().WithContext(timeoutCtx).Model(new(portal.User))
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.PortalEmail != "" {
		db = db.Where("portal_email LIKE ?", fmt.Sprintf("%%%s%%", param.PortalEmail))
	}
	if param.Mobile != "" {
		db = db.Where("mobile LIKE ?", fmt.Sprintf("%%%s%%", param.Mobile))
	}
	if param.Status != "" {
		db = db.Where("status = ?", param.Status)
	}
	if param.Name != "" {
		db = db.Where("name LIKE ?", fmt.Sprintf("%%%s%%", param.Name))
	}
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesec.AddFilter(db, param.Filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *UserStore) UpdateUser(ctx context.Context, param portal.UpdateUserParam) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if len(param.Updater) == 0 {
		return nil
	}
	db := s.db.Get().WithContext(timeoutCtx).Model(new(portal.User)).Where("id = ?", param.ID)
	if err := db.Updates(param.Updater).Error; err != nil {
		return err
	}
	return nil
}

func (s *UserStore) DeleteUser(ctx context.Context, userID int64) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(timeoutCtx).Model(new(portal.User)).Where("id = ?", userID)
	if err := db.Delete(&model.User{ID: userID}).Error; err != nil {
		return err
	}
	return nil
}

func (s *UserStore) AddUserToConsole(ctx context.Context, user *portal.User) error {

	req := ConsoleAddUser{
		Account: user.TensorEmail,
		Role:    model.RoleTypeAdmin,
		Mobile:  user.Mobile,
	}

	var modules []model.ModuleGroup
	if err := s.db.Get().Find(&modules).Error; err != nil {
		return err
	}
	md := make([]string, 0)
	for _, m := range modules {
		if m.ModuleNameEn == "User Center" {
			continue
		}
		md = append(md, fmt.Sprintf("%d", m.Id))
	}
	err := s.db.Get().Transaction(func(tx *gorm.DB) error {
		newu, innerErr := dal.InsertInactiveUser(ctx, tx, req.Account, req.Role, md, false, portal.UserAdminName, req.Mobile)
		if innerErr != nil {
			if util.IsPostgresDuplicateError(innerErr) {
				return nil
			}
			return innerErr
		}

		_, innerErr = dal.ActiveUser(ctx, tx, newu.UserName, user.TensorPwd, false)
		return innerErr
	})
	return err
}

type ConsoleAddUser struct {
	Account  string         `json:"account" binding:"required,dive,max=32"`
	Role     model.RoleType `json:"role" binding:"required,dive,oneof=admin normal"`
	ModuleID []string       `json:"moduleID"`
	Mobile   string         `json:"mobile"`
}
