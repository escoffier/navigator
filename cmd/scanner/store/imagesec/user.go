package imagesecStore

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type UserDal interface {
	GetUsername(ctx context.Context, username []string) (map[string]string, error)
}

type UserDao struct {
	db *databases.RDBInstance
}

func NewUserDao(db *databases.RDBInstance) *UserDao {
	return &UserDao{db: db}
}

func (dal *UserDao) GetUsername(ctx context.Context, username []string) (map[string]string, error) {
	res := make(map[string]string)
	username = util.DuplicateStringSlice(username)
	if len(username) == 0 {
		return res, nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	us := make([]model.User, 0)
	err := dal.db.Get().WithContext(ctx).Model(&model.User{}).Where("username IN ?", username).Find(&us).Error
	for i := range us {
		res[us[i].UserName] = us[i].Account
	}
	return res, err
}
