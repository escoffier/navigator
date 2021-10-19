package dal

import (
	"context"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func CreateLdapGroup(ctx context.Context, db *gorm.DB, group *model.LdapGroup) error {
	return db.WithContext(ctx).Create(group).Error
}

func DeleteLdapGroup(ctx context.Context, db *gorm.DB, id int32) error {
	return db.WithContext(ctx).Delete(&model.LdapGroup{}, id).Error
}

func UpdateLdapGroup(ctx context.Context, db *gorm.DB, group *model.LdapGroup) error {
	return db.WithContext(ctx).Select("*").Updates(group).Error
}

func GetLdapGroupByName(ctx context.Context, db *gorm.DB, name string) (*model.LdapGroup, error) {
	var group model.LdapGroup
	var err = db.WithContext(ctx).Where("name = ?", name).First(&group).Error
	return &group, err
}

func CheckLdapGroupExists(ctx context.Context, db *gorm.DB, id int32) (bool, error) {
	var count int64
	var err = db.WithContext(ctx).Model(&model.LdapGroup{}).Where("id = ?", id).Count(&count).Error
	return count == 1, err
}

func GetLdapGroupList(ctx context.Context, db *gorm.DB, offset, limit int) ([]*model.LdapGroup, error) {
	var groups []*model.LdapGroup
	var err = db.WithContext(ctx).Order("id").Offset(offset).Limit(limit).Find(&groups).Error
	return groups, err
}

func GetLdapGroupCount(ctx context.Context, db *gorm.DB) (int64, error) {
	var count int64
	var err = db.WithContext(ctx).Model(&model.LdapGroup{}).Count(&count).Error
	return count, err
}
