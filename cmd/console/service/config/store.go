package config

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrATTCKConfDataNotFound = errors.New("attck conf data not found")
	ErrRuleNotExists         = errors.New("rule not exists")
)

func LoadATTCKConfData(ctx context.Context, db *gorm.DB) (*model.ATTCKRuleData, error) {
	var data model.ATTCKRuleData
	var err = db.WithContext(ctx).Last(&data).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrATTCKConfDataNotFound
		}

		return nil, err
	}

	return &data, nil
}

func SaveATTCKConfData(ctx context.Context, db *gorm.DB, data *model.ATTCKRuleData, deprecatedRuleMasks []string, curOnlineOffset uint32) (baseOffset uint32, err error) {
	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Create(data).Error; _err != nil {
			return _err
		}

		if len(deprecatedRuleMasks) > 0 {
			if _err := tx.WithContext(ctx).Exec("delete from attck_rule_masks where name in (?)", deprecatedRuleMasks).Error; _err != nil {
				return _err
			}

			if _err := updateRuleMaskVersion(ctx, tx, curOnlineOffset); _err != nil {
				return _err
			}
		}

		return nil
	})

	return data.ID, err
}

func LoadATTCKRuleMaskVersion(ctx context.Context, db *gorm.DB) (version uint32, err error) {
	var record model.ATTCKRuleMaskVersion
	err = db.WithContext(ctx).Find(&record).Error
	return record.Version, err
}

func LoadATTCKRuleMasks(ctx context.Context, db *gorm.DB) ([]*model.ATTCKRuleMask, error) {
	var records []*model.ATTCKRuleMask
	var err = db.WithContext(ctx).Find(&records).Error
	return records, err
}

func LoadATTCKConfVersions(ctx context.Context, db *gorm.DB, offset, limit int) (int64, []*model.ATTCKConfVersion, error) {
	var records []*model.ATTCKConfVersion
	var err = db.WithContext(ctx).Model(&model.ATTCKRuleData{}).
		Select("version, username, created_at").
		Order("id desc").Offset(offset).Limit(limit).Find(&records).Error
	if err != nil {
		return 0, nil, err
	}

	var total int64
	err = db.WithContext(ctx).Model(&model.ATTCKRuleData{}).Count(&total).Error
	return total, records, err
}

func UpdateRuleMask(ctx context.Context, db *gorm.DB, addMasks []*model.ATTCKRuleMask, deletedMasks []string, curOnlineOffset uint32) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Exec("delete from attck_rule_masks where name in (?)", deletedMasks).Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(ctx).CreateInBatches(addMasks, 100).Error; _err != nil {
			return _err
		}

		return updateRuleMaskVersion(ctx, tx, curOnlineOffset)
	})
}

func updateRuleMaskVersion(ctx context.Context, db *gorm.DB, curOnlineOffset uint32) (err error) {
	if curOnlineOffset == 0 {
		return db.WithContext(ctx).Create(&model.ATTCKRuleMaskVersion{
			Version: 1,
		}).Error
	}
	return db.WithContext(ctx).Exec("update attck_rule_mask_version set version = ? + 1", curOnlineOffset).Error
}
