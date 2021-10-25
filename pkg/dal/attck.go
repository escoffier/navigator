package dal

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

func LoadATTCKConfVersion(ctx context.Context, db *gorm.DB) (uint32, error) {
	var data model.ATTCKRuleData
	var err = db.WithContext(ctx).Select("id").Order("id desc").Limit(1).Find(&data).Error
	return data.ID, err
}

func SaveATTCKConfData(ctx context.Context, db *gorm.DB, data *model.ATTCKRuleData, deprecatedRuleMasks []string) (baseOffset uint32, err error) {
	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Create(data).Error; _err != nil {
			return _err
		}

		if len(deprecatedRuleMasks) > 0 {
			if _err := tx.WithContext(ctx).Exec("delete from attck_rule_masks where name in (?)", deprecatedRuleMasks).Error; _err != nil {
				return _err
			}

			if _err := updateRuleMaskVersion(ctx, tx); _err != nil {
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

func UpdateRuleMask(ctx context.Context, db *gorm.DB, addMasks []*model.ATTCKRuleMask, deletedMasks []string) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Exec("delete from attck_rule_masks where name in (?)", deletedMasks).Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(ctx).CreateInBatches(addMasks, 100).Error; _err != nil {
			return _err
		}

		return updateRuleMaskVersion(ctx, tx)
	})
}

func updateRuleMaskVersion(ctx context.Context, db *gorm.DB) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		var conf model.ATTCKRuleMaskVersion
		var _err = tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(&conf).Error
		if _err != nil {
			if _err == gorm.ErrRecordNotFound {
				return tx.WithContext(ctx).Create(&model.ATTCKRuleMaskVersion{Version: 1}).Error
			}
			return _err
		} else {
			return db.WithContext(ctx).Exec("update attck_rule_mask_version set version = version + 1").Error
		}
	})
}
