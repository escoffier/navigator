package dal

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrATTCKConfDataNotFound = errors.New("attck conf data not found")
	ErrRuleNotExists         = errors.New("rule not exists")
)

func LoadATTCKConfDataByVersion1(ctx context.Context, db *gorm.DB, v uint16) (*model.ATTCKRuleData, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var data model.ATTCKRuleData
	var err = db.WithContext(tctx).Where("version1 = ?", v).Last(&data).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrATTCKConfDataNotFound
		}

		return nil, err
	}

	return &data, nil
}

func LoadATTCKConfData(ctx context.Context, db *gorm.DB) (*model.ATTCKRuleData, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var data model.ATTCKRuleData
	var err = db.WithContext(tctx).Last(&data).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrATTCKConfDataNotFound
		}

		return nil, err
	}

	return &data, nil
}

func LoadATTCKConfVersion(ctx context.Context, db *gorm.DB, v uint16) (uint32, error) {
	var data model.ATTCKRuleData
	var err = db.WithContext(ctx).Select("id").Where("version1 = ?", v).Order("id desc").Limit(1).Find(&data).Error
	return data.ID, err
}

func SaveATTCKConfData(ctx context.Context, db *gorm.DB, data *model.ATTCKRuleData, deprecatedRuleMasks []string, v uint16) (d *model.ATTCKRuleData, err error) {
	err = db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Create(data).Error; _err != nil {
			return _err
		}

		if len(deprecatedRuleMasks) > 0 {
			if _err := tx.WithContext(ctx).Exec("delete from ivan_platform_attck_rule_masks where name in (?) and version1 = ?", deprecatedRuleMasks, v).Error; _err != nil {
				return _err
			}

			if _err := updateRuleMaskVersion(ctx, tx, v); _err != nil {
				return _err
			}
		}

		return nil
	})

	return data, err
}

func LoadATTCKRuleMaskVersion(ctx context.Context, db *gorm.DB, v uint16) (version uint32, err error) {
	var record model.ATTCKRuleMaskVersion
	err = db.WithContext(ctx).Where("version1 = ?", v).Find(&record).Error
	return record.Version, err
}

func LoadATTCKRuleMasks(ctx context.Context, db *gorm.DB, v uint16) ([]*model.ATTCKRuleMask, error) {
	var records []*model.ATTCKRuleMask
	var err = db.WithContext(ctx).Where("version1 = ?", v).Find(&records).Error
	return records, err
}

func LoadATTCKConfVersions(ctx context.Context, db *gorm.DB, offset, limit int, v string) (int64, []*model.ATTCKConfVersion, error) {

	var records []*model.ATTCKConfVersion
	var dbQuery = db.WithContext(ctx).Model(&model.ATTCKRuleData{}).
		Select("version1, version2, username, created_at")
	if v == "" {
		// dbQuery = dbQuery
	} else if strings.Contains(v, ".") {
		vs := strings.Split(v, ".")
		dbQuery = dbQuery.Where("version1 like ? and version2 like ?", "%"+vs[0], vs[1]+"%")
	} else {
		dbQuery = dbQuery.Where("version1 like ? or version2 like ?", "%"+v+"%", "%"+v+"%")
	}
	dbQuery = dbQuery.Session(&gorm.Session{})

	var err = dbQuery.Order("id desc").Offset(offset).Limit(limit).Find(&records).Error
	if err != nil {
		return 0, nil, err
	}

	var total int64
	err = dbQuery.Count(&total).Error
	return total, records, err
}

func UpdateRuleMask(ctx context.Context, db *gorm.DB, addMasks []*model.ATTCKRuleMask, deletedMasks []string, v uint16) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		if _err := tx.WithContext(ctx).Exec("delete from ivan_platform_attck_rule_masks where name in (?) and version1 = ?", deletedMasks, v).Error; _err != nil {
			return _err
		}

		if _err := tx.WithContext(ctx).CreateInBatches(addMasks, 100).Error; _err != nil {
			return _err
		}

		return updateRuleMaskVersion(ctx, tx, v)
	})
}

func updateRuleMaskVersion(ctx context.Context, db *gorm.DB, v uint16) (err error) {
	return db.Transaction(func(tx *gorm.DB) error {
		var conf model.ATTCKRuleMaskVersion
		var _err = tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("version1 = ?", v).First(&conf).Error
		if _err != nil {
			if _err == gorm.ErrRecordNotFound {
				return tx.WithContext(ctx).Create(&model.ATTCKRuleMaskVersion{Version1: strconv.Itoa(int(v)), Version: 1}).Error
			}
			return _err
		} else {
			return db.WithContext(ctx).Exec("update ivan_platform_attck_rule_mask_versions set version = version + 1 where version1 = ?", v).Error
		}
	})
}
