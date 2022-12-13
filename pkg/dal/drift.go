package dal

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func updateDriftVersionStamp(tx *gorm.DB, config *model.TensorConfig) error {

	return tx.Model(&model.TensorConfig{}).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"config",
			"updater",
			"updated_at",
			"status",
		}),
	}).Create(config).Error
}
func CreateDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, whitelist model.DriftGlobalWhitelistItem) (uint64, error) {
	whitelist.ID = util.GenerateUUID64(whitelist.Path)
	if whitelist.UpdatedAt == 0 {
		whitelist.UpdatedAt = time.Now().UnixMilli()
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Create(&whitelist).Error
		if err != nil {
			return err
		}
		versionStamp := strconv.FormatInt(whitelist.UpdatedAt, 10)
		now := time.Now()
		config := &model.TensorConfig{
			Key:       model.ConfDriftWhitelistVersionKey,
			Config:    []byte(versionStamp),
			Creator:   whitelist.Creator,
			CreatedAt: now,
			Updater:   whitelist.Updater,
			UpdatedAt: now,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})
	if err != nil {
		return 0, err
	}

	return whitelist.ID, nil
}

func DelDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, id uint64) (model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", id).Find(&query).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}

	userName := model.GetUsernameFromContext(ctx)
	if userName == "" {
		userName = "system"
	}
	err = rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftGlobalWhitelistItem{}).Where("id = ?", id).Delete(&model.DriftGlobalWhitelistItem{}).Error
		if err != nil {
			return err
		}
		now := time.Now()
		versionStamp := strconv.FormatInt(now.UnixMilli(), 10)
		config := &model.TensorConfig{
			Key:       model.ConfDriftWhitelistVersionKey,
			Config:    []byte(versionStamp),
			Creator:   userName,
			CreatedAt: now,
			Updater:   userName,
			UpdatedAt: now,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	return query, nil

}

func UpdateDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, whitelist model.DriftGlobalWhitelistItem) (model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", whitelist.ID).Find(&query).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	if query.ID == 0 {
		return model.DriftGlobalWhitelistItem{}, errors.New("not found id")
	}

	tmpWhitelist := model.DriftGlobalWhitelistItem{}
	tmpWhitelist.ID = whitelist.ID
	tmpWhitelist.Updater = whitelist.Updater
	tmpWhitelist.UpdatedAt = whitelist.UpdatedAt
	tmpWhitelist.Path = whitelist.Path
	tmpWhitelist.ExpireAt = whitelist.ExpireAt
	tmpWhitelist.IsForever = whitelist.IsForever

	err = rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", tmpWhitelist.ID).
			Select("path", "updater", "updated_at", "expire_at", "is_forever").Updates(&tmpWhitelist).
			Error
		if err != nil {
			return err
		}

		now := time.Now()
		versionStamp := strconv.FormatInt(now.UnixMilli(), 10)
		config := &model.TensorConfig{
			Key:       model.ConfDriftWhitelistVersionKey,
			Config:    []byte(versionStamp),
			Creator:   tmpWhitelist.Creator,
			CreatedAt: now,
			Updater:   tmpWhitelist.Updater,
			UpdatedAt: now,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})

	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	return tmpWhitelist, nil
}

func ListDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, limit, offset int, path, searchStr string, startTime, endTime int64) ([]model.DriftGlobalWhitelistItem, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx)

	if searchStr != "" {
		db = db.Where("path LIKE ? OR updater LIKE ?", fmt.Sprintf("%%%s%%", searchStr), fmt.Sprintf("%%%s%%", searchStr))
	}
	if startTime != 0 || endTime != 0 {
		db = db.Where("expire_at >= ?", startTime).Or("is_forever = ? AND created_at <= ?", true, endTime)
	}

	var len int64
	db.Count(&len)
	res := []model.DriftGlobalWhitelistItem{}
	err := db.Order("created_at desc").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	return res, len, nil
}

func GetAllDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB) ([]model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Find(&res).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetDriftGlobalWhiteListById(ctx context.Context, rdb *gorm.DB, id uint64) (model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", id).Find(&query).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	if query.ID == 0 {
		return model.DriftGlobalWhitelistItem{}, fmt.Errorf("not find whitelist id=%d", id)
	}
	return query, nil

}

func CreateDriftPolicy(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicy) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	if policy.UpdatedAt.IsZero() {
		policy.UpdatedAt = now
	}
	tmpPolicies := []model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("resource_uuid=?", policy.ResourceUUID).Find(&tmpPolicies).Error
	if err != nil {
		return -1, err
	}
	if len(tmpPolicies) > 0 {
		return tmpPolicies[0].ID, fmt.Errorf("same uuid")
	}

	err = rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftPolicy{}).Create(&policy).Error
		if err != nil {
			return err
		}
		versionStamp := strconv.FormatInt(now.UnixMilli(), 10)
		config := &model.TensorConfig{
			Key:       model.ConfDriftPoliciesVersionKey,
			Config:    []byte(versionStamp),
			Creator:   policy.Creator,
			CreatedAt: policy.CreatedAt,
			Updater:   policy.Updater,
			UpdatedAt: policy.UpdatedAt,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})

	if err != nil {
		return -1, err
	}
	return policy.ID, nil
}

func DeleteDriftPolicy(ctx context.Context, rdb *gorm.DB, policyID int64) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	userName := model.GetUsernameFromContext(ctx)
	if userName == "" {
		userName = "system"
	}

	err := rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tmpPolicy model.DriftPolicy
		err := tx.Model(&tmpPolicy).WithContext(ctx).Where("id = ?", policyID).Delete(&tmpPolicy).Error

		if err == gorm.ErrRecordNotFound {
			logging.Get().Warn().Int64("policyID", policyID).Msg("Try to delete an nonexisted policy")
			return nil
		} else if err != nil {
			return err
		}

		now := time.Now()
		versionStamp := strconv.FormatInt(now.UnixMilli(), 10)
		config := &model.TensorConfig{
			Key:       model.ConfDriftPoliciesVersionKey,
			Config:    []byte(versionStamp),
			Creator:   userName,
			CreatedAt: now,
			Updater:   userName,
			UpdatedAt: now,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})
	return err
}

func UpdateDriftPolicy(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicyUpdate) (model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Find(&query).Error
	if err != nil {
		return model.DriftPolicy{}, err
	}

	now := time.Now()
	tmpPolicy := model.DriftPolicy{}
	tmpPolicy.ID = policy.PolicyID
	tmpPolicy.Enable = policy.Enable
	tmpPolicy.Mode = policy.Mode
	tmpPolicy.Updater = policy.Updater
	tmpPolicy.UpdatedAt = now

	err = rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Select("enable", "mode", "updater", "updated_at").Updates(&tmpPolicy).Error
		if err != nil {
			return err
		}
		versionStamp := strconv.FormatInt(now.UnixMilli(), 10)
		config := &model.TensorConfig{
			Key:       model.ConfDriftPoliciesVersionKey,
			Config:    []byte(versionStamp),
			Creator:   tmpPolicy.Updater,
			CreatedAt: tmpPolicy.UpdatedAt,
			Updater:   tmpPolicy.Updater,
			UpdatedAt: tmpPolicy.UpdatedAt,
			Status:    0,
		}
		return updateDriftVersionStamp(tx, config)
	})

	if err != nil {
		return model.DriftPolicy{}, err
	}
	return query, nil
}

func ListDriftPolicy(ctx context.Context, rdb *gorm.DB, limit, offset int, clusterKey string, resourceType, namespaces, enable, mode []string, search string) ([]model.DriftPolicy, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db := rdb.Model(&model.DriftPolicy{}).WithContext(ctx)
	if len(resourceType) > 0 {
		db = db.Where("resource_kind in ?", resourceType)
	}
	if len(enable) > 0 {
		db = db.Where("enable in ?", enable)
	}
	if len(mode) > 0 {
		db = db.Where("mode in ?", mode)
	}
	if len(namespaces) > 0 {
		if len(namespaces) == 1 {
			db = db.Where("namespace LIKE ?", fmt.Sprintf("%%%s%%", namespaces[0]))
		} else {
			db = db.Where("namespace in ?", namespaces)
		}
	}
	if search != "" {
		db = db.Where("resource LIKE ?", fmt.Sprintf("%%%s%%", search))
	}
	db = db.Where("cluster_key = ?", clusterKey)
	var len int64
	db.Count(&len)
	res := []model.DriftPolicy{}
	err := db.Order("created_at desc").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	return res, len, nil
}

func GetAllPolicies(ctx context.Context, rdb *gorm.DB) ([]model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Find(&res).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return res, nil
}

func GetPolicyByID(ctx context.Context, rdb *gorm.DB, id int64) (model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", id).Find(&res).Error
	if err != nil {
		return model.DriftPolicy{}, err
	}
	return res, nil
}

func PolicyDetail(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicy, limit int, offset int) ([]model.TensorContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.TensorContainer{}
	err := rdb.Model(&model.TensorContainer{}).WithContext(ctx).Where("cluster_key=? and resource_name = ? and namespace = ? and resource_kind=?", policy.ClusterKey, policy.Resource, policy.Namespace, policy.ResourceKind).Limit(limit).
		Offset(offset).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetImageID(ctx context.Context, rdb *gorm.DB, ids uint32) ([]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []int64{}
	err := rdb.Table(fmt.Sprintf("%s AS t", model.ImageList{}.TableName())).
		WithContext(ctx).
		Joins(fmt.Sprintf("JOIN  %s AS s on t.registry_id=s.id", model.Registry{}.TableName())).
		Where("t.image_uuid = ? and deleted_at=0", ids).Select("t.id").Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetContainerByID(ctx context.Context, rdb *gorm.DB, id uint32) (model.TensorContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := model.TensorContainer{}
	err := rdb.Model(&model.TensorContainer{}).WithContext(ctx).Where("id = ?", id).Find(&res).Error
	if err != nil {
		return model.TensorContainer{}, err
	}
	return res, nil
}

func UpdateResourceSupportInfo(ctx context.Context, rdb *gorm.DB, originData model.DriftSupportInfo) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	db := rdb.Model(&model.TensorResource{}).WithContext(ctx)
	db = db.Where("cluster_key = ? AND namespace = ? AND kind = ? AND name = ?",
		originData.Cluster,
		originData.Namespace,
		originData.ResourceKind,
		originData.ResourceName,
	)

	query := model.TensorResource{}
	var len int64
	db.Count(&len)
	if len != 1 {
		return errors.New("not found")
	}
	err := db.Find(&query).Error
	if err != nil {
		return err
	}
	separator := ","
	tmpData := model.TensorResource{Reason: ""}
	if !originData.IsSupportDrift {
		exist := false
		for _, v := range strings.Split(query.Reason, separator) {
			if v == originData.OSTarget {
				exist = true
				break
			}
		}
		if exist {
			tmpData.Reason = query.Reason
		} else {
			if query.Reason == "" {
				tmpData.Reason = originData.OSTarget
			} else {
				tmpData.Reason = strings.Join([]string{query.Reason, originData.OSTarget}, ",")
			}
		}
	}
	tmpData.IsSupportDrift = query.IsSupportDrift && originData.IsSupportDrift

	// logging.Get().Info().
	// 	Str("originData", fmt.Sprintf("%v", originData)).
	// 	Str("query:", fmt.Sprintf("%+v", query)).
	// 	Str("tmpData", fmt.Sprintf("%+v", tmpData)).
	// 	Msg("update support info")

	err = db.
		Select("reason", "is_support_drift").Updates(&tmpData).
		Error
	if err != nil {
		return err
	}
	return nil
}
