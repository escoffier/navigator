package dal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	// "gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

func CreateDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, whitelist model.DriftGlobalWhitelistItem) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tmpList := []model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("path=?", whitelist.Path).Find(&tmpList).Error
	if err != nil {
		return -1, err
	}
	if len(tmpList) > 0 {
		return tmpList[0].ID, fmt.Errorf("same path")
	}
	err = rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Create(&whitelist).Error
	if err != nil {
		return -1, err
	}

	return whitelist.ID, nil
}

func DelDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, id int64) (model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", id).Find(&query).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	err = rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", id).Delete(&model.DriftGlobalWhitelistItem{}).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	return query, nil

}

func UpdateDriftGlobalWhiteList(ctx context.Context, rdb *gorm.DB, whitelist model.DriftGlobalWhitelistItem) (model.DriftGlobalWhitelistItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tmpWhitelist := model.DriftGlobalWhitelistItem{}
	tmpWhitelist.Updater = whitelist.Updater
	tmpWhitelist.UpdatedAt = whitelist.UpdatedAt
	tmpWhitelist.Path = whitelist.Path
	tmpWhitelist.Expire_at = whitelist.Expire_at
	tmpWhitelist.Is_forever = whitelist.Is_forever
	query := model.DriftGlobalWhitelistItem{}
	err := rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", whitelist.ID).Find(&query).Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	if query.ID == 0 {
		return model.DriftGlobalWhitelistItem{}, errors.New("not found id")
	}
	// logging.Get().Info().Str("tmpData", fmt.Sprintf("%+v", tmpWhitelist)).Msg("update whitelist")
	err = rdb.Model(&model.DriftGlobalWhitelistItem{}).WithContext(ctx).Where("id = ?", whitelist.ID).
		Select("path", "updater", "updated_at", "expire_at", "is_forever").Updates(&tmpWhitelist).
		Error
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	tmpWhitelist.ID = query.ID
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
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetDriftGlobalWhiteListById(ctx context.Context, rdb *gorm.DB, id int64) (model.DriftGlobalWhitelistItem, error) {
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
	tmpPolicies := []model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("resource_uuid=?", policy.ResourceUUID).Find(&tmpPolicies).Error
	if err != nil {
		return -1, err
	}
	if len(tmpPolicies) > 0 {
		return tmpPolicies[0].ID, fmt.Errorf("same uuid")
	}
	err = rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Create(&policy).Error
	if err != nil {
		return -1, err
	}
	return policy.ID, nil
}

func DeleteDriftPolicy(ctx context.Context, rdb *gorm.DB, policyID int64) (model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policyID).Find(&query).Error
	if err != nil {
		return model.DriftPolicy{}, err
	}
	err = rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policyID).Delete(&model.DriftPolicy{}).Error
	if err != nil {
		return model.DriftPolicy{}, err
	}
	return query, nil
}

func UpdateDriftPolicy(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicyUpdate) (model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tmpPolicy := model.DriftPolicy{}
	tmpPolicy.ID = policy.PolicyID
	tmpPolicy.Enable = policy.Enable
	tmpPolicy.Mode = policy.Mode
	tmpPolicy.Updater = policy.Updater
	query := model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Find(&query).Error
	if err != nil {
		return model.DriftPolicy{}, err
	}
	err = rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Select("enable", "mode", "updater").Updates(&tmpPolicy).Error
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
	err := db.Offset(offset).Limit(limit).Find(&res).Error
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
	if err != nil {
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
