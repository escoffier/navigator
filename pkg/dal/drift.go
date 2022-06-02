package dal

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
)

func CreateDriftPolicy(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicy) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Create(&policy).Error
	if err != nil {
		return -1, err
	}
	return policy.ID, nil
}

func DeleteDriftPolicy(ctx context.Context, rdb *gorm.DB, policyID int64) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policyID).Delete(&model.DriftPolicy{}).Error
	if err != nil {
		return err
	}
	return nil
}

func UpdateDriftPolicy(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicyUpdate) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tmpPolicy := model.DriftPolicy{}
	tmpPolicy.ID = policy.PolicyID
	tmpPolicy.Enable = policy.Enable
	tmpPolicy.Mode = policy.Mode
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Select("enable", "mode").Updates(&tmpPolicy).Error
	if err != nil {
		return err
	}
	return nil
}

func ListDriftPolicy(ctx context.Context, rdb *gorm.DB, limit, offset int, clusterKey string, resourceType, enable, mode []string, search string) ([]model.DriftPolicy, error) {
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
	if search != "" {
		db = db.Where("resource LIKE ? OR namespace LIKE ?", fmt.Sprintf("%%%s%%", search), fmt.Sprintf("%%%s%%", search))
	}
	db = db.Where("cluster_key = ?", clusterKey)
	res := []model.DriftPolicy{}
	err := db.Find(&res).Offset(offset).Limit(limit).Error
	if err != nil {
		return nil, err
	}
	return res, nil
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
	err := rdb.Model(&model.ImageList{}).WithContext(ctx).Where("image_uuid = ?", ids).Select("id").Find(&res).Error
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
