package dal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
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

func CreateDriftPolicies(ctx context.Context, rdb *gorm.DB, policies []model.DriftPolicy) ([]model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.DriftPolicy{}).Create(&policies).Error
		if err != nil {
			return err
		}
		policy := policies[len(policies)-1]
		versionStamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
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
		return nil, err
	}

	return policies, err
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

func UpdateDriftPolicies(ctx context.Context, rdb *gorm.DB, policies []model.DriftPolicyUpdate) ([]model.DriftPolicy, []error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := model.DriftPolicy{}
	updatePolices := make([]model.DriftPolicy, 0, len(policies))
	errs := make([]error, 0)
	for index, policy := range policies {
		err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Find(&query).Error
		if err != nil {
			errs = append(errs, err)
			continue
		}

		tmpPolicy := model.DriftPolicy{}
		tmpPolicy.ID = policy.PolicyID
		tmpPolicy.Enable = policy.Enable
		tmpPolicy.Mode = policy.Mode
		tmpPolicy.Updater = policy.Updater
		tmpPolicy.UpdatedAt = time.Now()
		err = rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("id = ?", policy.PolicyID).Select("enable", "mode", "updater", "updated_at").Updates(&tmpPolicy).Error
		if err != nil {
			errs = append(errs, fmt.Errorf("update policy %d failed: %v", policy.PolicyID, err))
			continue
		}
		logging.Get().Info().Str("tmpPolicy:", fmt.Sprintf("%+v", tmpPolicy)).Msg("update policy success")
		updatePolices = append(updatePolices, tmpPolicy)
		if index == len(policies)-1 {
			err = rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				versionStamp := strconv.FormatInt(tmpPolicy.UpdatedAt.UnixMilli(), 10)
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
				errs = append(errs, fmt.Errorf("update version stamp failed: %v", err))
			}
		}
	}

	return updatePolices, errs
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

func GetDriftPoliciesCount(ctx context.Context, rdb *gorm.DB, clusterKey string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var len int64
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("cluster_key = ?", clusterKey).Count(&len).Error
	if err != nil {
		return 0, err
	}
	return len, nil
}

func GetDriftSupportResources(ctx context.Context, rdb *gorm.DB, clusterKey string) ([]model.TensorResource, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.TensorResource{}
	err := rdb.Model(&model.TensorResource{}).WithContext(ctx).Where("cluster_key = ? AND is_support_drift = ?", clusterKey, true).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetAllPoliciesByClusterKey(ctx context.Context, rdb *gorm.DB, clusterKey string) ([]model.DriftPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.DriftPolicy{}
	err := rdb.Model(&model.DriftPolicy{}).WithContext(ctx).Where("cluster_key = ?", clusterKey).Find(&res).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return res, nil
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

func RawContainers(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicy) ([]model.TensorRawContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.TensorRawContainer{}
	err := rdb.Model(&model.TensorRawContainer{}).WithContext(ctx).
		Where("cluster_key=? and resource_name = ? and namespace = ? and resource_kind=?",
			policy.ClusterKey, policy.Resource,
							policy.Namespace, policy.ResourceKind).
		Order("created_at desc").Limit(100). // return 50 latest containers, reduce the pressure of es
		Find(&res).Error

	if err != nil {
		return nil, err
	}
	return res, nil
}

func PolicyDetail(ctx context.Context, rdb *gorm.DB, policy model.DriftPolicy, limit int, offset int) ([]model.TensorContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.TensorContainer{}
	err := rdb.Model(&model.TensorContainer{}).WithContext(ctx).
		Where("cluster_key=? and resource_name = ? and namespace = ? and resource_kind=?",
			policy.ClusterKey,
			policy.Resource,
			policy.Namespace,
			policy.ResourceKind).Limit(limit).
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

	// deal reason
	var reasonList []model.ReasonItem
	err = json.Unmarshal([]byte(query.Reason), &reasonList)
	if err != nil {
		logging.Get().Err(err).Msgf("unmarshal reason failed, reason: %s", query.Reason)
	}
	var runningList []model.ReasonItem
	for _, v := range reasonList {
		// find raw container by id
		res := model.TensorRawContainer{}
		err := rdb.Model(&model.TensorRawContainer{}).WithContext(ctx).
			Where("id = ?", v.ID).Find(&res).Error

		if err != nil {
			logging.Get().Err(err).Msgf("get raw container by id %s failed", v.ID)
			continue
		}
		if res.Status < assets.Exited {
			runningList = append(runningList, v)
		}
	}
	runningList = append(runningList, model.ReasonItem{
		ID:             originData.ContainerID,
		OS:             originData.OSTarget,
		IsSupportDrift: originData.IsSupportDrift,
	})
	reasonBytes, err := json.Marshal(runningList)
	if err != nil {
		return err
	}

	tmpData := model.TensorResource{Reason: string(reasonBytes[:])}
	tmpData.IsSupportDrift = true
	for _, v := range runningList {
		tmpData.IsSupportDrift = tmpData.IsSupportDrift && v.IsSupportDrift
		if !tmpData.IsSupportDrift {
			break
		}
	}
	err = db.Select("reason", "is_support_drift").Updates(&tmpData).Error
	logging.Get().Info().Msgf("update resource support info success, %v", tmpData)
	return err
}

func UpdateResourceScannerStatus(ctx context.Context, rdb *gorm.DB, originData model.DriftSupportInfo) error {
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
	tmpData := query
	if originData.ScannerStatus > 0 {
		tmpData.ScannerStatus = originData.ScannerStatus
		err = db.Select("scanner_status").Updates(&tmpData).Error
	}
	return err
}

func InsertImageWhitelist(ctx context.Context, rdb *gorm.DB, imageWhitelist []model.DriftImageWhitelist) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := rdb.Model(&model.DriftImageWhitelist{}).WithContext(ctx)

	err := db.Create(&imageWhitelist).Error
	if err != nil {
		return err
	}
	return nil
}

func GetDefaultWhitelistByImageID(ctx context.Context, rdb *gorm.DB, offset, limit int, imageID string) ([]model.DriftImageWhitelist, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := rdb.Model(&model.DriftImageWhitelist{}).WithContext(ctx)
	db = db.Where("image_id = ?", imageID)
	db = db.Offset(offset)
	db = db.Limit(limit)
	res := []model.DriftImageWhitelist{}
	err := db.Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func GetDefaultWhitelistByImageTags(ctx context.Context, rdb *gorm.DB, offset, limit int, tags []string, searchStr string) ([]model.DriftImageWhitelist, int64, error) {
	if len(tags) == 0 {
		return nil, 0, nil
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var res []model.DriftImageWhitelist

	db := rdb.Model(&res).WithContext(ctx)

	var orConditions []string
	var args []interface{}

	for _, tag := range tags {
		orConditions = append(orConditions, "repo_tag LIKE ?")
		args = append(args, "%"+tag+"%")
	}
	query := strings.Join(orConditions, " OR ")
	if searchStr != "" {
		// db = db.Where("path LIKE ?", "%"+searchStr+"%")
		query = fmt.Sprintf("(%s) AND path LIKE ?", query)
		args = append(args, "%"+searchStr+"%")
	}
	db = db.Where(query, args...)
	var count int64
	err := db.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	db = db.Offset(offset)
	db = db.Limit(limit)
	err = db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	return res, count, nil
}
