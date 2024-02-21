package dal

import (
	"context"
	"errors"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"gorm.io/gorm"
)

func BehavioralLearnFileModelQuery(ctx context.Context, rdb *gorm.DB, resourceUUID uint32,
	searchStr string, permission int, isInModel bool,
	offset, limit int, startID uint64, cNames []string) ([]*model.BehavioralLearnFileModel, int64, error) {
	var res []*model.BehavioralLearnFileModel

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", isInModel)

	if startID != 0 {
		db = db.Where("id < ?", startID)
	}

	if searchStr != "" {
		db = db.Where("name like ? OR path like ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if permission != 0 {
		db = db.Where("permission = ?", permission)
	}
	if len(cNames) > 0 {
		db = db.Where("container_name in ?", cNames)
	}

	var total int64
	var err error
	db.Count(&total)
	if offset != 0 {
		err = db.Order("id DESC").Offset(offset).Limit(limit).Find(&res).Error
	} else if limit != 0 {
		err = db.Order("id DESC").Limit(limit).Find(&res).Error
	} else {
		err = db.Order("id DESC").Find(&res).Error
	}
	if err != nil {
		return nil, 0, err
	}

	return res, total, nil
}

func BehavioralLearnCommandModelQuery(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, searchStr string, isInModel bool,
	offset, limit int, startID uint64, cNames []string) ([]*model.BehavioralLearnCommandModel, int64, error) {
	var res []*model.BehavioralLearnCommandModel

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", isInModel)
	if startID != 0 {
		db = db.Where("id < ?", startID)
	}
	if searchStr != "" {
		db = db.Where("command like ? OR path like ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	if len(cNames) > 0 {
		db = db.Where("container_name in ?", cNames)
	}

	var total int64
	var err error
	db.Count(&total)
	if offset != 0 {
		err = db.Order("id DESC").Offset(offset).Limit(limit).Find(&res).Error
	} else if limit != 0 {
		err = db.Order("id DESC").Limit(limit).Find(&res).Error
	} else {
		err = db.Order("id DESC").Find(&res).Error

	}
	if err != nil {
		logging.GetLogger().Error().Msgf("get command model fail, uuid: %d limit: %d offset: %d total: %d", resourceUUID, limit, offset, total)
		return nil, 0, err
	}

	return res, total, nil
}

func BehavioralLearnNetworkModelQuery(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, streamDirection, port int,
	searchStr string, isInModel bool, offset, limit int, startID uint64, cNames []string) ([]*model.BehavioralLearnNetworkModel, int64, error) {
	var res []*model.BehavioralLearnNetworkModel

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", isInModel)
	if startID != 0 {
		db = db.Where("id < ?", startID)
	}

	if streamDirection != 0 {
		db = db.Where("stream_direction = ?", streamDirection)
	}

	if searchStr != "" {
		db = db.Where("resource_kind like ? OR resource_name like ? OR resource_namespace like ? OR port like ?", "%"+searchStr+"%", "%"+searchStr+"%", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	if len(cNames) > 0 {
		db = db.Where("container_name in ?", cNames)
	}

	var total int64
	var err error
	db.Count(&total)
	if offset != 0 {
		err = db.Order("id DESC").Offset(offset).Limit(limit).Find(&res).Error
	} else if limit != 0 {
		err = db.Order("id DESC").Limit(limit).Find(&res).Error
	} else {
		err = db.Order("id DESC").Find(&res).Error

	}
	if err != nil {
		return nil, 0, err
	}

	return res, total, nil
}

func BehavioralLearnGetModelMix(ctx context.Context, rdb *gorm.DB, resourceUUID uint32) ([]model.BehavioralLearnFileModel, []model.BehavioralLearnCommandModel, []model.BehavioralLearnNetworkModel, error) {
	var fileModel []model.BehavioralLearnFileModel
	var commandModel []model.BehavioralLearnCommandModel
	var networkModel []model.BehavioralLearnNetworkModel
	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", true)
	err := db.Find(&fileModel).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("get file model fail, uuid: %d", resourceUUID)

	}

	db = rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", true)
	err = db.Find(&commandModel).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("get command model fail, uuid: %d", resourceUUID)
	}

	db = rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where("resource_uuid = ?", resourceUUID).Where("is_in_model = ?", true)
	err = db.Find(&networkModel).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("get network model fail, uuid: %d", resourceUUID)
	}
	return fileModel, commandModel, networkModel, nil
}

func BehavioralLearnGetAbnormalCount(ctx context.Context, rdb *gorm.DB, resourceUUID uint32) (int64, error) {
	total := int64(0)
	var count int64
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where("resource_uuid = ? AND is_in_model = ?", resourceUUID, false).Count(&count).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("get file model fail, uuid: %d", resourceUUID)
	}
	total += count

	err = rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where("resource_uuid = ? AND is_in_model = ?", resourceUUID, false).Count(&count).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("get command model fail, uuid: %d", resourceUUID)
	}
	total += count

	err = rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where("resource_uuid = ? AND is_in_model = ?", resourceUUID, false).Count(&count).Error

	if err != nil {
		logging.GetLogger().Error().Msgf("get network model fail, uuid: %d", resourceUUID)
	}
	total += count

	return total, nil
}

func BehavioralLearnUpdateFileModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnFileModel) (model.BehavioralLearnFileModel, error) {
	query := model.BehavioralLearnFileModel{}
	query.ResourceUUID = data.ResourceUUID
	query.Id = data.Id

	res := model.BehavioralLearnFileModel{}

	err := rdb.WithContext(ctx).Model(&res).Where(&query).Updates(map[string]interface{}{
		"name":       data.Name,
		"path":       data.Path,
		"permission": data.Permission,
		"updated_at": time.Now().Unix(),
	}).Error
	if err != nil {
		return data, err
	}

	err = rdb.WithContext(ctx).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}

	return res, nil
}

func BehavioralLearnUpdateCommandModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnCommandModel) (model.BehavioralLearnCommandModel, error) {
	query := model.BehavioralLearnCommandModel{}
	query.ResourceUUID = data.ResourceUUID
	query.Id = data.Id

	res := model.BehavioralLearnCommandModel{}

	err := rdb.WithContext(ctx).Model(&res).Where(&query).Updates(map[string]interface{}{
		"command":    data.Command,
		"user":       data.User,
		"path":       data.Path,
		"updated_at": time.Now().Unix(),
	}).Error
	if err != nil {
		return data, err
	}

	err = rdb.WithContext(ctx).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}
	return res, nil
}

func BehavioralLearnUpdateNetworkModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnNetworkModel) (model.BehavioralLearnNetworkModel, error) {
	query := model.BehavioralLearnNetworkModel{}
	query.ResourceUUID = data.ResourceUUID
	query.Id = data.Id

	res := model.BehavioralLearnNetworkModel{}

	err := rdb.WithContext(ctx).Model(&res).Where(&query).Updates(map[string]interface{}{
		"port":               data.Port,
		"cluster_key":        data.ClusterKey,
		"resource_kind":      data.ResourceKind,
		"resource_name":      data.ResourceName,
		"resource_namespace": data.ResourceNamespace,
		"stream_direction":   data.StreamDirection,
		"updated_at":         time.Now().Unix(),
	}).Error
	if err != nil {
		return data, err
	}

	err = rdb.WithContext(ctx).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}
	return res, nil
}

func BehavioralLearnGetFileModelByID(ctx context.Context, rdb *gorm.DB, id uint64) (model.BehavioralLearnFileModel, error) {
	var res model.BehavioralLearnFileModel
	query := model.BehavioralLearnFileModel{}
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}

	return res, nil
}

func BehavioralLearnAddFileModelOutModel(ctx context.Context, rdb *gorm.DB, insertData model.BehavioralLearnFileModel) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Create(&insertData).Error
	return err
}

func BehavioralLearnGetCommandModelByID(ctx context.Context, rdb *gorm.DB, id uint64) (model.BehavioralLearnCommandModel, error) {
	var res model.BehavioralLearnCommandModel
	query := model.BehavioralLearnCommandModel{}
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}

	return res, nil
}

func BehavioralLearnAddCommandModelOutModel(ctx context.Context, rdb *gorm.DB, insertData model.BehavioralLearnCommandModel) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Create(&insertData).Error
	return err
}

func BehavioralLearnGetNetworkModelByID(ctx context.Context, rdb *gorm.DB, id uint64) (model.BehavioralLearnNetworkModel, error) {
	var res model.BehavioralLearnNetworkModel
	query := model.BehavioralLearnNetworkModel{}
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where(&query).First(&res).Error
	if err != nil {
		return res, err
	}

	return res, nil
}

func BehavioralLearnAddNetworkModelOutModel(ctx context.Context, rdb *gorm.DB, insertData model.BehavioralLearnNetworkModel) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Create(&insertData).Error
	return err
}

func BehavioralLearnInsertFileModels(ctx context.Context, rdb *gorm.DB, data []model.BehavioralLearnFileModel) ([]model.BehavioralLearnFileModel, error) {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Create(&data).Error
	return data, err
}

func BehavioralLearnInsertFileModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnFileModel) (model.BehavioralLearnFileModel, error) {
	// // delete old data

	if rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where("is_in_model = ? AND resource_uuid = ? AND path = ? AND permission = ? AND container_name = ?", data.IsInModel, data.ResourceUUID, data.Path, data.Permission, data.ContainerName).
		Updates(&data).RowsAffected == 0 {

		err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Create(&data).Error
		if err != nil {
			return data, err
		}
	}
	return data, nil
}

func BehavioralLearnInsertCommandModels(ctx context.Context, rdb *gorm.DB, data []model.BehavioralLearnCommandModel) ([]model.BehavioralLearnCommandModel, error) {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Create(&data).Error
	return data, err
}

func BehavioralLearnInsertCommandModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnCommandModel) (model.BehavioralLearnCommandModel, error) {

	if rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where("is_in_model = ? AND resource_uuid = ? AND path = ? AND command = ? AND container_name = ?", data.IsInModel, data.ResourceUUID, data.Path, data.Command, data.ContainerName).Updates(&data).RowsAffected == 0 {

		err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Create(&data).Error
		if err != nil {
			return data, err
		}
	}
	return data, nil
}

func BehavioralLearnInsertNetworkModels(ctx context.Context, rdb *gorm.DB, data []model.BehavioralLearnNetworkModel) ([]model.BehavioralLearnNetworkModel, error) {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Create(&data).Error
	return data, err
}

func BehavioralLearnInsertNetworkModel(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnNetworkModel) (model.BehavioralLearnNetworkModel, error) {

	if rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where("is_in_model = ? AND resource_uuid = ? AND port = ? AND stream_direction = ? and container_name = ? and process_name = ?", data.IsInModel, data.ResourceUUID, data.Port,
		data.StreamDirection, data.ContainerName, data.ProcessName).Updates(&data).RowsAffected == 0 {
		err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Create(&data).Error
		if err != nil {
			return data, err
		}
	}
	return data, nil
}

func BehavioralLearnDeleteFileModel(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, id uint64) error {
	query := model.BehavioralLearnFileModel{}
	query.ResourceUUID = resourceUUID
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where(&query).Delete(&model.BehavioralLearnFileModel{}).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnDeleteCommandModel(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, id uint64) error {
	query := model.BehavioralLearnCommandModel{}
	query.ResourceUUID = resourceUUID
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where(&query).Delete(&model.BehavioralLearnCommandModel{}).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnDeleteNetworkModel(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, id uint64) error {
	query := model.BehavioralLearnNetworkModel{}
	query.ResourceUUID = resourceUUID
	query.Id = id

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where(&query).Delete(&model.BehavioralLearnNetworkModel{}).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnUpdateResourceStatus(ctx context.Context, rdb *gorm.DB, tasks []model.BehavioralLearnTaskItem, op int) ([]model.TensorResource, error) {
	// update resource status
	res := []model.TensorResource{}
	uuids := []uint32{}
	for _, task := range tasks {
		uuids = append(uuids, task.ResourceUUID)
	}
	logging.GetLogger().Debug().Msgf("update resource status, uuids: %+v", uuids)
	// update resource status
	err := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("id in ?", uuids).Updates(map[string]interface{}{
		"behavioral_learn_status": op,
	}).Error
	if err != nil {
		return nil, err
	}

	// get resource
	err = rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("id in ?", uuids).Find(&res).Error
	if err != nil {
		return nil, err
	}

	return res, nil
}

func BehavioralLearnUpdateResourceLearnTime(ctx context.Context, rdb *gorm.DB, tasks []model.BehavioralLearnTaskItem) error {
	query := model.TensorResource{}
	for _, task := range tasks {
		query.ID = task.ResourceUUID

		err := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where(&query).Updates(map[string]interface{}{
			"behavioral_learn_time": task.LearnTime,
		}).Error
		if err != nil {
			return err
		}
		logging.GetLogger().Info().Msgf("query: %+v", query)
	}

	return nil
}

func BehavioralLearnUpdateResourceStartLearnTime(ctx context.Context, rdb *gorm.DB, tasks []model.BehavioralLearnTaskItem) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	query := model.TensorResource{}
	for _, task := range tasks {
		query.ID = task.ResourceUUID
		logging.GetLogger().Info().Msgf("update resource start learn time, uuid: %d, start time: %d", task.ResourceUUID, task.StartTime)
		err := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where(&query).Updates(map[string]interface{}{
			"behavioral_learn_start_time": task.StartTime,
		}).Error
		if err != nil {
			return err
		}
		// delete model
		err = rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModel{}).Where("resource_uuid = ? AND is_in_model = ?", task.ResourceUUID, true).Delete(&model.BehavioralLearnFileModel{}).Error
		if err != nil {
			logging.GetLogger().Error().Msgf("delete file model fail, uuid: %d", task.ResourceUUID)
		}
		err = rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModel{}).Where("resource_uuid = ? AND is_in_model = ?", task.ResourceUUID, true).Delete(&model.BehavioralLearnCommandModel{}).Error
		if err != nil {
			logging.GetLogger().Error().Msgf("delete command model fail, uuid: %d", task.ResourceUUID)
		}
		err = rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModel{}).Where("resource_uuid = ? AND is_in_model = ?", task.ResourceUUID, true).Delete(&model.BehavioralLearnNetworkModel{}).Error
		if err != nil {
			logging.GetLogger().Error().Msgf("delete network model fail, uuid: %d", task.ResourceUUID)
		}

	}

	return nil
}

func BehavioralLearnCountRawContainers(ctx context.Context, rdb *gorm.DB, clusterKey, namespace, kind, name string) (int64, error) {
	var count int64
	err := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Where("cluster_key = ? and namespace = ? and resource_kind = ? and resource_name = ? and status = 0",
		clusterKey, namespace, kind, name).Count(&count).Error

	return count, err
}

func BehavioralLearnGetContainers(ctx context.Context, rdb *gorm.DB,
	clusterKey, namespace, kind, name string) ([]*model.TensorContainer, error) {
	var containers []*model.TensorContainer

	err := rdb.WithContext(ctx).Model(&model.TensorContainer{}).Where("cluster_key = ? and namespace = ? and resource_kind = ? and resource_name = ?",
		clusterKey, namespace, kind, name).Find(&containers).Error

	return containers, err
}

func BehavioralLearnGetContainersByImageName(ctx context.Context, rdb *gorm.DB, imageName string) ([]*model.TensorRawContainer, error) {
	var containers []*model.TensorRawContainer
	// status == 0

	err := rdb.WithContext(ctx).Model(&model.TensorRawContainer{}).Where("image_name like ?", "%"+imageName+"%").Find(&containers).Error
	if err != nil {
		return nil, err
	}

	return containers, nil
}

func BehavioralLearnUpdateModelConfig(ctx context.Context, rdb *gorm.DB, data []model.BehavioralLearnModelConfig) ([]model.TensorResource, map[uint32]struct{}, int, error) {
	success := 0
	resMap := make(map[uint32]struct{})
	ress := []model.TensorResource{}
	for _, d := range data {
		var res model.TensorResource
		err := rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("id = ?", d.ResourceUUID).Find(&res).Error
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("get resource by uuid fail, uuid: %d", d.ResourceUUID)
			continue
		}

		if res.BehavioralLearnStatus < 2 {
			logging.GetLogger().Warn().Msgf("resource not ready, uuid: %d", d.ResourceUUID)
			continue
		}

		var status int8
		if d.Enabled {
			status = 3
		} else {
			status = 2
		}
		if res.BehavioralLearnStatus == status {
			logging.GetLogger().Warn().Msgf("resource status not change, uuid: %d", d.ResourceUUID)
			continue
		}
		err = rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("id = ?", d.ResourceUUID).
			Updates(map[string]interface{}{
				"behavioral_learn_status": status,
			}).Error
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("update resource status fail, uuid: %d", d.ResourceUUID)
			continue
		}

		ress = append(ress, res)

		resMap[d.ResourceUUID] = struct{}{}
		success++
	}

	return ress, resMap, success, nil
}

func BehavioralLearnModelOneKeyConfig(ctx context.Context, rdb *gorm.DB, enabled bool) (map[uint32]struct{}, int64, error) {
	success := 0
	res := make(map[uint32]struct{})
	query := ResourcesQuery()
	query = query.WithGreaterEqCondition("behavioral_learn_status", 2)

	resources, err := GetResources(ctx, rdb, query, 0, 0)
	if err != nil {
		return res, 0, err
	}
	var status int8
	if enabled {
		status = 3
	} else {
		status = 2
	}

	for _, resource := range resources {
		if resource.BehavioralLearnStatus < 2 {
			logging.GetLogger().Warn().Msgf("resource not ready, uuid: %d", resource.ID)
			continue
		}

		err = rdb.WithContext(ctx).Model(&model.TensorResource{}).Where("id = ?", resource.ID).
			Updates(map[string]interface{}{
				"behavioral_learn_status": status,
			}).Error
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("update resource status fail, uuid: %d", resource.ID)
			continue
		}
		success++
		res[resource.ID] = struct{}{}
	}

	return res, int64(success), err

}

func BehavioralLearnLogModelOperations(ctx context.Context, rdb *gorm.DB, data []model.BehavioralLearnModelOperationLog) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnModelOperationLog{}).Create(&data).Error
	return err
}

func BehavioralLearnGetModelOperationLog(ctx context.Context, rdb *gorm.DB, resourceUUID uint32, limit, offset int) ([]model.BehavioralLearnModelOperationLog, int64, error) {
	res := []model.BehavioralLearnModelOperationLog{}

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnModelOperationLog{}).Where("resource_uuid = ?", resourceUUID)

	var total int64
	db.Count(&total)
	err := db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	logging.GetLogger().Info().Msgf("res: %+v", res)
	return res, total, nil
}

func BehavioralLearnGetGlobalConfig(ctx context.Context, rdb *gorm.DB) (*model.BehavioralLearnGlobalConfig, error) {
	var res model.BehavioralLearnGlobalConfig

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnGlobalConfig{}).First(&res).Error
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func BehavioralLearnInsertGlobalConfig(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnGlobalConfig) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnGlobalConfig{}).Create(&data).Error

	return err
}

func BehavioralLearnUpdateGlobalConfig(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnGlobalConfig) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnGlobalConfig{}).
		Where("id > ?", 0).
		Updates(map[string]interface{}{
			"ignore_known_attack": data.IgnoreKnownAttack,
			"show_unrelated_res":  data.ShowUnrelatedRes,
			"auto_learn_new_res":  data.AutoLearnNewRes,
			"learn_time":          data.LearnTime,
		}).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnGetFileModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, offset, limit int, searchStr string, permission int) ([]model.BehavioralLearnFileModelGlobalWhiteList, int64, error) {
	var res []model.BehavioralLearnFileModelGlobalWhiteList

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModelGlobalWhiteList{})

	if searchStr != "" {
		db = db.Where("name like ? OR path like ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if permission != 0 {
		db = db.Where("permission = ?", permission)
	}

	var total int64
	db.Count(&total)
	err := db.Order("updated_at DESC").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}

	return res, total, nil
}

func BehavioralLearnInsertFileModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnFileModelGlobalWhiteList) (model.BehavioralLearnFileModelGlobalWhiteList, error) {
	// if exist, return error
	var res []model.BehavioralLearnFileModelGlobalWhiteList
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModelGlobalWhiteList{}).Where("name = ? and path = ? and permission = ?",
		data.Name, data.Path, data.Permission).First(&res).Error

	if err == nil && len(res) > 0 {
		logging.GetLogger().Warn().Msgf("file model global white list exist, name: %s, path: %s, permission: %d", data.Name, data.Path, data.Permission)
		return res[0], errors.New("file model global white list exist")
	}

	err = rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModelGlobalWhiteList{}).Create(&data).Error

	return data, err
}

func BehavioralLearnDeleteFileModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, id int64) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModelGlobalWhiteList{}).Where("id = ?", id).Delete(&model.BehavioralLearnFileModelGlobalWhiteList{}).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnUpdateFileModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnFileModelGlobalWhiteList) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnFileModelGlobalWhiteList{}).Where("id = ?", data.ID).Updates(&data).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnGetCommandModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, offset, limit int, searchStr string) ([]model.BehavioralLearnCommandModelGlobalWhiteList, int64, error) {
	logging.GetLogger().Info().Msgf("get command model global white list, offset: %d, limit: %d", offset, limit)
	var res []model.BehavioralLearnCommandModelGlobalWhiteList

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModelGlobalWhiteList{})

	if searchStr != "" {
		db = db.Where("command like ? OR path like ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	var total int64
	db.Count(&total)
	err := db.Order("updated_at DESC").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	logging.GetLogger().Info().Msgf("res: %+v", res)

	return res, total, nil
}

func BehavioralLearnInsertCommandModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnCommandModelGlobalWhiteList) (model.BehavioralLearnCommandModelGlobalWhiteList, error) {
	// if exist, return error
	var res []model.BehavioralLearnCommandModelGlobalWhiteList

	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModelGlobalWhiteList{}).Where("command = ? and user = ? and path = ?",
		data.Command, data.User, data.Path).First(&res).Error

	if err == nil && len(res) > 0 {
		logging.GetLogger().Warn().Msgf("command model global white list exist, command: %s, user: %s, path: %s", data.Command, data.User, data.Path)

		return res[0], errors.New("command model global white list exist")
	}

	err = rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModelGlobalWhiteList{}).Create(&data).Error

	return data, err
}

func BehavioralLearnDeleteCommandModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, id int64) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModelGlobalWhiteList{}).Where("id = ?", id).Delete(&model.BehavioralLearnCommandModelGlobalWhiteList{}).Error

	return err
}

func BehavioralLearnUpdateCommandModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnCommandModelGlobalWhiteList) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnCommandModelGlobalWhiteList{}).Where("id = ?", data.ID).Updates(&data).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnGetNetworkModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, offset, limit int, searchStr string, streamDirection []int) ([]model.BehavioralLearnNetworkModelGlobalWhiteList, int64, error) {
	var res []model.BehavioralLearnNetworkModelGlobalWhiteList

	db := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModelGlobalWhiteList{})

	if searchStr != "" {
		db = db.Where("port like ? OR name like ? OR namespace like ?", "%"+searchStr+"%", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if len(streamDirection) > 0 {
		db = db.Where("stream_direction in ?", streamDirection)
	}

	var total int64
	db.Count(&total)
	err := db.Order("updated_at DESC").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		return nil, 0, err
	}

	return res, total, nil
}

func BehavioralLearnInsertNetworkModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnNetworkModelGlobalWhiteList) (model.BehavioralLearnNetworkModelGlobalWhiteList, error) {
	// if exist, return error
	var res []model.BehavioralLearnNetworkModelGlobalWhiteList
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModelGlobalWhiteList{}).Where("port = ? and object_resource_uuid = ? and stream_direction = ?",
		data.Port, data.ObjectResourceUUID, data.StreamDirection).First(&res).Error

	if err == nil && len(res) > 0 {
		logging.GetLogger().Warn().Msgf("file model global white list exist, port: %d, object_resource_uuid: %d, stream_direction: %d", data.Port, data.ObjectResourceUUID, data.StreamDirection)
		return res[0], errors.New("file model global white list exist")
	}

	err = rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModelGlobalWhiteList{}).Create(&data).Error

	return data, err
}

func BehavioralLearnDeleteNetworkModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, id int64) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModelGlobalWhiteList{}).Where("id = ?", id).Delete(&model.BehavioralLearnNetworkModelGlobalWhiteList{}).Error

	return err
}

func BehavioralLearnUpdateNetworkModelGlobalWhiteList(ctx context.Context, rdb *gorm.DB, data model.BehavioralLearnNetworkModelGlobalWhiteList) error {
	err := rdb.WithContext(ctx).Model(&model.BehavioralLearnNetworkModelGlobalWhiteList{}).Where("id = ?", data.ID).Updates(&data).Error
	if err != nil {
		return err
	}

	return nil
}

func BehavioralLearnRawContainers(ctx context.Context, rdb *gorm.DB, clusterKey, namespace, kind, resourceName string,
	offset, limit int) ([]model.TensorRawContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := []model.TensorRawContainer{}
	var err error
	if limit > 0 {
		err = rdb.Model(&model.TensorRawContainer{}).WithContext(ctx).
			Where("cluster_key=? and resource_name = ? and namespace = ? and resource_kind=?",
				clusterKey, resourceName, namespace, kind).
			Order("created_at desc").Limit(limit).Offset(offset).
			Find(&res).Error
	} else {
		err = rdb.Model(&model.TensorRawContainer{}).WithContext(ctx).
			Where("cluster_key=? and resource_name = ? and namespace = ? and resource_kind=?",
				clusterKey, resourceName, namespace, kind).
			Order("created_at desc").Find(&res).Error
	}

	if err != nil {
		return nil, err
	}
	return res, nil
}

func BehavioralLearnGetResourceStatus(ctx context.Context, rdb *gorm.DB,
	namespace, resourceName, imageName string, clusterKey, resourceKind []string,
	startTime, endTime int64,
	limit, offset int, learnStatus []int8, showRunning bool) ([]model.TensorResource, int64, error) {
	res := make([]model.TensorResource, 0)
	subQuery := rdb.Select("cluster_key", "namespace", "resource_kind", "resource_name").Table("ivan_assets_raw_containers")
	mainQuery := rdb.Model(&model.TensorResource{}).Where("status = 0")

	if showRunning {
		subQuery = subQuery.Where("status = 0")

		if len(clusterKey) > 0 {
			subQuery = subQuery.Where("cluster_key in ?", clusterKey)
		}
		if len(resourceKind) > 0 {
			subQuery = subQuery.Where("resource_kind in ?", resourceKind)
		}
		if resourceName != "" {
			subQuery = subQuery.Where("resource_name like ?", "%"+resourceName+"%")
		}
		if namespace != "" {
			subQuery = subQuery.Where("namespace like ?", "%"+namespace+"%")
		}
		if imageName != "" {
			subQuery = subQuery.Where("image_name like ?", "%"+imageName+"%")
		}
		mainQuery = mainQuery.Where("(cluster_key, namespace, kind, name) in (?)", subQuery)
	} else {
		if len(clusterKey) > 0 {
			mainQuery = mainQuery.Where("cluster_key in ?", clusterKey)
		}
		if len(resourceKind) > 0 {
			mainQuery = mainQuery.Where("kind in ?", resourceKind)
		}
		if resourceName != "" {
			mainQuery = mainQuery.Where("name like ?", "%"+resourceName+"%")
		}
		if namespace != "" {
			mainQuery = mainQuery.Where("namespace like ?", "%"+namespace+"%")
		}
		if imageName != "" {
			subQuery = subQuery.Where("image_name like ?", "%"+imageName+"%")
			mainQuery = mainQuery.Where("(cluster_key, namespace, kind, name) in (?)", subQuery)
		}
	}

	if len(learnStatus) > 0 {
		mainQuery = mainQuery.Where("behavioral_learn_status in ?", learnStatus)
	}
	if startTime > 0 {
		mainQuery = mainQuery.Where("behavioral_learn_start_time >= ?", startTime)
	}
	if endTime > 0 {
		mainQuery = mainQuery.Where("behavioral_learn_start_time <= ?", endTime)
	}

	var count int64
	err := mainQuery.Count(&count).Error
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get resource status count fail")
		return nil, 0, err
	}

	logging.GetLogger().Debug().Msgf("get resource status count: %d", count)
	logging.GetLogger().Debug().Msgf("get resource status limit: %d, offset: %d", limit, offset)
	err = mainQuery.Order("id ASC").Offset(offset).Limit(limit).Find(&res).Error
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get resource status fail")
		return nil, 0, err
	}
	return res, count, nil
}
