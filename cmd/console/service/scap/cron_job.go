package scap

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// CronJobSave 创建或者修改
// 不存在则创建，存在则修改
func (s *Service) CronJobSave(ctx context.Context, cronJob *model.ScapCronRecord, clusters []model.ScapClusterInfo) error {
	var scapType = cronJob.Type

	// 校验policy是否存在
	if err := s.rdb.Get().WithContext(ctx).Where("type = ?", cronJob.Type).
		First(&model.ScapPolicy{}, cronJob.PolicyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("policy <%d> not found", cronJob.PolicyID)
		}

		return fmt.Errorf("policy <%d> verify failed", cronJob.PolicyID)
	}

	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		var old model.ScapCronRecord

		// 通过互斥锁锁锁住 type = scapType 的数据
		err = tx.Model(cronJob).
			Select("id", "version").
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("type = ?", cronJob.Type).
			First(&old).
			Error

		var notExist = errors.Is(err, gorm.ErrRecordNotFound)
		// 当查询失败，且错误不为数据不存在时直接返回错误
		if err != nil && !notExist {
			logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，查询cronjob失败，type:%d", scapType)
			return errors.New("cronjob创建失败")
		}

		// 创建新的集群信息
		err = tx.Create(clusters).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，集群信息保存失败，type:%d", scapType)
			return errors.New("cronjob创建失败")
		}

		var ids = make([]uint, 0, len(clusters))
		for i := range clusters {
			ids = append(ids, clusters[i].ID)
		}

		cronJob.ClusterInfoIds = ids
		cronJob.Version = old.Version + 1 // 版本号+1

		if notExist { // 如果不存在则新创建数据
			err = tx.Create(cronJob).Error
			if err != nil {
				logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，cronjob信息保存失败，type:%d", scapType)
				return errors.New("cronjob创建失败")
			}
		} else { // 存在则修改
			cronJob.ID = old.ID
			err = tx.Select("*").Omit("created_at", "deleted_at").Updates(cronJob).Error
			if err != nil {
				logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，cronjob信息修改失败，type:%d", scapType)
				return errors.New("cronjob 修改失败")
			}
		}

		// 当禁用cronjob的时候，直接返回
		if !cronJob.Status {
			return nil
		}

		err = s.AddCronJob(ctx, cronJob.Cron, &CronJobEntry{cronJobId: cronJob.ID, version: cronJob.Version, server: s, cron: cronJob.Cron})
		if err != nil {
			logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，添加定时任务失败，type:%d, id: %d, cron: %s", scapType, cronJob.ID, cronJob.Cron)
			return errors.New("cronjob 修改失败")
		}

		return nil
	})

	if err != nil {
		logging.GetLogger().Err(err).Msgf("cronjob 操作失败，类型:%d", scapType)
		return errors.New("cronjob创建失败")
	}

	return nil
}

func (s *Service) CronJobDetail(ctx context.Context, scapType string) (*model.ScapCronRecord, []model.ScapClusterInfo, error) {
	var cronJob model.ScapCronRecord
	var clusterInfo []model.ScapClusterInfo
	var db = s.rdb.Get().WithContext(ctx)

	err := db.Model(cronJob).Where("type = ?", scapType).
		First(&cronJob).
		Error

	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logging.GetLogger().Err(err).Msgf("查询cronjob失败，type:%d", scapType)
			return nil, nil, errors.New("cronjob查询失败")
		} else {
			return nil, nil, nil // 当没有数据的时候，直接返回一个空的数据
		}
	}

	// 获取集群信息的id和节点id
	err = db.Model(&model.ScapClusterInfo{}).Where("id IN ?", cronJob.ClusterInfoIds).Find(&clusterInfo).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("查询cronjob失败，查询clusterInfo信息失败, type:%d", scapType)
		return nil, nil, errors.New("cronjob查询失败")
	}

	// 获取集群名和节点名
	wg, nctx := errgroup.WithContext(ctx)
	// 启动goroutine去查询
	for i := range clusterInfo {
		tmp := &clusterInfo[i] // 临时变量避免被shadow
		wg.Go(func() (err error) {
			defer func() {
				if e := recover(); e != nil {
					err = errors.Errorf("panic when get clusterInfo, %v", e)
				}
			}()

			db := s.rdb.Get().WithContext(nctx)
			if err = db.
				Unscoped().
				Model(&model.TensorCluster{}).
				Select("name").
				Where("id = ?", tmp.ClusterKey).
				First(&tmp.ClusterName).
				Error; err != nil {
				return
			}

			// 如果是全部节点的话，不需要查询节点的信息
			if tmp.IsAllNodes {
				return
			}

			if err = db.
				WithContext(nctx).
				Unscoped().
				Model(&model.TensorNode{}).
				Select("host_name").
				Where("id IN ?", tmp.ClusterNodeIds).
				Find(&tmp.ClusterNodeNames).
				Error; err != nil {
				return
			}

			return
		})
	}

	if err := wg.Wait(); err != nil {
		logging.GetLogger().Err(err).Msgf("查询cronjob失败，查询clusterInfo详细信息失败, type:%d", scapType)
		return nil, nil, errors.New("cronjob查询失败")
	}

	return &cronJob, clusterInfo, nil
}

func (s *Service) AddCronJob(ctx context.Context, spec string, cronJob *CronJobEntry) error {
	logging.GetLogger().Info().Msgf("添加cronjob中, id: %d, cron: %s", cronJob.cronJobId, spec)
	_, err := s.cronServer.AddJob("TZ=Asia/Shanghai "+spec, cronJob)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("创建或者更新cronjob失败，添加定时任务失败，id: %d, cron: %s", cronJob.cronJobId, spec)
		return errors.New("cronjob 修改失败")
	}

	return nil
}
