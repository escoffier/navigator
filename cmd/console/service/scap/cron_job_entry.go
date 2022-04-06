package scap

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type CronJobEntry struct {
	cronJobId uint
	version   int64
	server    *Service
	cron      string
}

// 首先先判断版本是否正确，如果版本不正确的话，移除本任务

func (c *CronJobEntry) Run() {
	logging.GetLogger().Info().Msgf("start scap cronjob, cronjob id: %d, cron: %s, version: %d", c.cronJobId, c.cron, c.version)
	ctx := context.Background()
	record, err := c.GetCronJob(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get cronjob record failed")
		return
	}
	// 当当前版本不等于数据库的版本时，移除当前任务
	if c.version != record.Version {
		logging.GetLogger().Info().Msgf("cronjob record expired, remove it, version: %d, id: %d", c.version, c.cronJobId)
		for _, entry := range c.server.cronServer.Entries() {
			if i, ok := entry.Job.(*CronJobEntry); ok {
				if i.cronJobId == c.cronJobId && i.version == c.version {
					c.server.cronServer.Remove(entry.ID)
					logging.GetLogger().Info().Msgf("cronjob record expired, remove it successfully, id: %d, cron: %s, version: %d", c.cronJobId, c.cron, c.version)
				}
			}
		}
		return
	}

	// 当版本是正是现在的版本时，执行扫描逻辑

	// 首先向redis插入一条数据，数据存在则说明已经有节点在执行此任务
	key := fmt.Sprintf("scap-cron-job-%d-%d-%s", record.ID, record.Version, time.Now().Format("2006-01-02"))
	redisCli, _ := store.GetRedisClient(0)
	setResult := redisCli.SetNX(ctx, key, "", time.Hour)
	if ok, err := setResult.Result(); err != nil || !ok {
		logging.GetLogger().Info().Msgf("启动scap cronjob 失败, isExist: %v, err: %v", ok, err)
		return
	}

	// 获取扫描的集群信息
	var cluster []model.ScapClusterInfo
	if c.server.rdb.Get().WithContext(ctx).Where("id IN ?", record.ClusterInfoIds).Find(&cluster).Error != nil {
		logging.GetLogger().Err(err).Msgf("启动定时任务失败，获取集群信息失败，cron:%d, version:%d", record.ID, record.Version)
		return
	}

	job := &Job{Type: record.Type, UserName: record.Operator}
	job.PolicyID = record.PolicyId

	logging.GetLogger().Info().Msgf("start scap cronjob check, cronjob id: %d, cron: %s, version: %d", c.cronJobId, c.cron, c.version)

	_ = c.server.Do(ctx, job, cluster) // 启动job
}

func (c *CronJobEntry) GetCronJob(ctx context.Context) (*model.ScapCronRecord, error) {
	var record model.ScapCronRecord
	err := c.server.rdb.Get().WithContext(ctx).Where("id = ?", c.cronJobId).First(&record).Error
	if err != nil {
		return nil, err
	}

	return &record, nil
}
