package cron

import (
	"context"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/pkg/errors"
	cr "github.com/robfig/cron/v3"
	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	instance *CronService
	once     sync.Once
)

func Init(cron *cr.Cron, rdb *databases.RDBInstance) error {
	if cron == nil || rdb == nil {
		return errors.Errorf("illegal argument")
	}
	once.Do(func() {
		instance = newCronService(cron, rdb)
	})
	return nil
}

func Get(ctx context.Context) (*CronService, bool) {
	return instance, instance != nil
}

type CronService struct {
	cron *cr.Cron
	rdb  *databases.RDBInstance
}

func newCronService(
	cron *cr.Cron,
	rdb *databases.RDBInstance,
) *CronService {
	return &CronService{
		cron: cron,
		rdb:  rdb,
	}
}

func (s *CronService) startCron(ctx context.Context, cronData *model.CronScanTask) error {

	if s.idInCronEntries(cronData.CronId, s.cron.Entries()) {
		s.cron.Remove(cr.EntryID(cronData.CronId))
	}

	newCronID, err := s.cron.AddFunc(cronData.CronTime, func() {
		logging.GetLogger().Info().Msgf("Starting cron job now, clusterId : %v, checkType : %v.", cronData.ClusterID, cronData.CheckType)

		// don't cancel() when exiting this function as we are starting an async task
		scap, _ := scapper.GetScapper(ctx)

		_, err := scap.RunComplianceCheck(cronData.ClusterID, model.ComplianceCheckType(cronData.CheckType), "system", 0, 0, uuid.NewV4().String())
		if err != nil {
			logging.GetLogger().Error().Msgf("failed to run compliance check, clusterId : %v, checkType : %v.", cronData.ClusterID, cronData.CheckType)
		}
		// print debug log
		logging.GetLogger().Info().Msgf("Compliance cron job scheduled successfully, clusterId : %v, checkType : %v.", cronData.ClusterID, cronData.CheckType)

	})

	if err != nil {
		return errors.Errorf("add cron task failed, %v", err)
	}

	if cronData.CronId == 0 {
		cronData.CronId = int(newCronID)
		err = s.rdb.Get().WithContext(ctx).Create(cronData).Error
		if err != nil {
			s.cron.Remove(cr.EntryID(newCronID))
			return errors.Errorf("create cron task to db failed, %v", err)
		}
		return nil
	}
	// update cron task
	cronData.CronId = int(newCronID)
	query := "cluster_id = ? and check_type = ?"
	err = s.rdb.Get().WithContext(ctx).Where(query, cronData.ClusterID, cronData.CheckType).Select("*").Updates(cronData).Error
	if err != nil {
		s.cron.Remove(cr.EntryID(newCronID))
		return errors.Errorf("update cron task failed, %v", err)
	}

	return nil
}

func (s *CronService) StartCrons(ctx context.Context) error {
	return nil // 这里逻辑去掉？是否只有合规使用这个功能？todo 检查是否只有合规在使用这个功能
	// var cronTasks []*model.CronScanTask
	// err := s.rdb.GetReadDB().WithContext(ctx).Find(&cronTasks).Error
	// if err != nil {
	// 	return errors.Errorf("get cron task config failed, %v", err)
	// }
	//
	// for _, cronData := range cronTasks {
	// 	err = s.startCron(ctx, cronData)
	// 	if err != nil {
	// 		logging.GetLogger().Error().Msgf("cron start failed, %v", err)
	// 	}
	// }
	//
	// return nil
}

func (s *CronService) idInCronEntries(id int, cronEntries []cr.Entry) bool {
	if id == 0 {
		return false
	}

	for _, entry := range cronEntries {
		if id == int(entry.ID) {
			return true
		}
	}
	return false
}

func (s *CronService) UpdateCron(ctx context.Context, clusterId string, checkType model.ComplianceCheckType, cronString string) error {
	// get kube client for this cluster
	pgCtx, pgCancel := context.WithTimeout(ctx, time.Second*10)
	defer pgCancel()

	cronData := &model.CronScanTask{
		CreatedAt: time.Now().Unix(),
		CheckType: string(checkType),
		CronTime:  cronString,
		ClusterID: clusterId,
		CronId:    0,
	}

	var cronConfig model.CronScanTask
	query := "cluster_id = ? and check_type = ?"
	_ = s.rdb.GetReadDB().WithContext(pgCtx).First(&cronConfig, query, clusterId, string(checkType)).Error
	// get cron id
	cronData.CronId = cronConfig.CronId
	// start cron
	return s.startCron(ctx, cronData)
}

func (s *CronService) GetCron(ctx context.Context, clusterId string, checkType model.ComplianceCheckType) (*model.CronScanTask, error) {
	// get kube client for this cluster
	pgCtx, pgCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pgCancel()

	var cronInfo model.CronScanTask
	query := "check_type = ? and cluster_id = ?"
	err := s.rdb.GetReadDB().WithContext(pgCtx).First(&cronInfo, query, string(checkType), clusterId).Error
	if err != nil {
		return nil, errors.Errorf("find %v cron task config failed, %v", checkType, err)
	}

	return &cronInfo, nil
}
