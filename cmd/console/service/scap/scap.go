package scap

import (
	"context"
	"runtime"

	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	kube   = "kube"
	docker = "docker"
	host   = "host"
)

type Service struct {
	rdb        *databases.RDBInstance
	cronServer *cron.Cron
	scap       *scapper.Scapper
}

func NewService(rdb *databases.RDBInstance) *Service {
	cronServer := cron.New(cron.WithParser(cron.NewParser(
		cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
	)))

	scap, _ := scapper.GetScapper(context.Background())
	s := &Service{rdb: rdb, cronServer: cronServer, scap: scap}
	s.initCron()
	cronServer.Start()
	return s
}

func (s *Service) initCron() {

	var cronJob []model.ScapCronRecord
	if err := s.rdb.Get().Find(&cronJob).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		panic("init scap cronjob error")
	}

	for _, v := range cronJob {
		err := s.AddCronJob(context.Background(), v.Cron, &CronJobEntry{
			cronJobId: v.ID,
			version:   v.Version,
			server:    s,
			cron:      v.Cron,
		})
		if err != nil {
			logging.Get().Err(err).Msgf("init scap cronjob error, id: %d, cron: %s", v.ID, v.Cron)
		}
	}
}

// Scap 执行扫描逻辑
func (s *Service) Scap(ctx context.Context, scapType uint8, clusterKey, username string, clusterId, policyId uint) {
	defer func() {
		if e := recover(); e != nil {
			var buf [4096]byte
			n := runtime.Stack(buf[:], false)
			logging.
				Get().
				Error().
				Msgf("扫描失败, type: %d, clusterKey: %s, username: %s, err: %v, stack: %s", scapType, clusterKey, username, e, string(buf[:n]))
		}
	}()

	var checkType model.ComplianceCheckType
	switch scapType {
	case 1:
		checkType = model.ComplianceCheckTargetTypeKube
	case 2:
		checkType = model.ComplianceCheckTargetTypeDocker
	case 3:
		checkType = model.ComplianceCheckTargetTypeHost
	default:
		return
	}

	_, err := s.scap.RunComplianceCheck(clusterKey, checkType, username, clusterId, policyId)
	if err != nil {
		logging.Get().Err(err).Msgf("运行检查失败, type: %d, clusterKey: %s, username: %s", scapType, clusterKey, username)
	}
}

func (s *Service) Do(ctx context.Context, job *Job, clusters []model.ScapClusterInfo) error {
	for _, v := range clusters {
		go s.Scap(context.Background(), job.Type, v.ClusterKey, job.UserName, v.ID, job.PolicyID)
	}

	return nil
}
