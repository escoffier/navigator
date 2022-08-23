package scap

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	pkgasserts "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	batchv1 "k8s.io/api/batch/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	kube   = "kube"
	docker = "docker"
	host   = "host"
)

type Service struct {
	rdb         *databases.RDBInstance
	cronServer  *cron.Cron
	scap        *scapper.Scapper
	redisClient *redis.Client
}

func NewService(rdb *databases.RDBInstance, redisClient *redis.Client) *Service {
	cronServer := cron.New(cron.WithParser(cron.NewParser(
		cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
	)))

	scap, _ := scapper.GetScapper(context.Background())
	s := &Service{rdb: rdb, cronServer: cronServer, scap: scap, redisClient: redisClient}
	s.initCron()
	cronServer.Start()

	go s.StateSyncDaemon() // 这里启动一个goroutine用作合规的job状态同步

	return s
}

func (s *Service) initCron() {

	var cronJob []model.ScapCronRecord
	if err := s.rdb.Get().Find(&cronJob).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		panic("init scap cronjob error")
	}

	for _, v := range cronJob {
		err := s.AddCronJob(context.Background(), v.Cron, &CronJobEntry{
			cronJobId:   v.ID,
			version:     v.Version,
			server:      s,
			cron:        v.Cron,
			redisClient: s.redisClient,
		})
		if err != nil {
			logging.Get().Err(err).Msgf("init scap cronjob error, id: %d, cron: %s", v.ID, v.Cron)
		}
	}
}

// Scap 执行扫描逻辑
func (s *Service) Scap(ctx context.Context, scapType uint8, clusterKey, username string, clusterId, policyId uint, checkUUID string) {
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

	_, err := s.scap.RunComplianceCheck(clusterKey, checkType, username, clusterId, policyId, checkUUID)
	if err != nil {
		logging.Get().Err(err).Msgf("运行检查失败, type: %d, clusterKey: %s, username: %s", scapType, clusterKey, username)
	}
}

func (s *Service) Do(ctx context.Context, job *Job, clusters []model.ScapClusterInfo) error {
	for _, v := range clusters {
		go s.Scap(context.Background(), job.Type, v.ClusterKey, job.UserName, v.ID, job.PolicyID, v.CheckUUID)
	}

	return nil
}

// StateSyncDaemon 用于同步扫描任务的的状态
// 通过一个循环，获取到所有 运行中 的任务，查看它们的启动时间和与当前时间的间隔是否大于过期时间
// 大于过期时间的话，说明次任务已经过期，则把任务修改为完成，并且把未完成的子任务改为失败，然后通过标签删除所有的job
func (s *Service) StateSyncDaemon() {

	logging.
		Get().
		Info().
		Msg("scap StateSyncDaemon, scap StateSyncDaemon start")

	var timeout = time.Hour

	if t := os.Getenv("SCAP_JOB_TIMEOUT"); t != "" {
		var err error
		timeout, err = time.ParseDuration(t)
		if err != nil {
			logging.
				Get().
				Warn().
				Str("func", "scap StateSyncDaemon").
				Msgf("environment variable `SCAP_JOB_TIMEOUT` is %q, it not a valid Duration value. Use default value: 1h.", t)
		}
	} else {
		logging.
			Get().
			Info().
			Str("func", "scap StateSyncDaemon").
			Msgf("environment variable `SCAP_JOB_TIMEOUT` not be set. Use default value: 1h.", t)
	}

	interval := 60 * time.Second
	if t := os.Getenv("SCAP_JOB_INTERVAL"); t != "" {
		var err error
		interval, err = time.ParseDuration(t)
		if err != nil {
			logging.
				Get().
				Warn().
				Str("func", "scap StateSyncDaemon").
				Msgf("environment variable `SCAP_JOB_INTERVAL` is %q, it not a valid Duration value. Use default value: 30s.", t)
			interval = 60 * time.Second
		}
	} else {
		logging.
			Get().
			Info().
			Str("func", "scap StateSyncDaemon").
			Msgf("environment variable `SCAP_JOB_INTERVAL` not be set. Use default value: %v", interval)
	}

	logging.
		Get().
		Info().
		Str("func", "scap StateSyncDaemon").
		Msgf("scap job timeout: %v. interval: %v", timeout, interval)

	if timeout < 0 || interval < 0 {
		panic("timeout or interval must be positive duration")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		go func() {
			defer func() {
				if e := recover(); e != nil {
					logging.Get().Error().Msgf("scap StateSyncDaemon, run err: %v, panic: \n%s", e, debug.Stack())
				}
			}()

			// 执行同步逻辑
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			defer cancel()

			histories, err := s.getInProgressJobs(ctx)
			if err != nil {
				logging.Get().
					Err(err).
					Str("func", "scap StateSyncDaemon").
					Msg("get in progress jobs error")
			}

			eg, newCtx := errgroup.WithContext(ctx)
			for _, v := range histories {
				his := v

				eg.Go(func() (err error) {

					defer func() {
						if e := recover(); e != nil {
							err = fmt.Errorf("handle scap inprogress job panic: \n%s", debug.Stack())
						}
					}()

					var reason string
					// 检查是否过期
					// 如果已经过期了，则把所有对应的job都删除了，然后把 inprogress 的任务都设置为失败，原因：timeout
					// 如果还没有过期，则获取所有的job，判断状态，如果都是成功，则把任务设置为成功, 并且把数据库还处于 inprogress 状态的置为失败
					if time.Now().Add(-1*timeout).Unix() <= his.CreatedAt {
						jobList, err := s.getK8sJobsList(ctx, his)

						if err != nil {
							logging.Get().
								Err(err).
								Str("func", "scap StateSyncDaemon").
								Str("check task id", his.TaskID).
								Msg("get k8s jobs list failed")
							// return error will cause it to retryfor the next time. retry for the following specific reasons.
							if k8sErrors.IsServiceUnavailable(err) || k8sErrors.IsTimeout(err) || k8sErrors.IsServerTimeout(err) || k8sErrors.IsInternalError(err) ||
								k8sErrors.IsUnexpectedServerError(err) {
								return err
							}
						} else {
							for _, v := range jobList.Items {
								// 当有一个job还未完成，则说明扫描任务还未完成，等待下一个循环更新状态
								// 因为合规的job只有一个pod在执行，因此直接判断是否有成功的pod即可
								if v.Status.Succeeded == 0 {
									return nil
								}
							}
						}

						// 如果所有job的成功了，则需要把数据库中还在运行的任务都改为失败
						reason = "executing failed"
					} else {
						// 如果超时，则删除对应k8s的job
						err = s.deleteK8sJobs(newCtx, his)
						if err != nil {
							logging.Get().
								Err(err).
								Str("func", "scap StateSyncDaemon").
								Str("check task id", his.TaskID).
								Msg("delete k8s jobs failed")
							// return error will cause it to retryfor the next time. retry for the following specific reasons.
							if k8sErrors.IsServiceUnavailable(err) || k8sErrors.IsTimeout(err) || k8sErrors.IsServerTimeout(err) || k8sErrors.IsInternalError(err) ||
								k8sErrors.IsUnexpectedServerError(err) {
								return err
							}
						}

						reason = "timeout"
					}

					// 将子任务设置为失败，并设置失败原因
					err = s.updateSubJobToFailed(ctx, his.TaskID, reason)
					if err != nil {
						logging.Get().
							Err(err).
							Str("func", "scap StateSyncDaemon").
							Str("check task id", his.TaskID).
							Msg("update sub job to fail failed")
						return err
					}

					// 将主任务设置为 完成
					err = s.updateJobToSuccess(ctx, his.TaskID)
					if err != nil {
						logging.Get().
							Err(err).
							Str("func", "scap StateSyncDaemon").
							Str("check task id", his.TaskID).
							Msg("update job to success failed")
						return err
					}

					return nil
				})
			}

			err = eg.Wait()

			if err != nil {
				logging.Get().
					Err(err).
					Str("func", "scap StateSyncDaemon").
					Msg("handle scap histories error")
			}
		}()
	}

}

// 获取正在执行的jobs
func (s *Service) getInProgressJobs(ctx context.Context) ([]*model.ScanHistory, error) {
	var histories []*model.ScanHistory
	err := s.rdb.
		Get().
		Model(&model.ScanHistory{}).
		WithContext(ctx).
		Where("state = ?", model.ScanStateInProgress).
		Find(&histories).
		Error

	return histories, err
}

func (s *Service) getClusterInfo(ctx context.Context, clusterKey string) (*model.TensorCluster, error) {
	// get namespaces
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return nil, errors.New("get resources service error")
	}

	cluster := resSvc.GetClusterByKey(ctx, clusterKey)
	if len(cluster.WorkerNamespace) == 0 {
		return nil, errors.New("error namespace, it's empty")
	}

	return cluster, nil
}

func (s *Service) getK8sClient(_ context.Context, clusterKey string) (*pkgasserts.Clientset, error) {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, errors.New("get cluster falied")
	}

	// get client
	k8sClient, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return nil, errors.New("get k8s client error")
	}

	return k8sClient, nil
}

// 通过label删除对应的k8s jobs
func (s *Service) deleteK8sJobs(ctx context.Context, his *model.ScanHistory) error {
	cluster, err := s.getClusterInfo(ctx, his.ClusterKey)
	if err != nil {
		return err
	}

	k8sClient, err := s.getK8sClient(ctx, his.ClusterKey)
	if err != nil {
		return err
	}

	// labels
	labelSet := labels.SelectorFromSet(labels.Set{"CHECK_ID": his.TaskID})
	// delete these jobs which with label
	return k8sClient.BatchV1().
		Jobs(cluster.WorkerNamespace).
		DeleteCollection(
			ctx,
			v1.DeleteOptions{},
			v1.ListOptions{LabelSelector: labelSet.String()},
		)
}

// 将job更新为完成
func (s *Service) updateJobToSuccess(ctx context.Context, taskId string) error {
	// 获取到成功与失败的个数

	type count struct {
		State model.ScanState `gorm:"column:state"`
		Count int32           `gorm:"column:count"`
	}

	var counts []count
	err := s.rdb.Get().
		WithContext(ctx).
		Select([]string{"state", "COUNT(*) count"}).
		Model(&model.ScanNodeRecord{}).
		Where("task_id = ?", taskId).
		Group("state").
		Find(&counts).
		Error

	if err != nil {
		return errors.WithMessage(err, "get count error")
	}

	updates := map[string]interface{}{"state": model.ScanStateCompleted, "finished_at": time.Now().Unix()}
	for _, v := range counts {
		switch v.State {
		case model.ScanStateCompleted:
			updates["suc_node"] = v.Count
		case model.ScanStateFailed:
			updates["fail_node"] = v.Count
		}
	}

	err = s.rdb.
		Get().
		WithContext(ctx).
		Model(&model.ScanHistory{}).
		Where("task_id = ?", taskId).
		Where("state = ?", model.ScanStateInProgress).
		Updates(updates).
		Error

	if err != nil {
		return errors.WithMessage(err, "update history state failed")
	}

	return nil
}

// 将子任务更新为失败
func (s *Service) updateSubJobToFailed(ctx context.Context, taskId, reason string) error {
	err := s.rdb.
		Get().
		Model(&model.ScanNodeRecord{}).
		WithContext(ctx).
		Where("task_id = ?", taskId).
		Where("state = ?", model.ScanStateInProgress).
		Updates(
			map[string]interface{}{
				"state":       model.ScanStateFailed,
				"finished_at": time.Now().Unix(),
				"message":     reason,
			},
		).
		Error

	return err
}

func (s *Service) getK8sJobsList(ctx context.Context, his *model.ScanHistory) (*batchv1.JobList, error) {
	cluster, err := s.getClusterInfo(ctx, his.ClusterKey)
	if err != nil {
		return nil, err
	}

	k8sClient, err := s.getK8sClient(ctx, his.ClusterKey)
	if err != nil {
		return nil, err
	}
	labelSet := labels.SelectorFromSet(labels.Set{"CHECK_ID": his.TaskID})

	return k8sClient.
		BatchV1().
		Jobs(cluster.WorkerNamespace).
		List(ctx, v1.ListOptions{LabelSelector: labelSet.String()})
}
