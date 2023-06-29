package scapper

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

type Scapper struct {
	myNamespace          string
	myResourceNamePrefix string
	ClusterAddr          string
	rdb                  *databases.RDBInstance
	ScapService          *ScapService
	stream               rpcstream.MessageStream
}

const (
	// Potentially move to config file.

	checkTimeout           = time.Hour * 1
	historicalChecksToKeep = 3
	jobLabel               = "SCAPPER"
	jobStatusSucceed       = "success"
	jobStatusFailed        = "failed"
	jobStatusRunning       = "running"
)

type EnvironmentInfo struct {
	MyNamespace string
	MyPodName   string
}

func getPrefixOfName(name string) string {
	pos := strings.Index(name, "-console")
	if pos >= 0 {
		return name[:pos]
	}
	return ""
}

func newScapper(
	envInfo EnvironmentInfo,
	scapOpts *flag.ScapOpts,
	scapService *ScapService,
	rdb *databases.RDBInstance,
	stream rpcstream.MessageStream,
) *Scapper {
	if len(envInfo.MyNamespace) == 0 {
		envInfo.MyNamespace = "tensorsec"
	}
	prefix := "tensorsec"
	if len(envInfo.MyPodName) > 0 {
		prefix = getPrefixOfName(envInfo.MyPodName)
		if prefix == "" {
			prefix = "tensorsec"
		}
	}

	s := &Scapper{
		myNamespace:          envInfo.MyNamespace,
		myResourceNamePrefix: prefix,
		ScapService:          scapService,
		rdb:                  rdb,
		ClusterAddr:          scapOpts.ClusterAddr,
		stream:               stream,
	}

	return s
}

// setCheckHistoryFinishedAndJobStatusesFailed set all checkHistories and xxx-bench-records tasks finished and failed
func (s *Scapper) setCheckHistoryFinishedAndJobStatusesFailed(ctx context.Context, check model.Check, msg string) error {
	cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	scanRecord := &model.ScanNodeRecord{
		FinishedAt: time.Now().Unix(),
		State:      model.ScanStateFailed,
		Message:    msg,
	}

	err := util.RetryWithBackoff(cleanCtx, func() error {
		tbname := scanRecord.TableName()
		checkId := check.CheckUUID
		ret := s.rdb.Get().WithContext(cleanCtx).Table(tbname).
			Select("state", "finished_at", "message").
			Where("state = ?", model.ScanStateInProgress).
			Where("task_id = ?", checkId).Updates(scanRecord).Error
		if ret != nil {
			logging.Get().WithContext(cleanCtx).Errorf(ret, "update scan record failed, checkID : %s", check.CheckUUID)
		}
		return ret
	})

	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "Failed the scap update job status setting failed. checkID: %s", check.CheckUUID)
	}

	return err
}

// checkCheckStatusWithDelay check and update the status with given delayed time
func (s *Scapper) checkCheckStatusWithDelay(check model.Check, delayedTime time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic when timer to set task timeout: %v. Stack: %s", r, debug.Stack())
		}
	}()

	timerCtx, cancel := context.WithDeadline(context.Background(), delayedTime)
	defer cancel()

	<-timerCtx.Done()
	logging.Get().Warn().Msgf("Task timeout when console boots, try to finish these tasks")

	msg := "timeout in booting delayed timeout checking"
	err := s.setCheckHistoryFinishedAndJobStatusesFailed(context.Background(), check, msg)
	if err == nil {
		logging.Get().Info().Msgf("Booting check: unfinished job %+v setting finished.", check)
	} else {
		logging.Get().Err(err).Msgf("Booting check Error: unfinished job %+v setting finished fail.", check)
	}
}

// initCheckUnFinishedJobs will check all unfinished jobs, setting them finished if timeout.
// it's used to prevent the case: ongoing jobs are watched by console to set timeout; if console crashed or redeployed, these jobs will lose watches and being unfinished.
func (s *Scapper) InitCheckUnFinishedJobs(ctx context.Context) error {
	nowStamp := time.Now().Unix()
	tCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var scanHistory []model.ScanHistory
	err := s.rdb.Get().WithContext(tCtx).Where("finished_at = 0 AND schedule_type='job'").Find(&scanHistory).Error
	if err != nil {
		return errors.Errorf("get scan history list failed, %v", err)
	}

	for _, value := range scanHistory {
		check := model.Check{
			CheckType: value.CheckType,
			CheckUUID: value.TaskID,
			ClusterID: value.ClusterKey,
			Operator:  value.Operator,
		}

		if value.CreatedAt > 0 && nowStamp-value.CreatedAt > int64(checkTimeout/time.Second) {
			logging.Get().Warn().Msgf("Task timeout when console boots, try to finish task %+v", value)

			err := s.setCheckHistoryFinishedAndJobStatusesFailed(context.Background(), check, "timeout in booting timeout check")
			if err != nil {
				logging.Get().Err(err).Msgf("Booting check Error: unfinished job %+v setting finished fail.", check)
				continue
			}

			logging.Get().Info().Msgf("Booting check: unfinished job %+v setting finished.", check)
		} else { // not timeout, we should set up a customized timer to set timeout: when timeout reaches, we set the job finished.
			logging.Get().Warn().Msgf("Task timeout when console boots, try to watch the task async: %+v", value)

			createTs := nowStamp
			if value.CreatedAt > 0 {
				createTs = value.CreatedAt
			}
			createTime := time.Unix(createTs, 0)
			dalayedTime := createTime.Add(checkTimeout)

			go s.checkCheckStatusWithDelay(check, dalayedTime)
		}
	}

	return nil
}

func (s *Scapper) checkTargetTypeTasksStillInProgress(ctx context.Context, checkType, clusterID string) bool {
	pgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var scanTask model.ScanHistory
	err := s.rdb.Get().WithContext(pgCtx).
		Where("check_type = ? and cluster_key = ? and state = ?", checkType, clusterID, model.ScanStateInProgress).
		First(&scanTask).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logging.Get().Info().Msgf("check target type no tasks still in progress: checkType:%s, clusterId: %s", checkType, clusterID)
		} else {
			logging.Get().Error().Err(err).
				Msgf("check target type tasks still in progress error: checkType:%s, clusterId: %s", checkType, clusterID)
		}
		return false
	}
	// task id
	if scanTask.TaskID == "" || scanTask.CheckType != checkType {
		return false
	}
	// task state
	if scanTask.State == model.ScanStateInProgress {
		logging.Get().Info().
			Str("checkType", checkType).
			Str("clusterKey", clusterID).
			Msgf("taskId: %s, state: %d,  in progress", scanTask.TaskID, scanTask.State)

		return true
	}

	return false
}

func (s *Scapper) RunComplianceCheck(
	clusterID string,
	checkType model.ComplianceCheckType,
	username string,
	clusterInfoID uint,
	policyID uint,
	checkUUID string,
) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	var check = model.Check{
		CheckType: string(checkType),
		CheckUUID: checkUUID,
		ClusterID: clusterID,
		Operator:  username,
		PolicyID:  policyID,
	}

	// create scan history
	scanHistory := model.ScanHistory{
		TaskID:     check.CheckUUID,
		Operator:   check.Operator,
		CheckType:  check.CheckType,
		CreatedAt:  time.Now().Unix(),
		ClusterKey: check.ClusterID,
		PolicyID:   policyID,
	}

	// get cluster manager
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get cluster manager failed"))
	}
	// get k8s client
	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get k8s client failed, cluster id: %s", clusterID))
	}

	// 默认设置集群版本为2.18.0
	var clusterVersion, _ = version.NewVersion("2.18.0")
	_, tag, err := k8s.GetTargetClusterImageSplitInfo(ctx, kubeClient, s.myResourceNamePrefix, s.myNamespace)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("k8s.GetTargetClusterImageSplitInfo failed")
	} else {
		if tagVersion, err := version.NewVersion(tag); err != nil {
			logging.Get().Warn().Err(err).Str("imageTag", tag).Msg("parse cluster version failed")
		} else {
			clusterVersion = tagVersion
		}
	}

	logging.Get().Info().Str("clusterID", clusterID).
		Msgf("the cluster version of this compliance scan is %s", clusterVersion.String())

	// 设置环境变量 SCAP_JOB_ENABLED=true 将使用原有job方式扫描
	// 默认调度到daemon扫描
	// 需要集群版本再2.18以上才支持daemon扫描
	daemonScanBenchVersion, _ := version.NewVersion("2.18.0")
	if os.Getenv("SCAP_JOB_ENABLED") != "true" &&
		clusterVersion.GreaterThanOrEqual(daemonScanBenchVersion) {
		var cluster *model.TensorCluster
		err := func() error {
			clusterInfo, err := s.getCluster(ctx, clusterInfoID)
			if err != nil {
				return err
			}

			cluster = dal.GetClustersByKey(ctx, s.rdb.GetReadDB(), clusterInfo.ClusterKey)
			if cluster == nil {
				return fmt.Errorf("scap get cluster info failed")
			}

			if s.checkTargetTypeTasksStillInProgress(ctx, string(checkType), clusterID) {
				return fmt.Errorf("currently there are tasks still running")
			}

			db := s.rdb.Get().WithContext(ctx).Model(&model.TensorNode{}).
				Select("host_name AND cluster_key = ?", clusterID).Where("status=0")
			if !clusterInfo.IsAllNodes {
				db = db.Where("id IN ?", clusterInfo.ClusterNodeIds)
			}

			var nodes []string
			if err = db.Find(&nodes).Error; err != nil {
				return apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("can't list nodes name in this cluster from db: %v", err))
			}

			var checks []string
			checks, err = getCheckIds(ctx, s.rdb, policyID)
			if err != nil {
				return err
			}

			if checkType == model.ComplianceCheckTargetTypeDocker {
				checkType = model.ComplianceCheckTargetTypeCRI
			}

			for _, name := range nodes {
				req := pb.ComplianceScanReq{
					ClusterKey: clusterID,
					NodeName:   name,
					RequestID:  checkUUID,
					CheckIds:   checks,
					CheckType:  string(checkType),
				}

				var resp *pb.CommonReponse
				status := model.ScanStateInProgress

				resp, err = s.stream.PushComplianceScan(ctx, clusterID, &req)
				if err != nil {
					status = model.ScanStateFailed
					logging.Get().Error().Err(err).Msg("PushComplianceScan error")
				} else {
					logging.Get().Debug().Msgf("PushComplianceScan resp: %v", resp)
				}

				message := ""
				if resp != nil && resp.Status != 0 {
					status = model.ScanStateFailed
					message = resp.StatusMessage
				}

				check.NodeName = name
				err = s.dbAddDaemonStatusInProgress(ctx, &check, status, message, "daemon")
				if err != nil {
					logging.Get().Err(err).Msgf("set node %s daemon for check task %+v error", name, check)
				}
			}

			return nil
		}()

		scanHistory.ClusterName = cluster.Name
		scanHistory.ScheduleType = "daemon"

		if err != nil {
			logging.Get().Warn().Err(err).Msg("")

			scanHistory.State = model.ScanStateFailed
			scanHistory.FinishedAt = scanHistory.CreatedAt
		} else {
			scanHistory.State = model.ScanStateInProgress
		}

	} else {
		var cluster = new(model.TensorCluster)
		var nodes []corev1.Node
		var jobObj *batchv1.Job

		// 用个闭包接收错误，用来记录 失败 状态
		_, err := func() (string, error) {
			// get namespaces
			resSvc, ok := assets.GetResourcesService(ctx)
			if !ok {
				return "", apperror.NewResourceNotFoundError(http.StatusInternalServerError, errors.Errorf("get resource failed"))
			}
			cluster = resSvc.GetClusterByKey(ctx, clusterID)
			if cluster == nil {
				return "", apperror.NewClusterDoesntExistError(http.StatusInternalServerError, errors.Errorf("get cluster failed clusterId : %v", clusterID))
			}
			namespace := cluster.WorkerNamespace
			if namespace == "" {
				return "", apperror.NewClusterError(http.StatusInternalServerError, errors.Errorf("get namespaces failed with run compliance check"))
			}

			check.Namespace = namespace

			if err := s.syncJobState(ctx, string(checkType), clusterID); err != nil {
				return "", err
			}

			if s.checkTargetTypeTasksStillInProgress(ctx, string(checkType), clusterID) {
				return "", apperror.NewCheckAlreadyInProgressError(http.StatusInternalServerError, errors.Errorf("currently there are tasks still running"))
			}

			// get cluster manager
			// clusterManager, ok := k8s.GetClusterManager()
			// if !ok {
			// 	return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get cluster manager failed"))
			// }
			// // get k8s client
			// kubeClient, ok = clusterManager.GetClient(clusterID)
			// if !ok {
			// 	return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get k8s client failed, cluster id: %s", clusterID))
			// }

			err := s.garbageCollectHistoricalJobs(ctx, kubeClient, checkType, namespace)
			if err != nil {
				return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to garbage collect historical jobs: %v", err))
			}

			clusterInfo, err := s.getCluster(ctx, clusterInfoID)
			if err != nil {
				return "", err
			}

			// 兼容老版本扫描镜像
			benchVersion, _ := version.NewVersion("2.13.1")

			jobObj, err = s.prepareJobObject(ctx, &check, clusterVersion.LessThan(benchVersion))
			if err != nil {
				return "", err
			}

			s.modifyJob(checkType, jobObj, cluster)

			nodes, err = s.getNodes(ctx, kubeClient, clusterInfo)
			if err != nil {
				return "", apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list nodes in this cluster: %v", err))
			}

			// schedule jobs
			logging.Get().Info().
				Str("check-type", check.CheckType).Str("check-cluster", check.ClusterID).Str("check-uuid", check.CheckUUID).
				Str("namespace", check.Namespace).Str("operator", check.Operator).
				Int("node-items-num", len(nodes)).Msg("Scheduling SCAP check jobs")

			for i := range nodes {
				// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
				// or do we not care about this since this is a rare operation?
				err = s.dbAddJobStatusInProgress(ctx, &check, &nodes[i])
				if err != nil {
					logging.Get().Err(err).Msgf("set node %s for check task %+v error", nodes[i].Name, check)
					continue
				}
			}

			return checkUUID, nil
		}()

		if err != nil {
			logging.Get().Err(err).Msg("start job error")
		}

		scanHistory.ClusterName = cluster.Name
		scanHistory.ScheduleType = "job"

		if err != nil {
			scanHistory.State = model.ScanStateFailed
			scanHistory.FinishedAt = scanHistory.CreatedAt
		} else {
			scanHistory.State = model.ScanStateInProgress
			// async context is rooted in application context
			go s.asyncScheduleAndManageJobs(kubeClient, &check, jobObj, nodes, cluster.Name)
		}
	}

	err = s.rdb.Get().WithContext(ctx).Create(scanHistory).Error
	if err != nil {
		logging.Get().Err(err).Msgf("create scan history failed, operator : %v, checkType : %v, task id : %v.", check.Operator, check.CheckType, scanHistory.TaskID)
	}

	return checkUUID, nil
}

func (s *Scapper) RunExportFileTask(task *model.ExportTask) {
	// export file to xlsx
	err := s.ScapService.GetScanResultToFile(task)
	// print debug log
	// logging.Get().Info().Msgf("save scan result to xlsx over!!")
	// update task status
	finishedAt := time.Now().Unix()
	task.Status = 0
	if err != nil {
		task.Status = 2
		finishedAt = 0
		logging.Get().Error().Msgf("run export file task failed! %v.", err)
	} else {
		task.Content, err = s.ScapService.GetFileData(task.FileName)
		if err != nil {
			logging.Get().Error().Msgf("get file content failed, %v.", err)
		}
		// remove file
		_ = os.Remove(task.FileName)
	}
	// set timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// save finish time
	task.FinishedAt = finishedAt
	// update mongo data
	tbname := task.TableName()
	err = s.rdb.Get().WithContext(ctx).Table(tbname).Select("status", "finished_at", "content").Where("task_id = ? and username = ?", task.CheckId, task.UserName).Updates(&task).Error
	if err != nil {
		logging.Get().Error().Msgf("update export file task state failed! %v.", err)
	}
}

func (s *Scapper) garbageCollectHistoricalJobs(ctx context.Context, kubeClient *pkgassets.Clientset, checkType model.ComplianceCheckType, namespace string) error {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			jobLabel: "true",
		},
	}
	listOpts := metav1.ListOptions{}
	listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()

	jobs, err := kubeClient.BatchV1().Jobs(namespace).List(ctx, listOpts)
	if err != nil {
		return apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list jobs in this cluster: %v", err))
	}

	// Find the start time of the earliest job in each check
	startTimesOfChecks := make(map[string]time.Time)
	for _, job := range jobs.Items {
		checkID, ok := job.Labels["CHECK_ID"]
		if !ok {
			return apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Expected CHECK_ID label to be present"))
		}

		if job.Status.StartTime == nil {
			logging.Get().Info().Str("job-name", job.Name).Msg("StartTime is nil, skipping")
			continue
		}
		thisJobStartTime := job.Status.StartTime.Time

		earliestJobStartTimeSoFar, ok := startTimesOfChecks[checkID]
		if !ok {
			startTimesOfChecks[checkID] = thisJobStartTime
		} else if earliestJobStartTimeSoFar.After(thisJobStartTime) {
			startTimesOfChecks[checkID] = thisJobStartTime
		}
	}

	// We will be scheduling an additional check, so to keep historicalChecksToKeep, we must remove an additional one.
	// E.g. if there are 10 checks in history, and we have historicalChecksToKeep==3, we must remove 8,
	// so that there are 2 historical left. Because in a second, a new one will be scheduled (for a total of 3 historical).
	actualHistoricalChecksToKeep := historicalChecksToKeep - 1

	// check if there are enough historical checks to warrant further deletion steps.
	if len(startTimesOfChecks) <= actualHistoricalChecksToKeep {
		return nil
	}

	// Sort by start time
	type tempSortKeyValStruct struct {
		CheckID   string
		StartTime time.Time
	}
	var checksByStartTime []tempSortKeyValStruct
	for k, v := range startTimesOfChecks {
		checksByStartTime = append(checksByStartTime, tempSortKeyValStruct{k, v})
	}
	sort.Slice(checksByStartTime, func(i, j int) bool {
		return checksByStartTime[i].StartTime.Before(checksByStartTime[j].StartTime)
	})

	// Pop newest checks
	// note: we already checked boundary condition (array too short) before.
	checksByStartTime = checksByStartTime[:len(checksByStartTime)-actualHistoricalChecksToKeep]

	// Delete the job objects of remaining checks
	for _, job := range jobs.Items {
		// already validated that this label exists
		checkID, ok := job.Labels["CHECK_ID"]
		if !ok {
			continue
		}

		for _, toDelete := range checksByStartTime {
			if checkID != toDelete.CheckID {
				continue
			}

			err = s.deleteJobAndPods(ctx, kubeClient, namespace, job)
			if err != nil {
				return apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to cleanup historical job: %v", err))
			}
			logging.Get().Info().Str("job-name", job.Name).Msg("Cleaned up historical job")
			break
		}
	}

	return nil
}

func (s *Scapper) asyncScheduleAndManageJobs(kubeClient *pkgassets.Clientset, check *model.Check, jobObj *batchv1.Job, nodes []corev1.Node, clusterName string) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	scheduledNodesCh := make(chan string, len(nodes))
	finishedNodesCh, listenerStopCh, cacheSynced := s.startAsyncStatusListener(ctx, kubeClient, check, len(nodes))

	if !cacheSynced {
		logging.Get().Warn().Msg("Informer cache failed to sync, not sure how to handle this. Ignoring.")
	}

	go s.awaitAndUpdateJobsStatuses(check, scheduledNodesCh, finishedNodesCh, listenerStopCh)

FOR:
	for _, targetNode := range nodes {
		select {
		case <-ctx.Done():
			logging.Get().Error().Err(ctx.Err()).Msg("Ctx timeout while scheduling jobs")
			close(scheduledNodesCh)
			return
		default:
			// TODO: will it scale?
			// Note: I think it's safe to run this as goroutine for each job,
			// but I don't know if we should spam kube api this way...
			// I know kubeClient has some built in rate limiting so maybe it's ok?
			// Note2: but we must close scheduledNodesCh after all jobs were scheduled.
			// go func() {
			// create job name

			if !pkgassets.NodeIsReady(&targetNode) {
				continue FOR
			}

			nodeName := targetNode.Name

			jobName := s.CreateJobName(check.CheckUUID, check.CheckType, nodeName)
			// schedule job
			err := s.scheduleOneJob(ctx, kubeClient, check, jobObj.DeepCopy(), clusterName, jobName, nodeName, targetNode.Status.NodeInfo.Architecture)
			if err != nil {
				logging.Get().Error().Msgf("Failed to schedule job, %v.", err)

				msg := fmt.Sprintf("Failed to schedule job: %s", err)

				err = s.dbJobStatusUpdate(model.ScanStateFailed, check, nodeName, msg, time.Now().Unix())
				if err != nil {
					logging.Get().Err(err).Msgf("update job status failed, msg: %s", msg)
				}
				//
				finishedNodesCh <- nodeName
			} else {
				scheduledNodesCh <- nodeName
			}
		}
	}

	close(scheduledNodesCh)
}

func getCheckIds(ctx context.Context, db *databases.RDBInstance, policyId uint) ([]string, error) {
	var policy model.ScapPolicy
	var checkIds []string
	if err := db.Get().WithContext(ctx).Unscoped().First(&policy, policyId).Error; err != nil {
		return nil, err
	}

	if policy.IsDefault {
		// 陆金所默认策略只扫描这些合规项
		if os.Getenv("SCAP_LJS_ENABLED") == "true" {
			if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeDocker {
				checkIds = []string{
					"1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.8", "1.2.9", "1.2.10", "1.2.11", "1.2.12",
					"2.3", "2.5", "2.6", "2.12", "2.13", "2.14",
					"3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20", "3.21", "3.22",
					"5.5", "5.6", "5.7", "5.10", "5.11", "5.12", "5.19", "5.29",
				}
			} else if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeKube {
				checkIds = []string{
					"1.1.1", "1.1.2", "1.1.3", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9", "1.1.10", "1.1.11", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17", "1.1.18", "1.1.19", "1.1.20", "1.1.21",
					"1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9", "1.2.11", "1.2.17", "1.2.18", "1.2.19", "1.2.20", "1.2.22", "1.2.26", "1.2.27", "1.2.28", "1.2.29", "1.2.30", "1.2.31", "1.2.32",
					"1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.4.1",
					"2.1", "2.2", "2.4", "2.5", "2.6",
					"4.1.5", "4.1.7", "4.2.1", "4.2.2", "4.2.3", "4.2.5", "4.2.7", "4.2.9", "4.2.10",
				}
			}
		}
	} else {
		var rules []model.PolicyDetailInfo
		err := db.Get().WithContext(ctx).Model(&model.PolicyDetailInfo{}).
			Where("id IN ?", policy.RuleIds).Find(&rules).Error
		if err != nil {
			return nil, err
		}

		for _, v := range rules {
			checkIds = append(checkIds, v.PolicyId)
		}
	}

	return checkIds, nil
}

func (s Scapper) prepareJobObject(ctx context.Context, check *model.Check, oldVersion bool) (*batchv1.Job, error) {
	jobObj, err := s.readJobObjFromYamlFile(model.ComplianceCheckType(check.CheckType), oldVersion)
	if err != nil {
		logging.Get().Error().Err(err).Msg("Can't read job .yaml file")
		return nil, err
	}

	if check.PolicyID == 0 {
		return jobObj, nil
	}

	checks, err := getCheckIds(ctx, s.rdb, check.PolicyID)
	if err != nil {
		return nil, err
	}

	if len(checks) > 0 {
		jobObj.Spec.Template.Spec.Containers[0].Args = append(jobObj.Spec.Template.Spec.Containers[0].Args, "--check="+strings.Join(checks, ","))
	}

	return jobObj, nil
}

func (s Scapper) readJobObjFromYamlFile(checkType model.ComplianceCheckType, oldVersion bool) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == model.ComplianceCheckTargetTypeKube {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		jobYamlPath = "/jobs/cri-bench/job.yaml"
		if oldVersion {
			jobYamlPath = "/jobs/docker-bench-security/job.yaml"
		}
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		jobYamlPath = "/jobs/host-bench/job.yaml"
	} else {
		return nil, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("Unreachable code reached"))
	}

	jobYaml, err := os.ReadFile(jobYamlPath)
	if err != nil {
		return nil, apperror.NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't read job file: %v", err))
	}

	jobObj := &batchv1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader(jobYaml), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, apperror.NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't decode job file: %v", err))

	}

	if oldVersion {
		if checkType == model.ComplianceCheckTargetTypeKube {
			jobObj.Spec.Template.Spec.Containers[0].Args = []string{"--v=4", "--console"}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			jobObj.Spec.Template.Spec.Containers[0].Args = []string{}
		}
	}

	return jobObj, nil
}

func (s *Scapper) scheduleOneJob(ctx context.Context, kubeClient *pkgassets.Clientset, check *model.Check, jobObj *batchv1.Job, clusterName, jobName, targetNodeName, targetNodeArch string) error {
	// 使用节点亲和性替代nodeName
	jobObj.Spec.Template.Spec.Affinity = &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchFields: []corev1.NodeSelectorRequirement{
							{
								Key:      "metadata.name",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{targetNodeName},
							},
						},
					},
				},
			},
		},
	}

	// for sub clusters, the image repos might be different from the yamls which is defined by the image repositories of the main cluster; so get the image repo prefix dynamically.
	k8s.ReplaceJobYamlWithTheTargetImageRepos(ctx, jobObj, kubeClient, s.myResourceNamePrefix, s.myNamespace)

	if jobObj.Labels == nil {
		jobObj.Labels = make(map[string]string, 2)
	}
	jobObj.Labels["CHECK_ID"] = check.CheckUUID
	jobObj.Labels[jobLabel] = "true"

	jobObj.Name = jobName

	checkEnv := corev1.EnvVar{
		Name:  "CHECK_ID",
		Value: check.CheckUUID,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, checkEnv)

	clusterNameEnv := corev1.EnvVar{
		Name:  "CLUSTER_NAME",
		Value: clusterName,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, clusterNameEnv)

	clusterIDEnv := corev1.EnvVar{
		Name:  "CLUSTER_ID",
		Value: check.ClusterID,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, clusterIDEnv)

	nodeNameEnv := corev1.EnvVar{
		Name:  "NODE_NAME",
		Value: targetNodeName,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, nodeNameEnv)

	ClusterUrlEnv := corev1.EnvVar{
		Name:  "CLUSTER_ADDR",
		Value: s.ClusterAddr,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, ClusterUrlEnv)

	// replace the tag with arm64
	if strings.HasPrefix(targetNodeArch, "arm") &&
		jobObj.Spec.Template.Spec.Containers[0].Image != "" {
		repo := strings.Split(jobObj.Spec.Template.Spec.Containers[0].Image, ":")[0]
		jobObj.Spec.Template.Spec.Containers[0].Image = repo + ":arm64"
	}

	jobsClient := kubeClient.BatchV1().Jobs(check.Namespace)
	res, err := jobsClient.Create(ctx, jobObj, metav1.CreateOptions{})
	// HACK
	if k8serrors.IsAlreadyExists(err) {
		err = jobsClient.Delete(ctx, jobObj.Name, metav1.DeleteOptions{})
		if err != nil {
			return apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Job already exists, so tried deleting, but: %v", err))
		}

		time.Sleep(time.Second * 10)
		res, err = jobsClient.Create(ctx, jobObj, metav1.CreateOptions{})
	}
	if err != nil {
		return apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Couldn't schedule job: %v", err))
	}

	jobsName := res.ObjectMeta.Name

	logging.Get().Info().Str("target-node", jobObj.Spec.Template.Spec.NodeName).
		Str("job-name", jobsName).
		Str("arch", targetNodeArch).
		Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
		Msg("Scheduled SCAP check job")

	return nil
}

func (s *Scapper) dbAddJobStatusInProgress(ctx context.Context, check *model.Check, targetNode *corev1.Node) error {
	jobName := s.CreateJobName(check.CheckUUID, check.CheckType, targetNode.Name)

	status := model.ScanStateInProgress
	createAt := time.Now().Unix()
	finishedAt := int64(0)
	message := ""
	if !pkgassets.NodeIsReady(targetNode) {
		message = "node is not ready"
		status = model.ScanStateFailed
		finishedAt = createAt // 当不可以创建pods时(node 时not ready状态)
		logging.Get().Info().
			Str("task", check.CheckUUID).
			Str("nodeName", targetNode.Name).
			Msg("node is not ready, check this node failed")
	}

	task := model.ScanNodeRecord{
		TaskID:       check.CheckUUID,
		CheckType:    check.CheckType,
		ClusterKey:   check.ClusterID,
		Operator:     check.Operator,
		NodeName:     targetNode.Name,
		Namespace:    check.Namespace,
		JobName:      jobName,
		State:        status,
		CreatedAt:    createAt,
		FinishedAt:   finishedAt,
		Message:      message,
		ScheduleType: "job",
	}

	err := s.rdb.Get().WithContext(ctx).Create(&task).Error
	if err != nil {
		return errors.Errorf("create scan task failed, %v", err)
	}
	return nil
}

func (s *Scapper) dbAddDaemonStatusInProgress(ctx context.Context, check *model.Check, status model.ScanState, message, scheduleType string) error {
	createAt := time.Now().Unix()
	var finishedAt int64
	if status == model.ScanStateFailed {
		finishedAt = createAt
	}

	task := model.ScanNodeRecord{
		TaskID:       check.CheckUUID,
		CheckType:    check.CheckType,
		ClusterKey:   check.ClusterID,
		Operator:     check.Operator,
		NodeName:     check.NodeName,
		Namespace:    check.Namespace,
		JobName:      "",
		State:        status,
		CreatedAt:    createAt,
		FinishedAt:   finishedAt,
		Message:      message,
		ScheduleType: scheduleType,
	}

	err := s.rdb.Get().WithContext(ctx).Create(&task).Error
	if err != nil {
		return errors.Errorf("create scan task failed, %v", err)
	}
	return nil
}

func (s *Scapper) CreateJobName(checkId, checkType, targetNodeName string) string {
	jobName := fmt.Sprintf("%s-%s-bench-%s", checkId[:8], checkType, targetNodeName)
	// NOTICE: the length of k8s label cannot be larger than 63 characters
	if len(jobName) >= 63 {
		jobName = fmt.Sprintf("%s-%s-bench-%s", checkId[:8], checkType, util.MD5Hex(targetNodeName))
	}
	return jobName
}

func (s *Scapper) dbJobStatusUpdate(state model.ScanState, check *model.Check, nodeName, msg string, timeEpochSecs int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	scanRecord := &model.ScanNodeRecord{
		State:      state,
		FinishedAt: timeEpochSecs,
		Message:    msg,
	}

	tbname := scanRecord.TableName()
	taskId := check.CheckUUID

	tx := s.rdb.Get().WithContext(ctx).Table(tbname).Select("state", "finished_at", "message")
	err := tx.Where("node_name = ? and task_id = ? and state = ?", nodeName, taskId, model.ScanStateInProgress).Updates(scanRecord).Error
	if err != nil {
		logging.Get().Err(err).Msgf("Failed the scap update job status setting failed, task id : %s, node name : %s.", check.CheckUUID, nodeName)
	}
	// print debug log
	// logging.Get().Info().Msgf("update scan node record, %v.", *scanRecord)

	return err
}

func (s *Scapper) startAsyncStatusListener(ctx context.Context, kubeClient *pkgassets.Clientset, check *model.Check, maxNumJobs int) (chan string, chan struct{}, bool) {
	finishedNodesCh := make(chan string, maxNumJobs)

	kubeInformerFactory := informers.NewFilteredSharedInformerFactory(kubeClient, time.Second*30, check.Namespace, func(listOpts *v1.ListOptions) {
		labelSelector := metav1.LabelSelector{
			MatchLabels: map[string]string{
				"CHECK_ID": check.CheckUUID,
			},
		}
		listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()
	})
	jobInformer := kubeInformerFactory.Batch().V1().Jobs().Informer()

	// Keep track of already finished nodes, so that we don't handle events for further updates after they're done.
	alreadyFinishedNodes := make(map[string]bool)

	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {},
		DeleteFunc: func(obj interface{}) {
			_, ok := obj.(*batchv1.Job)
			if !ok {
				logging.Get().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *batchv1.Job")
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.Get().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *batchv1.Job")
				return
			}

			thisNodeName := job.Spec.Template.Spec.NodeName
			if _, ok = alreadyFinishedNodes[thisNodeName]; ok {
				return
			}

			// Finished successfuly?
			if job.Status.Succeeded > 0 {
				logging.Get().Info().Msgf("Managed job succeeded, job-name : %v.", job.Name)

				alreadyFinishedNodes[thisNodeName] = true

				err := s.dbJobStatusUpdate(model.ScanStateCompleted, check, thisNodeName, "success", time.Now().Unix())
				if err != nil {
					logging.Get().Error().Msgf("update job status(success) failed, %v.", err)
				}
				finishedNodesCh <- thisNodeName
				return
			}

			// Finished and failed?
			if isFailed, failedCondition := s.isJobFailed(job); isFailed {
				logging.Get().Info().Str("job-name", job.Name).Msg("Managed job failed")

				thisNodeName = job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName
				alreadyFinishedNodes[thisNodeName] = true

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				err := s.dbJobStatusUpdate(model.ScanStateFailed, check, thisNodeName, msg, transTime.Unix())
				if err != nil {
					logging.Get().Error().Msgf("update job status(failed) failed, %v.", err)
				}
			}
		},
	})

	stopCh := make(chan struct{})

	logging.Get().Info().Msgf("Starting to watch for job events, checkId : %s.", check.CheckUUID)
	kubeInformerFactory.Start(stopCh)

	var jobType *batchv1.Job
	cacheSynced := kubeInformerFactory.WaitForCacheSync(stopCh)[reflect.TypeOf(jobType)]

	return finishedNodesCh, stopCh, cacheSynced
}

func (s *Scapper) awaitAndUpdateJobsStatuses(check *model.Check, scheduledNodesCh, finishedNodesCh chan string, listenerStopCh chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	defer close(listenerStopCh)
	// I think this design is kinda fragile... but I don't have any quick ideas.
	// A better design would be to create a k8s custom resource with a custom controller to manage it.
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	//
	runningNodeNames := []string{}

	// TODO: 这里大问题，这个for循环无法退出，只能等到ctx超时的分支退出。服了。
	for {
		select {
		case <-ctx.Done():
			logging.Get().Error().Err(ctx.Err()).Msg("Ctx timeout while waiting for jobs to finish, will mark them as timed out")
			// mark remaining running jobs as timed out.
			err := s.setCheckHistoryFinishedAndJobStatusesFailed(ctx, *check, "context timeout when executing")
			if err != nil {
				logging.Get().Err(err).Msg("set finished job statuses failed when context timeout")
			}
			return

		case scheduledNodeName, ok := <-scheduledNodesCh:
			if !ok {
				scheduledNodesCh = nil
				continue
			}
			runningNodeNames = append(runningNodeNames, scheduledNodeName)
			logging.Get().Info().Str("node-name", scheduledNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job scheduled")

		case finishedNodeName, ok := <-finishedNodesCh:
			if !ok {
				finishedNodesCh = nil
				continue
			}
			runningNodeNames = removeElement(finishedNodeName, runningNodeNames)
			logging.Get().Info().Str("node-name", finishedNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job finished")

			if len(runningNodeNames) == 0 {
				ctxDb, cancelDb := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelDb()

				logging.Get().Info().Str("checkId", check.CheckUUID).Msg("All managed jobs accounted for, done watching for events")

				var count int64
				taskId := check.CheckUUID
				nodeState := model.ScanNodeRecord{}
				err := s.rdb.Get().WithContext(ctxDb).Table(nodeState.TableName()).Where("task_id = ? and state=0", taskId).Count(&count).Error
				if err != nil {
					logging.Get().Error().Msgf("get scan success node number failed, %v", err)
				}

				scanHistory := &model.ScanHistory{
					SucNode:    int32(count),
					State:      model.ScanStateCompleted,
					FinishedAt: time.Now().Unix(),
				}

				tbname := scanHistory.TableName()
				tx := s.rdb.Get().WithContext(ctxDb).Table(tbname).Select("suc_node", "state", "finished_at")
				err = tx.Where("task_id = ? and check_type = ? and cluster_key = ?", taskId, check.CheckType, check.ClusterID).Updates(scanHistory).Error
				if err != nil {
					logging.Get().Error().Msgf("update scan history failed, task ID : %v, clusterID : %v, %v.", taskId, check.ClusterID, err)
				}
				return
			}
		}

		if scheduledNodesCh == nil && finishedNodesCh == nil {
			logging.Get().Error().Msg("Both chans are nil, this shouldn't happen")
		}
	}

}

func (s Scapper) isJobFailed(job *batchv1.Job) (bool, *batchv1.JobCondition) {
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobFailed {
			// according to documentation of JobStatus,
			// "When a job fails, one of the conditions will have type == "Failed"."
			return true, &condition
		}
	}
	return false, nil
}

func (s *Scapper) deleteJobAndPods(ctx context.Context, kubeClient *pkgassets.Clientset, namespace string, job batchv1.Job) error {
	err := kubeClient.BatchV1().Jobs(namespace).Delete(ctx, job.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Failed to delete job: %v", err)
	}

	listOpts := metav1.ListOptions{
		LabelSelector: labels.Set(job.Spec.Selector.MatchLabels).String(),
	}
	err = kubeClient.CoreV1().Pods(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, listOpts)
	if err != nil {
		return fmt.Errorf("Failed to delete job's pods: %v", err)
	}
	return nil
}

func (s *Scapper) GetJobStatus(clusterID, namespaces, jobName string) (model.ScanState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// get cluster manager
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return model.ScanStateUnknown, errors.Errorf("get cluster manager failed")
	}
	// get k8s client
	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return model.ScanStateUnknown, errors.Errorf("get k8s client failed")
	}

	// BUG：这里job执行完毕就删除了，然后去查找这个job肯定找不到，就返回 ScanStateFailed
	job, err := kubeClient.BatchV1().Jobs(namespaces).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		logging.Get().Error().Msgf("get scap jobs info failed, %v.", err)
		return model.ScanStateFailed, nil
	}

	if job.Status.Succeeded > 0 {
		return model.ScanStateCompleted, nil
	}

	state := job.Status.Succeeded + job.Status.Failed + job.Status.Active
	if job.Status.Active > 0 || state == 0 {
		return model.ScanStateInProgress, nil
	}

	return model.ScanStateFailed, nil
}

func removeAtIdx(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func removeElement(what string, from []string) []string {
	for idx, el := range from {
		if el == what {
			return removeAtIdx(from, idx)
		}
	}
	return from
}

// 如果不是全部节点则从数据库拿，否则列出集群全部节点
func (s *Scapper) getNodes(ctx context.Context, kubeClient *pkgassets.Clientset, cluster *model.ScapClusterInfo) ([]corev1.Node, error) {
	var nodes []string
	if !cluster.IsAllNodes {
		nodes = make([]string, 0, len(cluster.ClusterNodeIds))
		if err := s.rdb.Get().WithContext(ctx).
			Model(&model.TensorNode{}).
			Select("host_name").
			Where("id IN ?", cluster.ClusterNodeIds).
			Find(&nodes).Error; err != nil {
			return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("can't list nodes name in this cluster from db: %v", err))
		}
	}

	var nodesIndex = make(map[string]struct{}, len(nodes))
	for _, v := range nodes {
		nodesIndex[v] = struct{}{}
	}

	// 先查询全部节点，如果自定义了节点，把对应的节点筛选出来。
	// find nodes to schedule check jobs on
	nodeItems, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("can't list nodes in this cluster from k8s cluster: %v", err))
	}

	if cluster.IsAllNodes {
		return nodeItems.Items, nil
	} else {
		var nodes = make([]corev1.Node, 0, len(nodes))

		for i := range nodeItems.Items {
			if _, ok := nodesIndex[nodeItems.Items[i].Name]; ok {
				nodes = append(nodes, nodeItems.Items[i])
			}
		}
		return nodes, nil
	}
}

// 获取集群的信息
func (s *Scapper) getCluster(ctx context.Context, clusterID uint) (*model.ScapClusterInfo, error) {
	var clusterInfo model.ScapClusterInfo
	if err := s.rdb.Get().WithContext(ctx).First(&clusterInfo, clusterID).Error; err != nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("can't list nodeids in this cluster from db: %v", err))
	}

	return &clusterInfo, nil
}

var hostRulesTmp = template.Must(template.New("host-config-map").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_tailoring_example">
  <status>incomplete</status>
  <version time="2020-09-22T16:00:00.000+02:00">1.0</version>
  <Profile id="xccdf_org.mysecurity.content_profile_unselect_memory_intensive_from_standard" extends="xccdf_org.ssgproject.content_profile_standard">
    <title>Unselect memory intensive rules</title>
    <!--
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.2_release_notes/known-issues
    See chapter 
    "Scanning large numbers of files with OpenSCAP causes systems to run out of memory"

    See also: https://bugzilla.redhat.com/show_bug.cgi?id=1558587#c12
    See also: https://martin.preisler.me/2013/11/xccdf-tailoring/

    So, deselect rules that involve recursion over the entire / filesystem:
    -->
    <select idref="xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_no_files_unowned_by_user" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_suid" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_sgid" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_rpm_verify_hashes" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_rpm_verify_permissions" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_rpm_verify_ownership" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits" selected="false"/>
    <select idref="xccdf_org.ssgproject.content_rule_dir_perms_world_writable_system_owned" selected="false"/>
	{{- range . }}
    <select idref="{{ . }}" selected="false"/>
	{{- end }}
  </Profile>
</Tailoring>`))

// 上面已存在的策略条目，做个索引防止重复添加
var hostRulesExist = map[string]struct{}{
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable": {},
	"xccdf_org.ssgproject.content_rule_no_files_unowned_by_user":                     {},
	"xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned":                {},
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_suid":           {},
	"xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_sgid":           {},
	"xccdf_org.ssgproject.content_rule_rpm_verify_hashes":                            {},
	"xccdf_org.ssgproject.content_rule_rpm_verify_permissions":                       {},
	"xccdf_org.ssgproject.content_rule_rpm_verify_ownership":                         {},
	"xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits":         {},
	"xccdf_org.ssgproject.content_rule_dir_perms_world_writable_system_owned":        {},
}

func (s *Scapper) getHostConfigMap(ctx context.Context, kubeClient *pkgassets.Clientset, checks []string, check *model.Check) (string, error) {
	var rules []string

	for _, v := range checks {
		if _, ok := hostRulesExist[v]; !ok {
			rules = append(rules, v)
		}
	}

	// 当全选了规则，则主机扫描排除的规则不变，这时不需要挂载configmap, 返回一个空字符串的configmap名标识不需要挂载configmap
	if len(rules) == 0 {
		return "", nil
	}

	var stringBuilder strings.Builder
	if err := hostRulesTmp.Execute(&stringBuilder, rules); err != nil {
		return "", errors.Wrap(err, "render hostRulesTmp failed")
	}

	// 创建configMap
	configMapName := fmt.Sprintf("host-scap-%d", check.PolicyID)

	configMap := &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name: configMapName,
		},
		Data: map[string]string{
			"tailoring-file-centos.xml": stringBuilder.String(),
		},
	}

	if _, err := kubeClient.
		CoreV1().
		ConfigMaps(check.Namespace).
		Create(ctx, configMap, metav1.CreateOptions{}); err != nil && !k8serrors.IsAlreadyExists(err) {
		return "", errors.Wrapf(err, "create config %s failed", configMapName)
	}

	return configMapName, nil
}

func (s *Scapper) modifyJob(scapType model.ComplianceCheckType, job *batchv1.Job, cluster *model.TensorCluster) {
	switch scapType {
	case model.ComplianceCheckTargetTypeKube:
		// 如果是openshift，修改执行的文件，执行 rh-1.0 文件
		if cluster.Platform == k8s.Openshift {
			logging.Get().Info().Msg("openshift platform")

			container := job.Spec.Template.Spec.Containers
			if length := len(container); length > 0 {
				for i := range container[length-1].Args {
					if strings.HasPrefix(container[length-1].Args[i], "--benchmark") {
						container[length-1].Args[i] = "--benchmark=rh-1.0"
						break
					}
				}
			}
		}
	case model.ComplianceCheckTargetTypeDocker:
	case model.ComplianceCheckTargetTypeHost:
	}
}

// 检查nodes是否处于ready状态
// 只有当node的Ready状态为true，且磁盘空间压力、内存压力、进程压力、网络配置都为false时 nodes才算可用。
// https://kubernetes.io/zh/docs/concepts/architecture/nodes/#condition
func (s *Scapper) nodeIsReady(node *corev1.Node) bool {
	for _, v := range node.Status.Conditions {
		switch v.Type {
		case corev1.NodeReady:
			if v.Status != corev1.ConditionTrue {
				return false
			}
		default:
			if v.Status != corev1.ConditionFalse {
				return false
			}
		}
	}

	return true
}

// syncJobState 同步进行中任务的状态。
// TODO: 一个临时方案
func (s *Scapper) syncJobState(ctx context.Context, checkType, clusterKey string) error {
	pgCtx, mpgCancel := context.WithTimeout(ctx, time.Second*2)
	defer mpgCancel()

	logger := logging.Get().Log().
		Str("checkType", checkType).
		Str("clusterKey", clusterKey)

	var inProcessItem []*model.ScanHistory

	err := s.rdb.Get().WithContext(pgCtx).Model(&model.ScanHistory{}).
		Where("cluster_key = ?", clusterKey).
		Where("check_type = ?", checkType).
		Where("state = ?", model.ScanStateInProgress).
		Find(&inProcessItem).
		Error

	if err != nil {
		logger.Err(err).Msg("获取正在运行的扫描历史失败")
		return err
	}

	service, ok := GetService(ctx)
	if !ok {
		err := errors.New("can't get ScapService")
		logger.Err(err).Msg("获取ScapService失败")
		return err
	}

	// 对正处于进行中的任务做一次数据同步
	for i := range inProcessItem {
		// 复用以前的逻辑
		if err := service.SynScanState(inProcessItem[i]); err != nil {
			logger.Err(err).Str("checkId", inProcessItem[i].TaskID).Msg("同步状态失败")
			return err
		}
	}

	return nil
}
