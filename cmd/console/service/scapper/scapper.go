package scapper

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Scapper struct {
	DockerRepoHostPort string
	DockerRepoScapTag  string
	ClusterAddr        string
	PostgresDB         *rdbtools.GormWrapper
	ScapService        *ScapService
}

const (
	// Potentially move to config file.

	checkTimeout           = time.Minute * 30
	historicalChecksToKeep = 3
	jobLabel               = "SCAPPER"
)

func newScapper(
	scapOpts *flag.ScapOpts,
	scapService *ScapService,
	postgresDB *rdbtools.GormWrapper,
) *Scapper {
	s := &Scapper{
		DockerRepoHostPort: scapOpts.HostPort,
		DockerRepoScapTag:  scapOpts.ImageTag,
		ScapService:        scapService,
		PostgresDB:         postgresDB,
		ClusterAddr:        scapOpts.ClusterAddr,
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
		query := "task_id = ?"
		checkId := check.CheckUUID
		ret := s.PostgresDB.Get().WithContext(cleanCtx).Table(tbname).Where(query, checkId).Updates(scanRecord).Error
		if ret != nil {
			logging.GetLogger().WithContext(cleanCtx).Errorf(ret, "update scan record failed, checkID : %s", check.CheckUUID)
		}
		return ret
	})

	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "Failed the scap update job status setting failed. checkID: %s", check.CheckUUID)
	}

	return err
}

// checkCheckStatusWithDelay check and update the status with given delayed time
func (s *Scapper) checkCheckStatusWithDelay(check model.Check, delayedTime time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when timer to set task timeout: %v. Stack: %s", r, debug.Stack())
		}
	}()

	timerCtx, cancel := context.WithDeadline(context.Background(), delayedTime)
	defer cancel()

	select {
	case <-timerCtx.Done():
		logging.GetLogger().Warn().Msgf("Task timeout when console boots, try to finish these tasks")

		msg := "timeout in booting delayed timeout checking"
		err := s.setCheckHistoryFinishedAndJobStatusesFailed(context.Background(), check, msg)
		if err == nil {
			logging.GetLogger().Info().Msgf("Booting check: unfinished job %+v setting finished.", check)
		} else {
			logging.GetLogger().Err(err).Msgf("Booting check Error: unfinished job %+v setting finished fail.", check)
		}
	}
}

// initCheckUnFinishedJobs will check all unfinished jobs, setting them finished if timeout.
// it's used to prevent the case: ongoing jobs are watched by console to set timeout; if console crashed or redeployed, these jobs will lose watches and being unfinished.
func (s *Scapper) InitCheckUnFinishedJobs(ctx context.Context) error {
	nowStamp := time.Now().Unix()
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var scanHistory []model.ScanHistory
	err := s.PostgresDB.Get().WithContext(pgCtx).Where("finished_at = 0").Find(&scanHistory).Error
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
			logging.GetLogger().Warn().Msgf("Task timeout when console boots, try to finish task %+v", value)

			err := s.setCheckHistoryFinishedAndJobStatusesFailed(context.Background(), check, "timeout in booting timeout check")
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Booting check Error: unfinished job %+v setting finished fail.", check)
				continue
			}

			logging.GetLogger().Info().Msgf("Booting check: unfinished job %+v setting finished.", check)
		} else { // not timeout, we should set up a customized timer to set timeout: when timeout reaches, we set the job finished.
			logging.GetLogger().Warn().Msgf("Task timeout when console boots, try to watch the task async: %+v", value)

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
	query := "check_type = ? and cluster_key = ?"
	err := s.PostgresDB.Get().WithContext(pgCtx).Order("finished_at DESC").First(&scanTask, query, checkType, clusterID).Error
	if err != nil {
		return false
	}
	//print debug log
	logging.GetLogger().Info().Msgf("scan task info : %v.", scanTask)
	//task id
	if scanTask.TaskID == "" || scanTask.CheckType != checkType {
		return false
	}
	//task state
	if scanTask.FinishedAt <= 0 || scanTask.State == model.ScanStateInProgress {
		return true
	}

	return false
}

func (s *Scapper) RunComplianceCheck(
	ctx context.Context,
	clusterID string,
	checkType model.ComplianceCheckType,
	username string,
) (uuid.UUID, error) {

	if s.checkTargetTypeTasksStillInProgress(ctx, string(checkType), clusterID) {
		return uuid.Nil, NewCheckAlreadyInProgressError(http.StatusInternalServerError, errors.Errorf("currently there are tasks still running"))
	}
	//get namespaces
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return uuid.Nil, NewCheckAlreadyInProgressError(http.StatusInternalServerError, errors.Errorf("get resource failed"))
	}
	cluster := resSvc.GetClusterByKey(ctx, clusterID)
	if cluster == nil {
		return uuid.Nil, NewCheckAlreadyInProgressError(http.StatusInternalServerError, errors.Errorf("get cluster failed clusterId : %v", clusterID))
	}
	namespace := cluster.WorkerNamespace
	if namespace == "" {
		return uuid.Nil, NewCheckAlreadyInProgressError(http.StatusInternalServerError, errors.Errorf("get namespaces failed with run compliance check"))
	}
	//get cluster manager
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get cluster manager failed"))
	}
	//get k8s client
	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("get k8s client failed"))
	}

	err := s.garbageCollectHistoricalJobs(ctx, kubeClient, checkType, namespace)
	if err != nil {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to garbage collect historical jobs: %w", err))
	}

	// generate check uuid that will identify results of this run in database
	checkUUID := uuid.NewV4()

	check := model.Check{
		CheckType: string(checkType),
		CheckUUID: checkUUID.String(),
		ClusterID: clusterID,
		Namespace: namespace,
		Operator:  username,
	}

	jobObj, err := s.prepareJobObject(&check)
	if err != nil {
		return uuid.Nil, err
	}

	// find nodes to schedule check jobs on
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list nodes in this cluster: %w", err))
	}

	// schedule jobs
	logging.GetLogger().Info().
		Str("check-type", string(check.CheckType)).Str("check-cluster", check.ClusterID).Str("check-uuid", check.CheckUUID).
		Str("namespace", check.Namespace).Str("operator", check.Operator).Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
		Int("node-items-num", len(nodes.Items)).Msg("Scheduling SCAP check jobs")

	for _, targetNode := range nodes.Items {
		// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
		// or do we not care about this since this is a rare operation?

		err := s.PgAddJobStatusInProgress(ctx, &check, targetNode.Name)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("set node %s for check task %+v error", targetNode.Name, check)
			continue
		}
	}
	//create scan history
	scanHistory := model.ScanHistory{
		TaskID:      check.CheckUUID,
		Operator:    check.Operator,
		CheckType:   string(check.CheckType),
		CreatedAt:   time.Now().Unix(),
		ClusterKey:  check.ClusterID,
		ClusterName: "",
		State:       model.ScanStateInProgress,
		FinishedAt:  0,
	}
	err = s.PostgresDB.Get().WithContext(ctx).Create(scanHistory).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("create scan history failed, operator : %v, checkType : %v, task id : %v.", check.Operator, check.CheckType, scanHistory.TaskID)
	}
	// async context is rooted in application context
	asyncCtx, _ := context.WithTimeout(context.Background(), checkTimeout)
	go s.asyncScheduleAndManageJobs(asyncCtx, kubeClient, &check, jobObj, nodes, scanHistory.ClusterName)

	return checkUUID, nil
}

func (s *Scapper) RunExportFileTask(task *model.ExportTask, language lang.LanguageType) error {
	// export file to xlsx
	err := s.ScapService.GetScanResultToFile(task, language)
	//print debug log
	//logging.GetLogger().Info().Msgf("save scan result to xlsx over!!")
	//update task status
	finishedAt := time.Now().Unix()
	task.Status = 0
	if err != nil {
		task.Status = 2
		finishedAt = 0
		logging.GetLogger().Error().Msgf("run export file task failed! %v.", err)
	} else {
		task.Content, err = s.ScapService.GetFileData(task.FileName)
		if err != nil {
			logging.GetLogger().Error().Msgf("get file content failed, %v.", err)
		}
		//remove file
		os.Remove(task.FileName)
	}
	//set timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//save finish time
	task.FinishedAt = finishedAt
	//update mongo data
	tbname := task.TableName()
	query := "task_id = ? and username = ?"
	err = s.PostgresDB.Get().WithContext(ctx).Table(tbname).Select("status", "finished_at", "content").Where(query, task.CheckId, task.UserName).Updates(&task).Error
	if err != nil {
		logging.GetLogger().Error().Msgf("update export file task state failed! %v.", err)
		return errors.Errorf("update status failed, %v", err)
	}

	return err
}

func (s *Scapper) garbageCollectHistoricalJobs(ctx context.Context, kubeClient *kubernetes.Clientset, checkType model.ComplianceCheckType, namespace string) error {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			jobLabel: "true",
		},
	}
	listOpts := metav1.ListOptions{}
	listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()

	jobs, err := kubeClient.BatchV1().Jobs(namespace).List(ctx, listOpts)
	if err != nil {
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list jobs in this cluster: %w", err))
	}

	// Find the start time of the earliest job in each check
	startTimesOfChecks := make(map[string]time.Time)
	for _, job := range jobs.Items {
		checkID, ok := job.Labels["CHECK_ID"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Expected CHECK_ID label to be present"))
		}

		if job.Status.StartTime == nil {
			logging.GetLogger().Info().Str("job-name", job.Name).Msg("StartTime is nil, skipping")
			continue
		}
		thisJobStartTime := job.Status.StartTime.Time

		earliestJobStartTimeSoFar, ok := startTimesOfChecks[checkID]
		if !ok {
			startTimesOfChecks[checkID] = thisJobStartTime
		} else {
			if earliestJobStartTimeSoFar.After(thisJobStartTime) {
				startTimesOfChecks[checkID] = thisJobStartTime
			}
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
		checkID, _ := job.Labels["CHECK_ID"]

		for _, toDelete := range checksByStartTime {
			if checkID == toDelete.CheckID {

				err := s.deleteJobAndPods(ctx, kubeClient, namespace, &job)
				if err != nil {
					return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to cleanup historical job: %w", err))
				}
				logging.GetLogger().Info().Str("job-name", job.Name).Msg("Cleaned up historical job")
				break
			}
		}
	}

	return nil
}

func (s *Scapper) asyncScheduleAndManageJobs(ctx context.Context, kubeClient *kubernetes.Clientset, check *model.Check, jobObj *batchv1.Job, nodes *corev1.NodeList, clusterName string) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	scheduledNodesCh := make(chan string, len(nodes.Items))
	finishedNodesCh, listenerStopCh, cacheSynced := s.startAsyncStatusListener(ctx, kubeClient, check, len(nodes.Items))

	if !cacheSynced {
		logging.GetLogger().Warn().Msg("Informer cache failed to sync, not sure how to handle this. Ignoring.")
	}

	go s.awaitAndUpdateJobsStatuses(ctx, check, scheduledNodesCh, finishedNodesCh, listenerStopCh)

	for _, targetNode := range nodes.Items {
		select {
		case <-ctx.Done():
			logging.GetLogger().Error().Err(ctx.Err()).Msg("Ctx timeout while scheduling jobs")
			close(scheduledNodesCh)
			return
		default:
			// TODO: will it scale?
			// Note: I think it's safe to run this as goroutine for each job,
			// but I don't know if we should spam kube api this way...
			// I know kubeClient has some built in rate limiting so maybe it's ok?
			// Note2: but we must close scheduledNodesCh after all jobs were scheduled.
			// go func() {
			//create job name
			jobName := s.CreateJobName(check.CheckUUID, check.CheckType, targetNode.Name)
			//schedule job
			err := s.scheduleOneJob(ctx, kubeClient, check, jobObj.DeepCopy(), clusterName, jobName, targetNode.Name)
			if err != nil {
				logging.GetLogger().Error().Msgf("Failed to schedule job, %v.", err)

				msg := fmt.Sprintf("Failed to schedule job: %s", err)
				check.NodeName = targetNode.Name
				err = s.PgJobStatusUpdate(ctx, model.ScanStateFailed, check, msg, time.Now().Unix())
				//
				finishedNodesCh <- targetNode.Name
			} else {
				scheduledNodesCh <- targetNode.Name
			}
		}
	}

	close(scheduledNodesCh)
}

func (s Scapper) prepareJobObject(check *model.Check) (*batchv1.Job, error) {
	jobObj, err := s.readJobObjFromYamlFile(model.ComplianceCheckType(check.CheckType))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Can't read job .yaml file")
		return nil, err
	}

	// Subsitute job's image repository in job.yaml for the one configured for Console.
	currImage := jobObj.Spec.Template.Spec.Containers[0].Image
	splitted := strings.Split(currImage, "/")
	currImgnameSplit := strings.Split(splitted[1], ":")
	currImgname := currImgnameSplit[0]
	newImage := fmt.Sprintf("%s/%s:%s", s.DockerRepoHostPort, currImgname, s.DockerRepoScapTag)
	jobObj.Spec.Template.Spec.Containers[0].Image = newImage

	return jobObj, nil
}

func (s Scapper) readJobObjFromYamlFile(checkType model.ComplianceCheckType) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == model.ComplianceCheckTargetTypeKube {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		jobYamlPath = "/jobs/docker-bench-security/job.yaml"
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		jobYamlPath = "/jobs/host-bench/job.yaml"
	} else {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Unreachable code reached"))
	}

	jobYaml, err := ioutil.ReadFile(jobYamlPath)
	if err != nil {
		return nil, NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't read job file: %w", err))
	}

	jobObj := &batchv1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't decode job file: %w", err))

	}
	return jobObj, nil
}

func (s *Scapper) scheduleOneJob(ctx context.Context, kubeClient *kubernetes.Clientset, check *model.Check, jobObj *batchv1.Job, clusterName, jobName, targetNodeName string) error {
	jobObj.Spec.Template.Spec.NodeName = targetNodeName

	if jobObj.Labels == nil {
		jobObj.Labels = make(map[string]string)
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

	jobsClient := kubeClient.BatchV1().Jobs(check.Namespace)
	res, err := jobsClient.Create(ctx, jobObj, metav1.CreateOptions{})
	// HACK
	if k8serrors.IsAlreadyExists(err) {
		err = jobsClient.Delete(ctx, jobObj.Name, metav1.DeleteOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Job already exists, so tried deleting, but: %w", err))
		}

		time.Sleep(time.Second * 10)
		res, err = jobsClient.Create(ctx, jobObj, metav1.CreateOptions{})
	}
	if err != nil {
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Couldn't schedule job: %w", err))
	}

	jobsName := res.ObjectMeta.Name

	logging.GetLogger().Info().Str("target-node", jobObj.Spec.Template.Spec.NodeName).
		Str("job-name", jobsName).Msg("Scheduled SCAP check job")

	return nil
}

func (s *Scapper) PgAddJobStatusInProgress(ctx context.Context, check *model.Check, targetNodeName string) error {
	jobName := s.CreateJobName(check.CheckUUID, check.CheckType, targetNodeName)

	task := model.ScanNodeRecord{
		TaskID:     check.CheckUUID,
		CheckType:  check.CheckType,
		ClusterKey: check.ClusterID,
		Operator:   check.Operator,
		NodeName:   targetNodeName,
		Namespace:  check.Namespace,
		JobName:    jobName,
		State:      model.ScanStateInProgress,
		CreatedAt:  time.Now().Unix(),
		FinishedAt: 0,
	}

	err := s.PostgresDB.Get().WithContext(ctx).Create(task).Error
	if err != nil {
		return errors.Errorf("create scan task failed, %v", err)
	}
	return nil
}

func (s *Scapper) CreateJobName(checkId, checkType, targetNodeName string) string {
	return fmt.Sprintf("%s-%s-%s", checkId[:8], checkType, targetNodeName)
}

func (s *Scapper) PgJobStatusUpdate(ctx context.Context, state int32, check *model.Check, msg string, timeEpochSecs int64) error {
	scanRecord := &model.ScanNodeRecord{
		State:      state,
		FinishedAt: timeEpochSecs,
		Message:    msg,
	}

	tbname := scanRecord.TableName()
	taskId := check.CheckUUID
	nodeName := check.NodeName
	query := "node_name = ? and task_id = ?"
	tx := s.PostgresDB.Get().WithContext(ctx).Table(tbname).Select("state", "finished_at", "message")
	err := tx.Where(query, nodeName, taskId).Updates(scanRecord).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Failed the scap update job status setting failed, task id : %s, node name : %s.", check.CheckUUID, nodeName)
	}
	//print debug log
	logging.GetLogger().Info().Msgf("update scan node record, %v.", *scanRecord)

	return err
}

func (s *Scapper) startAsyncStatusListener(ctx context.Context, kubeClient *kubernetes.Clientset, check *model.Check, maxNumJobs int) (chan string, chan struct{}, bool) {
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
			job, ok := obj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *batchv1.Job")
				return
			}
			thisNodeName := job.Spec.Template.Spec.NodeName
			if _, ok := alreadyFinishedNodes[thisNodeName]; ok {
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *batchv1.Job")
				return
			}

			thisNodeName := job.Spec.Template.Spec.NodeName
			if _, ok := alreadyFinishedNodes[thisNodeName]; ok {
				return
			}

			// Finished successfuly?
			if job.Status.Succeeded > 0 {
				logging.GetLogger().Info().Msgf("Managed job succeeded, job-name : %v.", job.Name)

				alreadyFinishedNodes[thisNodeName] = true

				pgCtx, pgCancel := context.WithTimeout(ctx, time.Second*10)
				defer pgCancel()

				check.NodeName = thisNodeName
				err := s.PgJobStatusUpdate(pgCtx, model.ScanStateCompleted, check, "success", time.Now().Unix())
				if err != nil {
					logging.GetLogger().Error().Msgf("update job status(success) failed, %v.", err)
				}
				finishedNodesCh <- thisNodeName
				return
			}

			// Finished and failed?
			if isFailed, failedCondition := s.isJobFailed(job); isFailed {
				logging.GetLogger().Info().Str("job-name", fmt.Sprintf("%s", job.Name)).Msg("Managed job failed")

				thisNodeName := job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName
				alreadyFinishedNodes[thisNodeName] = true

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				pgCtx, pgCancel := context.WithTimeout(ctx, time.Second*10)
				defer pgCancel()

				check.NodeName = thisNodeName
				err := s.PgJobStatusUpdate(pgCtx, model.ScanStateFailed, check, msg, transTime.Unix())
				if err != nil {
					logging.GetLogger().Error().Msgf("update job status(failed) failed, %v.", err)
				}
				return
			}

			// some other event happened - pass.
			return
		},
	})

	stopCh := make(chan struct{})

	logging.GetLogger().Info().Msgf("Starting to watch for job events, checkId : %s.", check.CheckUUID)
	kubeInformerFactory.Start(stopCh)

	var jobType *batchv1.Job
	cacheSynced := kubeInformerFactory.WaitForCacheSync(stopCh)[reflect.TypeOf(jobType)]

	return finishedNodesCh, stopCh, cacheSynced
}

func (s *Scapper) awaitAndUpdateJobsStatuses(ctx context.Context, check *model.Check, scheduledNodesCh, finishedNodesCh chan string, listenerStopCh chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	defer close(listenerStopCh)

	// I think this design is kinda fragile... but I don't have any quick ideas.
	// A better design would be to create a k8s custom resource with a custom controller to manage it.

	runningNodeNames := []string{}

	for {
		select {
		case <-ctx.Done():
			logging.GetLogger().Error().Err(ctx.Err()).Msg("Ctx timeout while waiting for jobs to finish, will mark them as timed out")
			// mark remaining running jobs as timed out.
			err := s.setCheckHistoryFinishedAndJobStatusesFailed(ctx, *check, "context timeout when executing")
			if err != nil {
				logging.GetLogger().Err(err).Msg("set finished job statuses failed when context timeout")
			}
			return

		case scheduledNodeName, ok := <-scheduledNodesCh:
			if !ok {
				scheduledNodesCh = nil
				continue
			}
			runningNodeNames = append(runningNodeNames, scheduledNodeName)
			logging.GetLogger().Info().Str("node-name", scheduledNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job scheduled")

		case finishedNodeName, ok := <-finishedNodesCh:
			if !ok {
				finishedNodesCh = nil
				continue
			}
			runningNodeNames = removeElement(finishedNodeName, runningNodeNames)
			logging.GetLogger().Info().Str("node-name", finishedNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job finished")

			if len(runningNodeNames) == 0 {
				logging.GetLogger().Info().Str("checkId", check.CheckUUID).Msg("All managed jobs accounted for, done watching for events")

				var count int64
				taskId := check.CheckUUID
				nodeState := model.ScanNodeRecord{}
				err := s.PostgresDB.Get().WithContext(ctx).Table(nodeState.TableName()).Where("task_id = ? and state=0", taskId).Count(&count).Error
				if err != nil {
					logging.GetLogger().Error().Msgf("get scan success node number failed, %v", err)
				}

				scanHistory := &model.ScanHistory{
					SucNode:    int32(count),
					State:      model.ScanStateCompleted,
					FinishedAt: time.Now().Unix(),
				}

				tbname := scanHistory.TableName()
				condition := "task_id = ? and check_type = ? and cluster_key = ?"
				tx := s.PostgresDB.Get().WithContext(ctx).Table(tbname).Select("suc_node", "state", "finished_at")
				err = tx.Where(condition, taskId, check.CheckType, check.ClusterID).Updates(scanHistory).Error
				if err != nil {
					logging.GetLogger().Error().Msgf("update scan history failed, task Id : %v, clusterID : %v, %v.", taskId, check.ClusterID, err)
				}
				return
			}
		}

		if scheduledNodesCh == nil && finishedNodesCh == nil {
			logging.GetLogger().Error().Msg("Both chans are nil, this shouldn't happen")
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

func (s *Scapper) deleteJobAndPods(ctx context.Context, kubeClient *kubernetes.Clientset, namespace string, job *batchv1.Job) error {
	err := kubeClient.BatchV1().Jobs(namespace).Delete(ctx, job.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Failed to delete job: %w", err)
	}

	listOpts := metav1.ListOptions{
		LabelSelector: labels.Set(job.Spec.Selector.MatchLabels).String(),
	}
	err = kubeClient.CoreV1().Pods(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, listOpts)
	if err != nil {
		return fmt.Errorf("Failed to delete job's pods: %w", err)
	}
	return nil
}

func (s *Scapper) GetJobStatus(clusterID, namespaces, jobName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//get cluster manager
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return "", errors.Errorf("get cluster manager failed")
	}
	//get k8s client
	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return "", errors.Errorf("get k8s client failed")
	}

	job, err := kubeClient.BatchV1().Jobs(namespaces).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		return "failed", nil
	}

	if job.Status.Succeeded > 0 {
		return "success", nil
	}

	if job.Status.Active > 0 {
		return "running", nil
	}

	return "failed", nil
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
