package api

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		// TODO: rethink paths, this is bad
		r.Get("/check/{checkType}/{checkID}", api.getScapJob())
		r.Post("/check/{checkType}/cluster/{clusterID}", api.scapCheck())
	}
}

type JobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id, omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	Status     string             `json:"status" bson:"status"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt"`
	Results    string             `json:"results" bson:"results"`
}

// @Summary Get scap results
// @Description Get current scap results for a specific job
// @ID v1-scap-job-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "scap job ID"
// @Router /api/v1/scap/check/{checkType}/{checkID} [get]
func (api *api) getScapJob() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			response.Bad(w, "checkID param missing")
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			response.Bad(w, "checkType param missing")
			return
		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			response.Bad(w, "invalid checkType param value (allowed: kube/docker/host)")
			return
		}

		// from mongo
		mongoCollection := ""
		if checkType == "kube" {
			mongoCollection = "kube-bench-records"
		} else if checkType == "docker" {
			mongoCollection = "docker-bench-records"
		} else if checkType == "host" {
			mongoCollection = "host-bench-records"
		} else {
			response.InternalError(w, "Unreachable code reached")
			return
		}

		cursor, err := api.mongodb.Collection(mongoCollection).Find(ctx, bson.M{"checkId": checkID})
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		defer cursor.Close(ctx)

		var results []JobEntry
		for cursor.Next(ctx) {
			var result JobEntry
			err := cursor.Decode(&result)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}
			// TODO: pagination
			results = append(results, result)
		}

		err = cursor.Err()
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, results)
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @ID v1-scap-check
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/check/{checkType}/cluster/{clusterID} [post]
func (api *api) scapCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			response.Bad(w, "checkType param missing")
			return
		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			response.Bad(w, "invalid checkType param value (allowed: kube/docker/host)")
			return
		}

		clusterID := chi.URLParam(r, "clusterID")
		if clusterID == "" {
			response.Bad(w, "clusterID is not provided")
			return
		}

		// get kube client for this cluster
		kubeClient, err := api.getKubeClientForCluster(ctx, clusterID)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't get k8s client: %s", err))
			return
		}

		// read job yaml for this check type
		jobObj, err := api.readJobObjFromYamlFile(checkType)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't read job .yaml file: %s", err))
			return
		}

		// Subsitute job's image repository in job.yaml for the one configured for Console.
		currImage := jobObj.Spec.Template.Spec.Containers[0].Image
		splitted := strings.Split(currImage, "/")
		currImgname := splitted[1]
		newImage := fmt.Sprintf("%s/%s", api.scapper.DockerRepoHostPort, currImgname)
		jobObj.Spec.Template.Spec.Containers[0].Image = newImage

		// find nodes to schedule check jobs on
		nodes, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't list nodes in this cluster: %s", err))
			return
		}

		// generate check uuid that will identify results of this run in database
		checkUUID := uuid.NewV4()
		checkEnv := corev1.EnvVar{
			Name:  "CHECK_ID",
			Value: checkUUID.String(),
		}
		jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, checkEnv)

		// get namespace of this pod - it will be used for scheduled jobs/pods
		namespace := os.Getenv("MY_POD_NAMESPACE")
		if namespace == "" {
			namespace = "default"
		}

		// schedule jobs
		logging.GetLogger().Info().
			Str("check-type", checkType).
			Str("check-uuid", checkUUID.String()).
			Str("namespace", namespace).
			Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
			Msg("Scheduling SCAP check jobs")

		numScheduledJobs := 0

		for _, targetNode := range nodes.Items {
			// TODO: will it scale?
			// What about context timeout? Launching jobs for thousands of nodes may take a while.

			// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
			// or do we not care about this since this is a rare operation?
			// Also, this should also clean up all Error and Completed pods.

			err := api.scheduleOneJob(kubeClient, namespace, jobObj.DeepCopy(), checkUUID, targetNode.Name)
			if err != nil {
				response.InternalError(w, fmt.Sprintf("Failed to schedule job: %s", err))
				return
			}
			numScheduledJobs++

			api.addScapInitialEntry(ctx, checkType, checkUUID, targetNode.Name)

		}

		response.Ok(w, checkUUID.String())

		go api.startManagedJobRoutine(kubeClient, namespace, checkUUID, numScheduledJobs, checkType)
	}
}

func (api *api) getKubeClientForCluster(ctx context.Context, clusterID string) (*kubernetes.Clientset, error) {
	cluster, err := api.getClusterFromMongo(ctx, clusterID)
	if err != nil {
		return nil, fmt.Errorf("Cluster not found: %s", err)
	}

	kubeConfigDecoded, err := b64.StdEncoding.DecodeString(cluster.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Can't decode kubeconfig: %s", err)
	}

	kubeClient, err := k8s.CreateK8sClientFromKubeConfig(kubeConfigDecoded)
	if err != nil {
		return nil, fmt.Errorf("Can't create k8s client: %s", err)
	}

	return kubeClient, nil
}

func (api *api) getMongoCollectionForCheckType(checkType string) string {
	if checkType == "kube" {
		return "kube-bench-records"
	} else if checkType == "docker" {
		return "docker-bench-records"
	} else if checkType == "host" {
		return "host-bench-records"
	} else {
		return ""
	}
}

func (api *api) readJobObjFromYamlFile(checkType string) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == "kube" {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == "docker" {
		jobYamlPath = "/jobs/docker-bench-security/job.yaml"
	} else if checkType == "host" {
		jobYamlPath = "/jobs/host-bench/job.yaml"
	} else {
		return nil, fmt.Errorf("Unreachable code reached")
	}

	jobYaml, err := ioutil.ReadFile(jobYamlPath)
	if err != nil {
		return nil, fmt.Errorf("Can't read job file: %s", err)
	}

	jobObj := &batchv1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, fmt.Errorf("Can't decode job file: %s", err)
	}
	return jobObj, nil
}

func (api *api) scheduleOneJob(kubeClient *kubernetes.Clientset, namespace string, jobObj *batchv1.Job, checkUUID uuid.UUID, targetNodeName string) error {
	jobObj.Spec.Template.Spec.NodeName = targetNodeName

	if jobObj.Labels == nil {
		jobObj.Labels = make(map[string]string)
	}
	jobObj.Labels["CHECK_ID"] = checkUUID.String()
	jobObj.Name = fmt.Sprintf("%s-%s", checkUUID.String()[:8], jobObj.Name)

	nodeNameEnv := corev1.EnvVar{
		Name:  "NODE_NAME",
		Value: targetNodeName,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, nodeNameEnv)

	// TODO: This should be a secret. There's probably a better way to do this anyways.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=%s",
		api.scapper.MongoUsername, api.scapper.MongoPassword, api.scapper.MongoEndpoint, api.scapper.MongoDatabase, api.scapper.MongoDatabase)
	mongoStringEnv := corev1.EnvVar{
		Name:  "MONGO_STRING",
		Value: mongoString,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, mongoStringEnv)

	jobObj.Name = fmt.Sprintf("%s-%s", jobObj.Name, targetNodeName)

	jobsClient := kubeClient.BatchV1().Jobs(namespace)
	res, err := jobsClient.Create(jobObj)
	// HACK
	if k8serrors.IsAlreadyExists(err) {
		err = jobsClient.Delete(jobObj.Name, &metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("Job already exists, so tried deleting, but: %s", err)
		}

		time.Sleep(time.Second * 10)
		res, err = jobsClient.Create(jobObj)
	}
	if err != nil {
		return fmt.Errorf("Couldn't schedule job: %s", err)
	}

	jobName := res.ObjectMeta.Name

	logging.GetLogger().Info().
		Str("target-node", jobObj.Spec.Template.Spec.NodeName).
		Str("job-name", jobName).
		Msg("Scheduled SCAP check job")

	return nil
}

func (api *api) addScapInitialEntry(ctx context.Context, checkType string, checkUUID uuid.UUID, targetNodeName string) error {
	now := time.Now()
	secs := now.Unix()
	entry := JobEntry{
		ID:        primitive.NewObjectIDFromTimestamp(now),
		CheckID:   checkUUID.String(),
		NodeName:  targetNodeName,
		Status:    "scheduled",
		CreatedAt: secs,
	}
	// TODO: Potential race condition: we are inserting to mongo after scheduling the job (which upserts to mongo).
	// However I don't see a better way to do this right now.
	_, err := api.mongodb.Collection(api.getMongoCollectionForCheckType(checkType)).InsertOne(ctx, entry)
	if err != nil {
		return fmt.Errorf("Failed insert to mongo: %s", err)
	}

	return nil
}

func (api *api) startManagedJobRoutine(kubeClient *kubernetes.Clientset, namespace string, checkUUID uuid.UUID,
	numScheduledJobs int, checkType string) {
	var waitingForJobCompletionCount int64
	waitingForJobCompletionCount = int64(numScheduledJobs)

	// TODO: if console restarts while job is running, that job's events won't be watched.
	// TODO: rethink. Maybe we should have a listener thread all the time and utilize AddFunc
	// to listen to newly created jobs and keep track that way?
	// I think this design is kinda fragile... but I don't have any quick ideas.
	// A better design would be to create a k8s custom resource with a custom controller to manage it.

	kubeInformerFactory := informers.NewFilteredSharedInformerFactory(kubeClient, time.Second*30, namespace, func(listOpts *v1.ListOptions) {
		labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"CHECK_ID": checkUUID.String()}}
		listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()
	})
	jobInformer := kubeInformerFactory.Batch().V1().Jobs().Informer()

	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		DeleteFunc: func(obj interface{}) {},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Failed to cast to *batchv1.Job")
				return
			}

			if job.Status.Succeeded > 0 {
				atomic.AddInt64(&waitingForJobCompletionCount, -1)
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Int64("jobs-left", atomic.LoadInt64(&waitingForJobCompletionCount)).
					Msg("Managed job succeeded")

				// not sure if  we should delete... we should allow for user to read logs probably.
				// err := api.deleteJobAndPods(kubeClient, namespace, job)
				// if err != nil {
				// 	logging.GetLogger().Error().
				// 		Str("job-name", fmt.Sprintf("%s", job.Name)).
				// 		Err(err).
				// 		Msg("Failed to clean up job in k8s")
				// }
				return
			}

			var failedCondition *batchv1.JobCondition
			failedCondition = nil
			for idx, condition := range job.Status.Conditions {
				if condition.Type == batchv1.JobFailed {
					// according to documentation of JobStatus,
					// "When a job fails, one of the conditions will have type == "Failed"."
					failedCondition = &job.Status.Conditions[idx]
				}
			}
			if failedCondition != nil {
				atomic.AddInt64(&waitingForJobCompletionCount, -1)
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Int64("jobs-left", atomic.LoadInt64(&waitingForJobCompletionCount)).
					Msg("Managed job failed - updating it in mongo")

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				mongoCtx, cancel := api.getTimeoutCtx(time.Second * 10)
				defer cancel()

				thisNodeName := job.Spec.Template.Spec.NodeName
				// thisNodeName := ""
				// for _, env := range job.Spec.Template.Spec.Containers[0].Env {
				// 	if env.Name == "NODE_NAME" {
				// 		thisNodeName = env.Value
				// 	}
				// }

				filter := bson.M{"checkId": checkUUID.String(), "nodeName": thisNodeName}
				// TODO: is there better way to do this using struct annotations?
				update := bson.M{"$set": bson.M{
					"status":     "failed",
					"finishedAt": transTime.Unix(),
					"message":    msg,
				}}
				_, err := api.mongodb.Collection(api.getMongoCollectionForCheckType(checkType)).UpdateOne(mongoCtx, filter, update)
				if err != nil {
					logging.GetLogger().Error().
						Str("checkId", checkUUID.String()).
						Str("nodeName", thisNodeName).
						Msg("Failed to update mongo entry status to failed")
				}

				// not sure if  we should delete... we should allow for user to read logs probably.
				// err = api.deleteJobAndPods(kubeClient, namespace, job)
				// if err != nil {
				// 	logging.GetLogger().Error().
				// 		Str("job-name", fmt.Sprintf("%s", job.Name)).
				// 		Err(err).
				// 		Msg("Failed to clean up job in k8s")
				// }
				return
			}

			// some other event happened - pass.
			return
		},
	})

	stop := make(chan struct{})
	defer close(stop)

	logging.GetLogger().Info().
		Str("checkId", checkUUID.String()).
		Msg("Starting to watch for job events")
	kubeInformerFactory.Start(stop)

	for atomic.LoadInt64(&waitingForJobCompletionCount) > 0 {
		time.Sleep(time.Second * 1)
	}

	logging.GetLogger().Info().
		Str("checkId", checkUUID.String()).
		Msg("All managed jobs accounted for, done watching for events")
}

func (api *api) deleteJobAndPods(kubeClient *kubernetes.Clientset, namespace string, job *batchv1.Job) error {
	err := kubeClient.BatchV1().Jobs(namespace).Delete(job.Name, &metav1.DeleteOptions{})
	if err != nil {
		logging.GetLogger().Error().
			Str("job-name", fmt.Sprintf("%s", job.Name)).
			Err(err).
			Msg("Failed to delete job in k8s")
		return fmt.Errorf("Failed to delete job: %s", err)
	}

	listOpts := metav1.ListOptions{
		LabelSelector: labels.Set(job.Spec.Selector.MatchLabels).String(),
	}
	err = kubeClient.CoreV1().Pods(namespace).DeleteCollection(&metav1.DeleteOptions{}, listOpts)
	if err != nil {
		return fmt.Errorf("Failed to job's pods: %s", err)
	}
	return nil
}

// @Summary Tell scap to check
// @Description Tell scap to check
// @ID v1-scap-check
// @Produce json
// @Router /api/v1/scap/check [post]
// func (api *api) scapcheck() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		task := &model.ScapTask{
// 			ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
// 			ScannerType: "kubebench_all",
// 			Status:      model.ScannerStatusReady,
// 			CreatedAt:   time.Now().Unix(),
// 		}

// 		ctx, cancel := api.getTimeoutCtx()
// 		defer cancel()
// 		_, err := api.mongodb.Collection(model.ScapTasksCollection).
// 			InsertOne(ctx, task)
// 		if err != nil {
// 			response.InternalError(w, err.Error())
// 			return
// 		}

// 		response.Ok(w, task)
// 	}
// }
