package api

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScapTask())
		r.Post("/check/{checkType}/cluster/{clusterID}", api.scapCheck())
	}
}

// @Summary Get a scap task by scaptask ID
// @Description Get a scap task
// @ID v1-scap-task-get
// @Produce json
// @Param taskID path string true "scap task ID"
// @Router /api/v1/scap/task/{taskID} [get]
func (api *api) getScapTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result model.ScapTask
		err = api.mongodb.Collection(model.ScapTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, result)
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
	// type resp struct {
	// 	ClusterID string `json:"clusterID"`
	// }
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
		cluster, err := api.getClusterFromMongo(ctx, clusterID)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		kubeConfigDecoded, err := b64.StdEncoding.DecodeString(cluster.KubeConfig)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't decode kubeconfig: %s", err))

			return
		}

		kubeClient, err := k8s.CreateK8sClientFromKubeConfig(kubeConfigDecoded)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't create k8s client: %s", err))
			return
		}

		// read job yaml for this check type
		jobYamlPath := ""
		if checkType == "kube" {
			jobYamlPath = "/jobs/kube-bench/job.yaml"
		} else if checkType == "docker" {
			jobYamlPath = "/jobs/docker-bench-security/job.yaml"
		} else {
			response.InternalError(w, "TODO host SCAP")
			return
		}

		jobYaml, err := ioutil.ReadFile(jobYamlPath)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't read job file: %s", err))
			return
		}

		jobObj := &batchv1.Job{}
		decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
		err = decoder.Decode(&jobObj)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't decode job file: %s", err))
			return
		}

		// Subsitute job's image repository in job.yaml for the one configured for Console.
		currImage := jobObj.Spec.Template.Spec.Containers[0].Image
		splitted := strings.Split(currImage, "/")
		currImgname := splitted[1]
		newImage := fmt.Sprintf("%s/%s", api.scapper.DockerRepoHostPort, currImgname)
		jobObj.Spec.Template.Spec.Containers[0].Image = newImage

		// find nodes to schedule job on
		nodes, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't list nodes in this cluster: %s", err))
			return
		}

		// generate job uuid that will identify results of this run in database
		jobUUID := uuid.NewV4()
		jobEnv := corev1.EnvVar{
			Name:  "JOB_ID",
			Value: jobUUID.String(),
		}
		jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, jobEnv)

		// get namespace of this pod - it will be used for scheduled jobs/pods
		namespace := os.Getenv("MY_POD_NAMESPACE")
		if namespace == "" {
			namespace = "default"
		}

		// schedule jobs
		logging.GetLogger().Info().
			Str("job-type", checkType).
			Str("job-uuid", jobUUID.String()).
			Str("namespace", namespace).
			Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
			Msg("Scheduling SCAP jobs")

		for _, targetNode := range nodes.Items {
			// Note: I tested it on a 2-node microk8s cluster (ubuntu 18.04 and centos 8)
			// question is - will it scale?
			// What about context timeout? Launching jobs for thousands of nodes may take a while.

			// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
			// or do we not care about this since this is a rare operation?
			// Also, this should also clean up all Error and Completed pods.

			// See: https://kubernetes.io/docs/concepts/workloads/controllers/job/#specifying-your-own-pod-selector
			// We must specify controller-uid ourselves and tell k8s that we know what we're doing.
			// manSec := true
			// jobObj.Spec.ManualSelector = &manSec

			// // generate job uuid
			// jobControllerUUID := uuid.NewV4()

			// selector := metav1.LabelSelector{
			// 	MatchLabels: map[string]string{
			// 		"kubernetes.io/hostname": targetHostname,
			// 		"controller-uid":         jobControllerUUID.String(),
			// 	},
			// }
			// jobObj.Spec.Selector = &selector

			// jobObj.

			// jobObj.Spec.Template.Labels["kubernetes.io/hostname"] = targetHostname
			// jobObj.Spec.Template.Labels["controller-uid"] = jobControllerUUID.String()

			jobObjCp := jobObj.DeepCopy()

			jobObjCp.Spec.Template.Spec.NodeName = targetNode.Name

			nodeNameEnv := corev1.EnvVar{
				Name:  "NODE_NAME",
				Value: targetNode.Name,
			}
			jobObjCp.Spec.Template.Spec.Containers[0].Env = append(jobObjCp.Spec.Template.Spec.Containers[0].Env, nodeNameEnv)

			// TODO: This should be a secret. There's probably a better way to do this anyways.
			mongoString := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=%s",
				api.scapper.MongoUsername, api.scapper.MongoPassword, api.scapper.MongoEndpoint, api.scapper.MongoDatabase, api.scapper.MongoDatabase)
			mongoStringEnv := corev1.EnvVar{
				Name:  "MONGO_STRING",
				Value: mongoString,
			}
			jobObjCp.Spec.Template.Spec.Containers[0].Env = append(jobObjCp.Spec.Template.Spec.Containers[0].Env, mongoStringEnv)

			jobObjCp.Name = fmt.Sprintf("%s-%s", jobObjCp.Name, targetNode.Name)

			jobsClient := kubeClient.BatchV1().Jobs(namespace)
			res, err := jobsClient.Create(jobObjCp)
			// HACK
			if k8serrors.IsAlreadyExists(err) {
				err = jobsClient.Delete(jobObjCp.Name, &metav1.DeleteOptions{})
				if err != nil {

					response.InternalError(w, fmt.Sprintf("Job already exists, so tried deleting, but: %s", err))
					return
				}

				time.Sleep(time.Second * 10)
				res, err = jobsClient.Create(jobObjCp)
			}
			if err != nil {
				response.InternalError(w, fmt.Sprintf("Couldn't schedule job: %s", err))
				return
			}

			jobName := res.ObjectMeta.Name

			logging.GetLogger().Info().
				Str("target-node", jobObjCp.Spec.Template.Spec.NodeName).
				Str("job-name", jobName).
				Msg("Scheduled SCAP job")
		}

		if err != nil {
			response.InternalError(w, fmt.Sprintf("Failed to schedule job: %s", err))
			return
		}
	}
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
