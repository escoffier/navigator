package data

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
	batchV1 "k8s.io/api/batch/v1"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *Service) GetGCTask(ctx context.Context, gcTaskID string) (*model.GCTask, error) {
	return s.taskManager.GetGCTask(ctx, gcTaskID)
}

func (s *Service) RunGC(ctx context.Context, dataType string, ttl int) (task *model.GCTask, err error) {
	kubeClient, restConfig, err := k8s.KubeClientFromServiceAccoount()
	if err != nil || kubeClient == nil || restConfig == nil {
		return nil, fmt.Errorf("k8s is not ready")
	}

	var t def.GCTaskType
	err = t.ConvertFromStr(dataType)
	if err != nil {
		return nil, err
	}

	task, err = s.taskManager.CreateGCTask(ctx, t)
	if err != nil {
		return nil, err
	}

	err = s.launchK8sJob(ctx, kubeClient, t, task.Hash, ttl)
	if err != nil {
		if _err := s.taskManager.UpdateTaskStatus(ctx, task.Hash, model.GCFailed); _err != nil {
			logging.GetLogger().Error().Msgf("UpdateTaskStatus fail", zap.Error(err))
		}
		return nil, err
	}

	return task, nil
}

func (s *Service) launchK8sJob(ctx context.Context, client *kubernetes.Clientset, taskType def.GCTaskType, taskID string, ttl int) error {
	jobObj, err := s.loadJobTemplate(taskType)
	if err != nil {
		return fmt.Errorf("loadJobTemplate fail, err:%w", err)
	}

	if err = s.completeJobInfo(jobObj, taskType, ttl, taskID); err != nil {
		return fmt.Errorf("completeJobInfo fail, err:%w", err)
	}

	_, err = client.BatchV1().Jobs(getNamespace()).Create(ctx, jobObj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create job fail, err:%w", err)
	}

	return nil
}

func (s *Service) loadJobTemplate(taskType def.GCTaskType) (*batchV1.Job, error) {
	var jobYamlPath string
	switch taskType {
	case def.GCTaskTypeHotLogic:
		jobYamlPath = "/jobs/hot-logic/job.yaml"
	case def.GCTaskTypeHotOffline:
		jobYamlPath = "/jobs/hot-offline/job.yaml"
	case def.GCTaskTypeCold:
		jobYamlPath = "/jobs/cold/job.yaml"
	default:
		return nil, def.ErrUnknownTaskType
	}

	jobContent, err := ioutil.ReadFile(jobYamlPath)
	if err != nil {
		return nil, fmt.Errorf("can't read job file: %w", err)
	}

	jobObj := &batchV1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader(jobContent), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, fmt.Errorf("can't decode job file: %w", err)
	}

	return jobObj, nil
}

func (s *Service) completeJobInfo(job *batchV1.Job, taskType def.GCTaskType, ttl int, taskID string) error {
	if len(job.Spec.Template.Spec.Containers) != 1 {
		return fmt.Errorf("unexpected job template")
	}

	job.Spec.Template.Spec.Containers[0].Image = os.Getenv("CLEANER_IMAGE")
	job.Name = generateJobName(taskType, taskID)

	taskIDEnv := coreV1.EnvVar{
		Name:  env.TaskID,
		Value: taskID,
	}

	ttlEnv := coreV1.EnvVar{
		Name:  env.TTLDayOffset,
		Value: strconv.Itoa(ttl),
	}

	pgHostEnv := coreV1.EnvVar{
		Name:  env.RDBHost,
		Value: util.GetEnvWithDefault(env.RDBHost, ""),
	}

	pgPortEnv := coreV1.EnvVar{
		Name:  env.RDBPort,
		Value: util.GetEnvWithDefault(env.RDBPort, ""),
	}

	pgUserEnv := coreV1.EnvVar{
		Name:  env.RDBUser,
		Value: util.GetEnvWithDefault(env.RDBUser, ""),
	}

	pgPasswordEnv := coreV1.EnvVar{
		Name:  env.RDBPassword,
		Value: util.GetEnvWithDefault(env.RDBPassword, ""),
	}

	pgSSLModeEnv := coreV1.EnvVar{
		Name:  env.RDBSSLMode,
		Value: util.GetEnvWithDefault(env.RDBSSLMode, ""),
	}

	job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env, taskIDEnv, ttlEnv,
		pgHostEnv, pgPortEnv, pgUserEnv, pgPasswordEnv, pgSSLModeEnv)
	if taskType == def.GCTaskTypeHotOffline {
		esURLEnv := coreV1.EnvVar{
			Name:  env.ElasticURL,
			Value: util.GetEnvWithDefault(env.ElasticURL, ""),
		}
		esUsernameEnv := coreV1.EnvVar{
			Name:  env.ElasticUsername,
			Value: util.GetEnvWithDefault(env.ElasticUsername, ""),
		}
		esPasswordEnv := coreV1.EnvVar{
			Name:  env.ElasticPassword,
			Value: util.GetEnvWithDefault(env.ElasticPassword, ""),
		}
		job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env, esURLEnv, esUsernameEnv, esPasswordEnv)
	}
	return nil
}

func getNamespace() string {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	return namespace
}

func generateJobName(taskType def.GCTaskType, taskID string) string {
	return fmt.Sprintf("data-gc-%s-%s", strings.ToLower(taskType.String()), taskID)
}
