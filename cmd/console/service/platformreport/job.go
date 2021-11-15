package platformreport

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strconv"

	batchV1 "k8s.io/api/batch/v1"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/env"
	env2 "gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type jobArg struct {
	templateID     int32
	uuid           string
	startTimestamp int64
	endTimestamp   int64
}

func (s *Service) launchK8sJob(ctx context.Context, arg *jobArg) error {
	kubeClient, restConfig, err := k8s.KubeClientFromServiceAccoount()
	if err != nil || kubeClient == nil || restConfig == nil {
		return fmt.Errorf("k8s is not ready")
	}

	jobObj, err := s.loadJobTemplate()
	if err != nil {
		return fmt.Errorf("loadJobTemplate fail, err:%w", err)
	}

	if err = s.completeJobInfo(jobObj, arg); err != nil {
		return fmt.Errorf("completeJobInfo fail, err:%w", err)
	}

	_, err = kubeClient.BatchV1().Jobs(getNamespace()).Create(ctx, jobObj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create job fail, err:%w", err)
	}

	return nil
}

func (s *Service) loadJobTemplate() (*batchV1.Job, error) {
	var jobYamlPath = "/jobs/platform-report/job.yaml"

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

const (
	consoleBaseExternalURLEnv = "CONSOLE_EXTERNAL_URL"
	platformRelativePath      = "/"
)

func (s *Service) completeJobInfo(job *batchV1.Job, arg *jobArg) error {
	if len(job.Spec.Template.Spec.Containers) != 1 {
		return fmt.Errorf("unexpected job template")
	}

	job.Name = generateJobName(arg.uuid)
	job.Spec.Template.Spec.Containers[0].Image = util.GetEnvWithDefault(env.Image, "")

	uuidEnv := coreV1.EnvVar{
		Name:  env.UUID,
		Value: arg.uuid,
	}

	taskIDEnv := coreV1.EnvVar{
		Name:  env.TemplateID,
		Value: strconv.Itoa(int(arg.templateID)),
	}

	startTimestampEnv := coreV1.EnvVar{
		Name:  env.StartTimestamp,
		Value: strconv.Itoa(int(arg.startTimestamp)),
	}

	endTimestampEnv := coreV1.EnvVar{
		Name:  env.EndTimestamp,
		Value: strconv.Itoa(int(arg.endTimestamp)),
	}

	maxTaskTimeEnv := coreV1.EnvVar{
		Name:  env.MaxTaskTimeSec,
		Value: strconv.Itoa(int(MaxTaskTime.Seconds())),
	}

	pgHostEnv := coreV1.EnvVar{
		Name:  env.PostgresHost,
		Value: util.GetEnvWithDefault(env.PostgresHost, ""),
	}

	pgPortEnv := coreV1.EnvVar{
		Name:  env.PostgresPort,
		Value: util.GetEnvWithDefault(env.PostgresPort, ""),
	}

	pgUserEnv := coreV1.EnvVar{
		Name:  env.PostgresUser,
		Value: util.GetEnvWithDefault(env.PostgresUser, ""),
	}

	pgPasswordEnv := coreV1.EnvVar{
		Name:  env.PostgresPassword,
		Value: util.GetEnvWithDefault(env.PostgresPassword, ""),
	}

	pgSSLModeEnv := coreV1.EnvVar{
		Name:  env.PostgresSSLMode,
		Value: util.GetEnvWithDefault(env.PostgresSSLMode, ""),
	}

	emailHostEnv := coreV1.EnvVar{
		Name:  env.EmailHost,
		Value: s.emailConf.Host,
	}

	emailPortEnv := coreV1.EnvVar{
		Name:  env.EmailPort,
		Value: strconv.Itoa(s.emailConf.Port),
	}

	emailUsernameEnv := coreV1.EnvVar{
		Name:  env.EmailUsername,
		Value: s.emailConf.Username,
	}

	emailPasswordEnv := coreV1.EnvVar{
		Name:  env.EmailPassword,
		Value: s.emailConf.Password,
	}

	consoleBaseURL := util.GetEnvWithDefault(consoleBaseExternalURLEnv, "")
	notifyBaseURL, err := generateNotifyBaseURL(consoleBaseURL)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("invalid consoleBaseURL:%s", consoleBaseURL)
	}

	notifyBaseURLEnv := coreV1.EnvVar{
		Name:  env.NotifyBaseURL,
		Value: notifyBaseURL,
	}

	emailOfficialNameEnv := coreV1.EnvVar{
		Name:  env2.EmailOfficialName,
		Value: util.GetEnvWithDefault(env2.EmailOfficialName, env2.DefaultEmailOfficialName),
	}

	job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env,
		uuidEnv, taskIDEnv, startTimestampEnv, endTimestampEnv, maxTaskTimeEnv,
		emailOfficialNameEnv, emailHostEnv, emailPortEnv, emailUsernameEnv, emailPasswordEnv, notifyBaseURLEnv,
		pgHostEnv, pgPortEnv, pgUserEnv, pgPasswordEnv, pgSSLModeEnv)
	return nil
}

func generateJobName(uuid string) string {
	return fmt.Sprintf("platform-report-%s", uuid)
}

func getNamespace() string {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	return namespace
}

func generateNotifyBaseURL(consoleBaseURL string) (string, error) {
	u, err := url.Parse(consoleBaseURL)
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, platformRelativePath)

	return u.String(), nil
}
