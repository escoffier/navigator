package hunter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/def"
	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/env"
	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/taskmanager"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	batchV1 "k8s.io/api/batch/v1"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
)

type Service struct {
	taskManager def.TaskManager
	conf        *model.KubeHunterTranslateConf
}

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(db *databases.RDBInstance) error {
	if db == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		instance, err = newService(db)
	})
	return err
}

const (
	MaxScanTime = time.Hour * 2
)

func newService(db *databases.RDBInstance) (*Service, error) {
	confBytes, err := os.ReadFile("/kube-scanner/translate.json")
	if err != nil {
		logging.Get().Err(err).Msg("load kube-scanner translate conf fail")
		return nil, err
	}

	var conf model.KubeHunterTranslateConf
	err = json.Unmarshal(confBytes, &conf)
	if err != nil {
		logging.Get().Err(err).Msg("parse kube-scanner translate conf fail")
		return nil, err
	}

	service := &Service{
		taskManager: taskmanager.NewManager(db, MaxScanTime),
		conf:        &conf,
	}

	go service.expireRecordLoop()
	return service, nil
}

var (
	ErrClusterNotFound = errors.New("cluster not found")
)

const (
	mainClusterName = "default"
)

func (s *Service) Scan(ctx context.Context, clusterID string) (err error) {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return errors.New("get resource service failed")
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager failed")
	}

	cluster := resSvc.GetClusterByKey(ctx, clusterID)
	if cluster == nil {
		return ErrClusterNotFound
	}

	consoleBaseURL := util.GetEnvWithDefault(consoleBaseExternalURLEnv, "")
	if cluster.Name == mainClusterName {
		consoleBaseURL = util.GetEnvWithDefault(consoleBaseInternalURLEnv, "")
	}

	namespace := cluster.WorkerNamespace
	if namespace == "" {
		return errors.New("no namespace")
	}

	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return errors.Errorf("get k8s client failed")
	}

	uuid := util.GenerateUUIDHex()
	_, err = s.taskManager.CreateKubeHunterRecord(ctx, clusterID, uuid, model.GetUsernameFromContext(ctx))
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			oneCtx, oneCancel := context.WithTimeout(context.Background(), time.Second)
			defer oneCancel()
			if _err := s.taskManager.UpdateRecord(oneCtx, uuid, model.KubeHunterRecordStatusFailed, nil); _err != nil {
				logging.Get().Err(_err).Msg("UpdateRecord fail")
			}
		}
	}()

	return s.launchK8sJob(ctx, kubeClient, uuid, namespace, consoleBaseURL)
}

func (s *Service) launchK8sJob(ctx context.Context, client *pkgassets.Clientset, uuid, namespace, consoleBaseURL string) error {
	jobObj, err := s.loadJobTemplate()
	if err != nil {
		return fmt.Errorf("loadJobTemplate fail, err:%w", err)
	}

	if err = s.completeJobInfo(jobObj, uuid, consoleBaseURL); err != nil {
		return fmt.Errorf("completeJobInfo fail, err:%w", err)
	}

	_, err = client.BatchV1().Jobs(namespace).Create(ctx, jobObj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create job fail, err:%w", err)
	}

	return nil
}

func (s *Service) loadJobTemplate() (*batchV1.Job, error) {
	var jobYamlPath = "/jobs/kube-scanner/job.yaml"

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

func (s *Service) completeJobInfo(job *batchV1.Job, uuid, consoleBaseURL string) error {
	if len(job.Spec.Template.Spec.Containers) != 2 {
		return fmt.Errorf("unexpected job template")
	}

	job.Name = generateJobName(uuid)
	uuidEnv := coreV1.EnvVar{
		Name:  env.UUID,
		Value: uuid,
	}

	reportURL, err := generateReportURL(consoleBaseURL)
	if err != nil {
		return fmt.Errorf("generateReportURL fail, err:%s", err)
	}

	reportURLEnv := coreV1.EnvVar{
		Name:  env.ReportURL,
		Value: reportURL,
	}

	maxTaskTimeEnv := coreV1.EnvVar{
		Name:  env.MaxTaskTimeSec,
		Value: strconv.Itoa(int(MaxScanTime.Seconds())),
	}

	job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env,
		uuidEnv, reportURLEnv, maxTaskTimeEnv)
	return nil
}

const (
	consoleBaseInternalURLEnv = "CONSOLE_INTERNAL_URL"
	consoleBaseExternalURLEnv = "CONSOLE_EXTERNAL_URL"
	relativePath              = "/api/openapi/hunter-report"
)

func generateReportURL(consoleBaseURL string) (string, error) {
	u, err := url.Parse(consoleBaseURL)
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, relativePath)

	return u.String(), nil
}

func generateJobName(uuid string) string {
	return fmt.Sprintf("kube-scanner-%s", uuid)
}

func (s *Service) GetClusterScanResult(ctx context.Context, cluster, lang string) (*model.KubeHunterTotalDisplay, error) {
	record, err := s.taskManager.GetLatestCompleteRecord(ctx, cluster)
	if err != nil {
		return nil, err
	}

	return translateRecord(record, lang, s.conf)
}

const (
	defaultLang = string(lang.LanguageEN)
)

func translateRecord(record *model.KubeHunterRecord, lang string, conf *model.KubeHunterTranslateConf) (*model.KubeHunterTotalDisplay, error) {
	var meta model.KubeHunterRecordMeta
	var err = json.Unmarshal(record.MetaInfo, &meta)
	if err != nil {
		return nil, err
	}

	result := &model.KubeHunterTotalDisplay{
		UUID:            record.UUID,
		Cluster:         record.Cluster,
		Username:        record.Username,
		StartTimestamp:  util.GetMillisecondTimestampByTime(record.CreatedAt),
		EndTimestamp:    util.GetMillisecondTimestampByTime(record.UpdatedAt),
		Vulnerabilities: make([]*model.VulnerabilityDisplay, 0, len(meta.Vulnerabilities)),
	}

	result.NodeCount = len(meta.Nodes)
	result.ServiceCount = len(meta.Services)
	result.Severities = make(map[string]int)

	for _, v := range meta.Vulnerabilities {
		key := fmt.Sprintf("%s@%s@%s", v.Category, v.SubCategory, v.Name)
		item, ok := conf.Vulnerabilities[key]
		if !ok {
			logging.Get().Warn().Msgf("not found kube vulnerability:%s", key)
			continue
		}

		transItem, ok := item[lang]
		if !ok {
			logging.Get().Warn().Msgf("not found kube vulnerability trans:%s, lang:%s", key, lang)
			transItem, ok = item[defaultLang]
		}
		if !ok {
			logging.Get().Warn().Msgf("not found kube vulnerability default trans:%s", key)
			continue
		}

		vulnerabilityDisplay := &model.VulnerabilityDisplay{}
		vulnerabilityDisplay.Evidence = v.Evidence
		vulnerabilityDisplay.Location = v.Location
		vulnerabilityDisplay.Name = transItem.Name
		vulnerabilityDisplay.Category = transItem.Category
		vulnerabilityDisplay.SubCategory = transItem.SubCategory
		vulnerabilityDisplay.Description = transItem.Description
		vulnerabilityDisplay.IssueDetail = transItem.IssueDetail
		vulnerabilityDisplay.Remediation = transItem.Remediation
		vulnerabilityDisplay.Severity = translateSeverity(v.Severity, conf, lang)

		result.Severities[v.Severity]++
		result.VulnerabilityCount++

		result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilityDisplay)
	}

	translateLocation(result, conf, lang)

	return result, nil
}

func translateLocation(record *model.KubeHunterTotalDisplay, conf *model.KubeHunterTranslateConf, lang string) {
	if locationTrans, ok := conf.LocationTransConf[lang]; ok {
		for _, vulnerability := range record.Vulnerabilities {
			for old, trans := range locationTrans {
				vulnerability.Location = strings.ReplaceAll(vulnerability.Location, old, trans)
			}
		}
	}
}

func translateSeverity(severity string, conf *model.KubeHunterTranslateConf, lang string) string {
	if severityTrans, ok := conf.SeverityTransConf[lang]; ok {
		if result := severityTrans[severity]; result != "" {
			return result
		}
	}

	return severity
}

func (s *Service) CheckTaskInProgress(ctx context.Context, cluster string) (bool, error) {
	return s.taskManager.CheckInProgress(ctx, cluster)
}

func (s *Service) ReportKubeHunterResult(ctx context.Context, uuid string, originBody []byte) (err error) {
	defer func() {
		if err != nil {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), time.Second*2)
			defer cleanCancel()

			set := func() error {
				oneCtx, oneCancel := context.WithTimeout(cleanCtx, time.Millisecond*500)
				defer oneCancel()
				return s.taskManager.UpdateRecord(oneCtx, uuid, model.KubeHunterRecordStatusFailed, nil)
			}

			if _err := util.RetryWithBackoff(cleanCtx, set); _err != nil {
				logging.Get().Err(_err).Msgf("update record fail, uuid:%s", uuid)
			}
		}
	}()

	str, err := strconv.Unquote(util.Bytes2StringNoCopy(originBody))
	if err != nil {
		logging.Get().Err(err).Msg("try parse body failed")
		str = util.Bytes2StringNoCopy(originBody)
	}

	var content model.RawKubeHunterContent
	err = json.Unmarshal(util.String2BytesNoCopy(str), &content)
	if err != nil {
		return err
	}

	metaInfo, err := parseMetaInfo(&content)
	if err != nil {
		return err
	}

	set := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, time.Millisecond*500)
		defer oneCancel()
		return s.taskManager.UpdateRecord(oneCtx, uuid, model.KubeHunterRecordStatusComplete, metaInfo)
	}

	return util.RetryWithBackoff(ctx, set)
}

func parseMetaInfo(content *model.RawKubeHunterContent) ([]byte, error) {
	var meta model.KubeHunterRecordMeta
	meta.Nodes = content.Nodes
	meta.Services = content.Services
	meta.Vulnerabilities = make([]*model.VulnerabilityMeta, len(content.Vulnerabilities))
	for i := range content.Vulnerabilities {
		categoryItems := strings.Split(content.Vulnerabilities[i].Category, " // ")
		if len(categoryItems) != 2 {
			logging.Get().Error().Msgf("unexpected category:%s", content.Vulnerabilities[i].Category)
			continue
		}
		meta.Vulnerabilities[i] = &model.VulnerabilityMeta{
			Category:    categoryItems[0],
			SubCategory: categoryItems[1],
			Name:        content.Vulnerabilities[i].Vulnerability,
			Location:    content.Vulnerabilities[i].Location,
			Evidence:    content.Vulnerabilities[i].Evidence,
			Severity:    content.Vulnerabilities[i].Severity,
		}
	}

	result, err := json.Marshal(meta)
	logging.Get().Debug().Msgf("metaInfo:%s", util.Bytes2StringNoCopy(result))
	return result, err
}
