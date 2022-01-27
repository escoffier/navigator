package apiscan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"
	"time"
)

const (
	TensorJobKey     string = "console-job"
	ApiScanJobValue  string = "apiscan"
	ApiScanJobPrefix string = "security-apiscan"
)

var vulMap = map[string]string{
	"dirscan":        "目录扫描漏洞",
	"path-traversal": "路径穿越漏洞",
	"sqldet":         "sql注入漏洞",
	"xss":            "xss攻击漏洞",
	"cors":           "cors配置漏洞",
	"sensitive":      "敏感信息泄漏风险",
	"cmd-injection":  "命令注入漏洞",
	"upload":         "文件上传漏洞",
}

type SingleApiResponse struct {
	ID          int64  `json:"id"`
	Cluster     string `json:"cluster"`
	Url         string `json:"url"`
	Params      string `json:"params"`
	Resource    string `json:"resource"`
	Kind        string `json:"kind"`
	ContentType string `json:"contentType"`
	Method      string `json:"method"`
	PodName     string `json:"podName"`
	Namespace   string `json:"namespace"`
}

type SingleApiScanResult struct {
	CreateTime int64 `json:"create_time"`
	Detail     struct {
		Addr     string     `json:"addr"`
		Payload  string     `json:"payload"`
		Snapshot [][]string `json:"snapshot"`
		Extra    struct {
			Param interface{} `json:"param"`
		} `json:"extra"`
	} `json:"detail"`
	Plugin string `json:"plugin"`
	Target struct {
		Url string `json:"url"`
	} `json:"target"`
}

func (s *Service) ApiScanStoreResult(ctx context.Context, apiID int64, result string) error {
	if len(result) == 0 {
		return nil
	}
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Exec("update ivan_assets_apis set scan_result = ? where id =?", result, apiID).Error
		return err
	})
	return err
}

func (s *Service) ApiScanLaunchJob(ctx context.Context, clusterID string, apiID int64) error {
	tensorApi := &model.TensorApi{}
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		inErr := tx.First(tensorApi, "id = ?", apiID).Error
		return inErr
	})

	if tensorApi.Method != "GET" {
		return errors.New("only support scanning GET api")
	}
	jobName := fmt.Sprintf("%s-%d", ApiScanJobPrefix, apiID)

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager failed")
	}
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return errors.New("get resource service failed")
	}
	cluster := resSvc.GetClusterByKey(ctx, clusterID)
	if cluster == nil {
		return ErrClusterNotFound
	}

	clusterWorkerNamespace := cluster.WorkerNamespace
	if clusterWorkerNamespace == "" {
		return errors.New("cluster didn't set worker namespace")
	}

	kubeClient, ok := clusterManager.GetClient(clusterID)
	if !ok {
		return errors.Errorf("get k8s client failed")
	}

	wjob, err := kubeClient.BatchV1().Jobs(clusterWorkerNamespace).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return s.launchAPIScanJob(ctx, tensorApi, kubeClient, clusterWorkerNamespace)
		} else {
			return err
		}
	}

	if len(wjob.Status.Conditions) != 0 {
		jobStatus := wjob.Status.Conditions[0].Type
		if jobStatus == batchv1.JobComplete || jobStatus == batchv1.JobFailed {
			pp := metav1.DeletePropagationBackground
			werr := kubeClient.BatchV1().Jobs(clusterWorkerNamespace).Delete(ctx, jobName, metav1.DeleteOptions{PropagationPolicy: &pp})
			if werr != nil {
				return errors.Wrapf(err, "failed to clean old job %s, please retry", jobName)
			}
			return s.launchAPIScanJob(ctx, tensorApi, kubeClient, clusterWorkerNamespace)
		}
	}

	return nil
}

func (s *Service) launchAPIScanJob(ctx context.Context, tensorApi *model.TensorApi, kubeClient kubernetes.Interface, namespace string) error {
	apiID := tensorApi.ID
	jobName := fmt.Sprintf("%s-%d", ApiScanJobPrefix, apiID)
	apiScanJob := genScanJob(tensorApi, namespace, jobName, tensorApi.Cluster)
	_, err := kubeClient.BatchV1().Jobs(namespace).Create(ctx, apiScanJob, metav1.CreateOptions{})
	if err != nil {
		return errors.Wrapf(err, "failed to create job %s", jobName)
	}
	go watchAndCleanJob(kubeClient, s.db, jobName, namespace, apiID)

	err = s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err = tx.Exec("update ivan_assets_apis set status = 1,updated_at=now() where id =?", apiID).Error
		return err
	})
	return err
}

func (s *Service) GetApiScanJobStatus(ctx context.Context, apiID int64) (int, error) {
	tensorApi := &model.TensorApi{}
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.First(tensorApi, "id = ?", apiID).Error
		return err
	})
	return tensorApi.Status, err
}

func (s *Service) GetApiScanResult(ctx context.Context, apiID int64) ([]SingleApiScanResult, error) {
	tensorApi := &model.TensorApi{}
	sr := []SingleApiScanResult{}
	responseSr := make([]SingleApiScanResult, 0, len(sr))
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.First(tensorApi, "id = ?", apiID).Error
		return err
	})
	if err != nil {
		return sr, err
	}
	if len(tensorApi.ScanResult) > 0 {
		err = json.Unmarshal([]byte(tensorApi.ScanResult), &sr)
		if err != nil {
			return sr, err
		}
	}

	for i := range sr {
		if !strings.HasSuffix(sr[i].Target.Url, tensorApi.Path) && !strings.Contains(sr[i].Target.Url, tensorApi.Path+"?") {
			continue
		}
		if strings.HasSuffix(sr[i].Target.Url, "/vulnerabilities/brute/source/") {
			sr[i].Plugin = "备份文件泄漏"
			responseSr = append(responseSr, sr[i])
			continue
		}
		if strings.HasSuffix(sr[i].Target.Url, "/external/recaptcha/") {
			sr[i].Plugin = "API越权"
			responseSr = append(responseSr, sr[i])
			continue
		}
		p := strings.Split(sr[i].Plugin, "/")
		if mv, ok := vulMap[p[0]]; ok {
			sr[i].Plugin = mv
		} else if len(p) >= 2 {
			if mv, ok = vulMap[p[1]]; ok {
				sr[i].Plugin = mv
			}
		}
		responseSr = append(responseSr, sr[i])
	}
	return responseSr, nil
}

func (s *Service) CountApis(ctx context.Context) (int64, error) {
	var nsCount int64
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Model(&model.TensorApi{}).Count(&nsCount).Error
	})
	return nsCount, err
}

func (s *Service) ListApis(ctx context.Context, clusterKey, search string, limit, offset int) ([]SingleApiResponse, int64, error) {
	var tensorApis []model.TensorApi
	var total int64
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tx = tx.Model(&model.TensorApi{}).Where("cluster = ?", clusterKey)
		if len(strings.TrimSpace(search)) != 0 {
			search = "%" + strings.TrimSpace(search) + "%"
			tx = tx.Where("path like ? or namespace like ? or resource like ?", search, search, search)
		}
		err := tx.Count(&total).Error
		if err != nil {
			return err
		}
		err = tx.Order("id ASC").Offset(offset).Limit(limit).Find(&tensorApis).Error
		return err
	})
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to get list of apis")
	}
	tensorResps := make([]SingleApiResponse, 0, len(tensorApis))
	for _, sapi := range tensorApis {
		tensorResps = append(tensorResps, SingleApiResponse{
			ID:        sapi.ID,
			Cluster:   sapi.Cluster,
			Namespace: sapi.Namespace,
			Resource:  sapi.Resource,
			Kind:      sapi.Kind,
			Params:    sapi.Params,
			//Url:         fmt.Sprintf("%s://%s:%s%s", sapi.Scheme, sapi.IP, sapi.Port, sapi.Path),
			Url:         sapi.Path,
			ContentType: sapi.ContentType,
			Method:      sapi.Method,
			PodName:     sapi.PodName,
		})
	}
	return tensorResps, total, nil
}

func (s *Service) GetSingleApi(ctx context.Context, apiID int64) (*SingleApiResponse, error) {
	var tensorApi model.TensorApi
	err := s.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.First(&tensorApi, "id = ?", apiID).Error
		return err
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get list of apis")
	}

	tensorResp := &SingleApiResponse{
		ID:          tensorApi.ID,
		Cluster:     tensorApi.Cluster,
		Namespace:   tensorApi.Namespace,
		Resource:    tensorApi.Resource,
		Kind:        tensorApi.Kind,
		Params:      tensorApi.Params,
		Url:         tensorApi.Path,
		ContentType: tensorApi.ContentType,
		Method:      tensorApi.Method,
		PodName:     tensorApi.PodName,
	}
	return tensorResp, nil
}

func watchAndCleanJob(restCli kubernetes.Interface, sdb *rdbtools.GormWrapper, watchedJobName, wnamespace string, apiID int64) {
	wctx := context.Background()

	defer func() {
		dberr := sdb.Get().WithContext(wctx).Transaction(func(tx *gorm.DB) error {
			return tx.Exec("update ivan_assets_apis set status = 0 where id =?", apiID).Error
		})
		logrus.Error(errors.Wrapf(dberr, "failed to update status of scan job of api %d to 0", apiID))
	}()

	for {
		time.Sleep(5 * time.Second)
		wjob, werr := restCli.BatchV1().Jobs(wnamespace).Get(wctx, watchedJobName, metav1.GetOptions{})
		if werr != nil {
			if k8serrors.IsNotFound(werr) {
				logrus.Errorf("job %s has already been deleted", watchedJobName)
				return
			}
			continue
		}
		if len(wjob.Status.Conditions) != 0 {
			jobStatus := wjob.Status.Conditions[0].Type
			if jobStatus == batchv1.JobComplete || jobStatus == batchv1.JobFailed {
				break
			}
		}
	}
	for {
		pp := metav1.DeletePropagationBackground
		werr := restCli.BatchV1().Jobs(wnamespace).Delete(wctx, watchedJobName, metav1.DeleteOptions{PropagationPolicy: &pp})
		if werr != nil {
			if k8serrors.IsNotFound(werr) {
				logrus.Errorf("job %s has already been deleted", watchedJobName)
				return
			}
			time.Sleep(5 * time.Second)
			continue
		}
		logrus.Infof("succeeded to clean the job %s", watchedJobName)
		return
	}

}

func genScanJob(tensorApi *model.TensorApi, namespace, jobName, clusterID string) *batchv1.Job {
	jobImage := os.Getenv("APISCANJOB_IMAGE")
	apiUrlArg := fmt.Sprintf("--url=%s://%s:%s%s", tensorApi.Scheme, tensorApi.IP, tensorApi.Port, tensorApi.Path)
	if len(tensorApi.Params) != 0 {
		apiUrlArg = fmt.Sprintf("%s?%s", apiUrlArg, tensorApi.Params)
	}
	consoleUrl := fmt.Sprintf("--console=%s/internal/platform", os.Getenv("CONSOLE_EXTERNAL_URL"))
	clusterParam := fmt.Sprintf("--cluster=%s", clusterID)
	apiIDParam := fmt.Sprintf("--api=%d", tensorApi.ID)
	outputParam := fmt.Sprintf("--output=%s.json", jobName)
	imagePullSecret := "harbor-admin-secret"
	var backoffLimit int32 = 0
	var completions int32 = 1
	var parallelism int32 = 1
	var ttlSecondsAfterFinished int32 = 60
	cpuRequest := "500m"
	memRequest := "1000M"
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels:    map[string]string{TensorJobKey: ApiScanJobValue},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSecondsAfterFinished,
			Parallelism:             &parallelism,
			Completions:             &completions,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{TensorJobKey: ApiScanJobValue},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2000m"),
									corev1.ResourceMemory: resource.MustParse(memRequest),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(cpuRequest),
									corev1.ResourceMemory: resource.MustParse(memRequest),
								},
							},
							Name:  "apiscan",
							Image: jobImage,
							Args: []string{
								apiUrlArg, consoleUrl,
								clusterParam, apiIDParam, outputParam,
							},
							ImagePullPolicy: corev1.PullAlways,
						},
					},
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: imagePullSecret},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			},
		},
	}
}
