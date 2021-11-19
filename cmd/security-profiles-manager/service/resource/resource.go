package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	dp "github.com/novln/docker-parser"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/policy"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	v1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	kubesystemNamespace = "kube-system"
)

type SecResourceService struct {
	db          *rdbtools.GormWrapper
	k8sClient   *kubernetes.Clientset
	myNamespace string
}

var (
	instance *SecResourceService
	once     sync.Once
)

func Init(
	ctx context.Context,
	db *rdbtools.GormWrapper,
	k8sClient *kubernetes.Clientset,
) error {
	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE environment variable not set")
	}
	once.Do(func() {
		instance = &SecResourceService{
			db:          db,
			k8sClient:   k8sClient,
			myNamespace: myNamespace,
		}
	})

	return nil
}

func Get() (*SecResourceService, bool) {
	return instance, instance != nil
}

func (s *SecResourceService) ListNamespaces(ctx context.Context, cluster string, unattached bool) ([]string, int, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dbcancel()
	var namespaces []string
	query := []string{}
	if cluster != "" {
		query = append(query, fmt.Sprintf("cluster = '%s'", cluster))
	}
	if unattached {
		query = append(query, "security_policy_id is null")
	}
	partialQuery := s.db.Get().WithContext(dbctx).Model(&model.SecurityPolicyResource{})
	if len(query) > 0 {
		queryString := strings.Join(query, " and ")
		partialQuery = partialQuery.Where(queryString)
	}

	result := partialQuery.Distinct().Pluck("namespace", &namespaces)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return namespaces, int(len(namespaces)), nil
		}
		return namespaces, int(len(namespaces)), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing resoures in database: %w", result.Error))
	}

	return namespaces, int(len(namespaces)), nil
}

func (s *SecResourceService) ListResourceNames(ctx context.Context, cluster, namespace string, kind model.KubernetesResource, unattached bool) ([]string, int, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dbcancel()
	resourceNames := make([]string, 0)
	query := []string{}
	if cluster != "" {
		query = append(query, fmt.Sprintf("cluster = '%s'", cluster))
	}
	if namespace != "" {
		query = append(query, fmt.Sprintf("namespace = '%s'", namespace))
	}
	if kind != model.KubernetesResourceAny {
		query = append(query, fmt.Sprintf("kind = '%s'", kind))
	}
	if unattached {
		query = append(query, "security_policy_id is null")
	}
	partialQuery := s.db.Get().WithContext(dbctx).Model(&model.SecurityPolicyResource{})
	if len(query) > 0 {
		queryString := strings.Join(query, " and ")
		partialQuery = partialQuery.Where(queryString)
	}

	result := partialQuery.Distinct().Pluck("name", &resourceNames)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return resourceNames, int(len(resourceNames)), nil
		}
		return resourceNames, int(len(resourceNames)), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing resoures in database: %w", result.Error))
	}

	return resourceNames, int(len(resourceNames)), nil
}

func (s *SecResourceService) ListResourceKinds(ctx context.Context, cluster, namespace string, unattached bool) ([]string, int, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dbcancel()
	resourceKinds := make([]string, 0)
	query := []string{}
	if cluster != "" {
		query = append(query, fmt.Sprintf("cluster = '%s'", cluster))
	}
	if namespace != "" {
		query = append(query, fmt.Sprintf("namespace = '%s'", namespace))
	}
	if unattached {
		query = append(query, "security_policy_id is null")
	}
	partialQuery := s.db.Get().WithContext(dbctx).Model(&model.SecurityPolicyResource{})
	if len(query) > 0 {
		queryString := strings.Join(query, " and ")
		partialQuery = partialQuery.Where(queryString)
	}

	result := partialQuery.Distinct().Pluck("kind", &resourceKinds)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return resourceKinds, int(len(resourceKinds)), nil
		}
		return resourceKinds, int(len(resourceKinds)), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing resoures in database: %w", result.Error))
	}

	return resourceKinds, int(len(resourceKinds)), nil
}

func (s *SecResourceService) ListClusters(ctx context.Context, unattached bool) ([]string, int, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dbcancel()
	var clusters []string
	query := []string{}
	if unattached {
		query = append(query, "security_policy_id is null")
	}
	partialQuery := s.db.Get().WithContext(dbctx).Model(&model.SecurityPolicyResource{})
	if len(query) > 0 {
		queryString := strings.Join(query, " and ")
		partialQuery = partialQuery.Where(queryString)
	}

	result := partialQuery.Distinct().Pluck("cluster", &clusters)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return clusters, int(len(clusters)), nil
		}
		return clusters, int(len(clusters)), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing resoures in database: %w", result.Error))
	}

	return clusters, int(len(clusters)), nil
}

func (s *SecResourceService) ListResources(ctx context.Context, cluster, namespace string, resourceKind model.KubernetesResource, name, containerName string, unattached bool, offset int, limit int, sortBy string, sortOrder string, search string) ([]model.SecurityPolicyResource, int, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()
	var resources []model.SecurityPolicyResource
	var totalCount int64
	partialQuery := s.db.Get().WithContext(dbctx)
	if search != "" {
		sqlSearch := "%" + search + "%"
		partialQuery = partialQuery.Where("cluster LIKE ? OR namespace LIKE ? OR kind LIKE ? OR name LIKE ? OR container_name LIKE ?",
			sqlSearch, sqlSearch, sqlSearch, sqlSearch, sqlSearch)
	} else {
		query := make([]string, 0)
		if cluster != "" {
			query = append(query, fmt.Sprintf("cluster = '%s'", cluster))
		}
		if namespace != "" {
			query = append(query, fmt.Sprintf("namespace = '%s'", namespace))
		}
		if resourceKind != model.KubernetesResourceAny {
			query = append(query, fmt.Sprintf("kind = '%s'", resourceKind))
		}
		if name != "" {
			query = append(query, fmt.Sprintf("name = '%s'", name))
		}
		if containerName != "" {
			query = append(query, fmt.Sprintf("container_name = '%s'", containerName))
		}
		if unattached {
			query = append(query, "security_policy_id is null")
		}
		if len(query) > 0 {
			queryString := strings.Join(query, " and ")
			partialQuery = partialQuery.Where(queryString)
		}
	}

	var sort string
	if sortOrder == "asc" {
		sort = sortBy
	} else {
		sort = fmt.Sprintf("%s %s", sortBy, sortOrder)
	}

	result := partialQuery.Order(sort).Offset(offset).Limit(limit).Find(&resources).
		Offset(-1).Limit(-1).Count(&totalCount)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return resources, int(totalCount), nil
		}
		return resources, int(totalCount), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing resoures in database: %w", result.Error))
	}

	return resources, int(totalCount), nil
}

func (s *SecResourceService) Init() {
	informerFactory := informers.NewSharedInformerFactory(s.k8sClient, time.Minute*2)

	deploymentInformer := informerFactory.Apps().V1().Deployments().Informer()
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.Deployment)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.Deployment")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.Deployment)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.Deployment")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*v1.Deployment)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *v1.Deployment")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
		},
	})

	daemonsetInformer := informerFactory.Apps().V1().DaemonSets().Informer()
	daemonsetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.DaemonSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.DaemonSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceDaemonset, append(containers, initContainers...))
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.DaemonSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.DaemonSet")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceDaemonset, append(containers, initContainers...))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*v1.DaemonSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *v1.DaemonSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceDaemonset, append(containers, initContainers...))
		},
	})

	statefulsetInformer := informerFactory.Apps().V1().StatefulSets().Informer()
	statefulsetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.StatefulSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.StatefulSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceStatefulset, append(containers, initContainers...))
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.StatefulSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.StatefulSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceStatefulset, append(containers, initContainers...))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*v1.StatefulSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *v1.StatefulSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceStatefulset, append(containers, initContainers...))
		},
	})

	cronjobsInformer := informerFactory.Batch().V1beta1().CronJobs().Informer()
	cronjobsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*v1beta1.CronJob)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1beta1.CronJob")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.JobTemplate.Spec.Template.Spec.Containers
			initContainers := resource.Spec.JobTemplate.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceCronJob, append(containers, initContainers...))
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*v1beta1.CronJob)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1beta1.CronJob")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.JobTemplate.Spec.Template.Spec.Containers
			initContainers := resource.Spec.JobTemplate.Spec.Template.Spec.InitContainers
			s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceCronJob, append(containers, initContainers...))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*v1beta1.CronJob)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *v1beta1.CronJob")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.JobTemplate.Spec.Template.Spec.Containers
			initContainers := resource.Spec.JobTemplate.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceCronJob, append(containers, initContainers...))
		},
	})

	jobsInformer := informerFactory.Batch().V1().Jobs().Informer()
	jobsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *batchv1.Job")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceJob, append(containers, initContainers...))
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *batchv1.Job")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceJob, append(containers, initContainers...))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *batchv1.Job")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			containers := resource.Spec.Template.Spec.Containers
			initContainers := resource.Spec.Template.Spec.InitContainers
			s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceJob, append(containers, initContainers...))
		},
	})

	replicasetInformer := informerFactory.Apps().V1().ReplicaSets().Informer()
	replicasetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.ReplicaSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.ReplicaSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			owner := metav1.GetControllerOf(resource)
			if owner != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				deployment, err := s.k8sClient.AppsV1().Deployments(resource.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to get owner of *v1.ReplicaSet")
					return
				}
				containers := deployment.Spec.Template.Spec.Containers
				initContainers := deployment.Spec.Template.Spec.InitContainers
				s.addResource(deployment.Name, deployment.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
			} else {
				containers := resource.Spec.Template.Spec.Containers
				initContainers := resource.Spec.Template.Spec.InitContainers
				s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceReplicaSet, append(containers, initContainers...))
			}
		},
		DeleteFunc: func(obj interface{}) {
			resource, ok := obj.(*v1.ReplicaSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *v1.ReplicaSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			owner := metav1.GetControllerOf(resource)
			if owner != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				deployment, err := s.k8sClient.AppsV1().Deployments(resource.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to get owner of *v1.ReplicaSet")
					return
				}
				containers := deployment.Spec.Template.Spec.Containers
				initContainers := deployment.Spec.Template.Spec.InitContainers
				s.removeResource(deployment.Name, deployment.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
			} else {
				containers := resource.Spec.Template.Spec.Containers
				initContainers := resource.Spec.Template.Spec.InitContainers
				s.removeResource(resource.Name, resource.Namespace, model.KubernetesResourceReplicaSet, append(containers, initContainers...))
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			resource, ok := newObj.(*v1.ReplicaSet)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *v1.ReplicaSet")
				return
			}
			if resource.Namespace == s.myNamespace || resource.Namespace == kubesystemNamespace {
				logging.GetLogger().Debug().Str("namespace", resource.Namespace).
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Resource existing in namespace, for which profiles cannot be generated. Skipping")
				return
			}
			owner := metav1.GetControllerOf(resource)
			if owner != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				deployment, err := s.k8sClient.AppsV1().Deployments(resource.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to get owner of *v1.ReplicaSet")
					return
				}
				containers := deployment.Spec.Template.Spec.Containers
				initContainers := deployment.Spec.Template.Spec.InitContainers
				s.addResource(deployment.Name, deployment.Namespace, model.KubernetesResourceDeployment, append(containers, initContainers...))
			} else {
				containers := resource.Spec.Template.Spec.Containers
				initContainers := resource.Spec.Template.Spec.InitContainers
				s.addResource(resource.Name, resource.Namespace, model.KubernetesResourceReplicaSet, append(containers, initContainers...))
			}
		},
	})

	stopChan := make(chan struct{})
	informerFactory.Start(stopChan)

	logging.GetLogger().Info().Msg("Kubernetes watcher initialized")

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	stopChan <- struct{}{}
}

func (s *SecResourceService) addResource(name string, namespace string, kind model.KubernetesResource, containers []corev1.Container) error {
	policyService, exists := policy.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get policy service")
		return fmt.Errorf("Failed to get policy service")
	}

	for _, c := range containers {
		reference, err := dp.Parse(c.Image)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("image", c.Image).Msg("Failed to parse image")
			continue
		}
		resource := model.SecurityPolicyResource{
			Cluster:       "default",
			Name:          name,
			Namespace:     namespace,
			Kind:          kind,
			ContainerName: c.Name,
			ImageRegistry: reference.Registry(),
			ImageName:     reference.ShortName(),
			ImageTag:      reference.Tag(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = policyService.AddResource(ctx, resource)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("resource", fmt.Sprintf("%v", resource)).Msg("Failed to add resource")
			continue
		}
	}

	return nil
}

func (s *SecResourceService) removeResource(name string, namespace string, kind model.KubernetesResource, containers []corev1.Container) error {
	policyService, exists := policy.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get policy service")
		return fmt.Errorf("Failed to get policy service")
	}
	for _, c := range containers {
		reference, err := dp.Parse(c.Image)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("image", c.Image).Msg("Failed to parse image")
			continue
		}
		resource := model.SecurityPolicyResource{
			Cluster:       "default",
			Name:          name,
			Namespace:     namespace,
			Kind:          kind,
			ContainerName: c.Name,
			ImageRegistry: reference.Registry(),
			ImageName:     reference.ShortName(),
			ImageTag:      reference.Tag(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = policyService.RemoveResource(ctx, resource)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("resource", fmt.Sprintf("%v", resource)).Msg("Failed to remove resource")
			continue
		}
	}

	return nil
}
