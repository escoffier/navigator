package assets

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/constants"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes"
	netLister "k8s.io/client-go/listers/networking/v1"

	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	applisters "k8s.io/client-go/listers/apps/v1"
	batchv1lister "k8s.io/client-go/listers/batch/v1"
	v1beta1lister "k8s.io/client-go/listers/batch/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	defenselisters "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/defense/v1"
	sigYaml "sigs.k8s.io/yaml"
)

const (
	dupCacheSize = 16 * 1024
)

var (
	DeploymentType        = reflect.TypeOf(&appsv1.Deployment{})
	DaemonSetType         = reflect.TypeOf(&appsv1.DaemonSet{})
	PodType               = reflect.TypeOf(&corev1.Pod{})
	IngressType           = reflect.TypeOf(&netv1.Ingress{})
	ServiceType           = reflect.TypeOf(&corev1.Service{})
	EndpointsType         = reflect.TypeOf(&corev1.Endpoints{})
	SecretType            = reflect.TypeOf(&corev1.Secret{})
	PVType                = reflect.TypeOf(&corev1.PersistentVolume{})
	PVCType               = reflect.TypeOf(&corev1.PersistentVolumeClaim{})
	ReplicaSetType        = reflect.TypeOf(&appsv1.ReplicaSet{})
	JobType               = reflect.TypeOf(&batchv1.Job{})
	CronJobType           = reflect.TypeOf(&v1beta1.CronJob{})
	CronJobV1Type         = reflect.TypeOf(&batchv1.CronJob{})
	ReplicaControllerType = reflect.TypeOf(&corev1.ReplicationController{})
	StatefulSetType       = reflect.TypeOf(&appsv1.StatefulSet{})
	RoleType              = reflect.TypeOf(&rbacv1.Role{})
	ClusterRoleType       = reflect.TypeOf(&rbacv1.ClusterRole{})
	NamespaceType         = reflect.TypeOf(&corev1.Namespace{})
	NodeType              = reflect.TypeOf(&corev1.Node{})
	HoneySportType        = reflect.TypeOf(&defensev1.Honeypot{})
)

type Controller struct {
	podLister       corelisters.PodLister
	dpLister        applisters.DeploymentLister
	dsLister        applisters.DaemonSetLister
	jbLister        batchv1lister.JobLister
	cjbLister       v1beta1lister.CronJobLister
	cjbv1Lister     batchv1lister.CronJobLister
	rcLister        corelisters.ReplicationControllerLister
	ssLister        applisters.StatefulSetLister
	rsLister        applisters.ReplicaSetLister
	rlLister        rbaclisters.RoleLister
	crlLister       rbaclisters.ClusterRoleLister
	nsLister        corelisters.NamespaceLister
	nodeLister      corelisters.NodeLister
	hpLister        defenselisters.HoneypotLister
	svcLister       corelisters.ServiceLister
	endLister       corelisters.EndpointsLister
	secretLister    corelisters.SecretLister
	pvLister        corelisters.PersistentVolumeLister
	pvcLister       corelisters.PersistentVolumeClaimLister
	ingNetV1Lister  netLister.IngressLister
	ingNetV1BLister netLister.IngressLister
	ingExtV1BLister netLister.IngressLister
	podSynced       cache.InformerSynced
	dsSynced        cache.InformerSynced
	dpSynced        cache.InformerSynced
	jbSynced        cache.InformerSynced
	cjbSynced       cache.InformerSynced
	rcSynced        cache.InformerSynced
	ssSynced        cache.InformerSynced
	rsSynced        cache.InformerSynced
	rlSynced        cache.InformerSynced
	crlSynced       cache.InformerSynced
	nsSynced        cache.InformerSynced
	nodeSynced      cache.InformerSynced
	hpSynced        cache.InformerSynced
	svcSynced       cache.InformerSynced
	endSynced       cache.InformerSynced
	secretSynced    cache.InformerSynced
	pvSynced        cache.InformerSynced
	pvcSynced       cache.InformerSynced
	ingNetV1Synced  cache.InformerSynced
	ingNetV1BSynced cache.InformerSynced
	ingExtV1BSynced cache.InformerSynced
	queue           workqueue.RateLimitingInterface
	clusterKey      string
	mqWriter        mq.Writer
	topic           string
	poolInfo        *pkgassets.PoolInfo

	dupCache *pkgassets.DuplicationCheckingCache
}

type Assets struct {
	Object interface{}
	Type   reflect.Type
	key    string
	Action pkgassets.Action
}

func NewAssetsController(factory informers.SharedInformerFactory, tensorFactory externalversions.SharedInformerFactory, writer mq.Writer, clusterKey, topic string, poolInfo *pkgassets.PoolInfo, k8sClient *kubernetes.Clientset) (*Controller, error) {
	ac := &Controller{
		podLister:    factory.Core().V1().Pods().Lister(),
		dpLister:     factory.Apps().V1().Deployments().Lister(),
		dsLister:     factory.Apps().V1().DaemonSets().Lister(),
		ssLister:     factory.Apps().V1().StatefulSets().Lister(),
		rsLister:     factory.Apps().V1().ReplicaSets().Lister(),
		rlLister:     factory.Rbac().V1().Roles().Lister(),
		crlLister:    factory.Rbac().V1().ClusterRoles().Lister(),
		nsLister:     factory.Core().V1().Namespaces().Lister(),
		nodeLister:   factory.Core().V1().Nodes().Lister(),
		jbLister:     factory.Batch().V1().Jobs().Lister(),
		rcLister:     factory.Core().V1().ReplicationControllers().Lister(),
		hpLister:     tensorFactory.Defense().V1().Honeypots().Lister(),
		svcLister:    factory.Core().V1().Services().Lister(),
		endLister:    factory.Core().V1().Endpoints().Lister(),
		secretLister: factory.Core().V1().Secrets().Lister(),
		pvLister:     factory.Core().V1().PersistentVolumes().Lister(),
		pvcLister:    factory.Core().V1().PersistentVolumeClaims().Lister(),
		queue:        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "assets"),
		clusterKey:   clusterKey,
		mqWriter:     writer,
		topic:        topic,
		poolInfo:     poolInfo,
		dupCache:     pkgassets.NewDuplicationCheckingCache(3*time.Hour, dupCacheSize),
	}
	// todo 可优化为api-resource方式
	var version int
	kubeVersion, err := k8sClient.DiscoveryClient.ServerVersion()
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Msgf("kubernetes version: %s", kubeVersion.String())
	version = k8s.GetKubeMininorVersion(kubeVersion.String())
	// cronjob is deprecated in v1.21+ unavailable in v1.25+
	if version >= 21 {
		ac.cjbv1Lister = factory.Batch().V1().CronJobs().Lister()
		factory.Batch().V1().CronJobs().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    ac.addCronJob,
			UpdateFunc: ac.updateCronJob,
			DeleteFunc: ac.deleteCronJob,
		})
		ac.cjbSynced = factory.Batch().V1().CronJobs().Informer().HasSynced
	} else {
		ac.cjbLister = factory.Batch().V1beta1().CronJobs().Lister()
		factory.Batch().V1beta1().CronJobs().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    ac.addCronJob,
			UpdateFunc: ac.updateCronJob,
			DeleteFunc: ac.deleteCronJob,
		})
		ac.cjbSynced = factory.Batch().V1beta1().CronJobs().Informer().HasSynced
	}

	// ingress  暂时 支持 networking.k8s.io/v1
	var supportedIngressApiVersion []string
	resources, err := k8sClient.Discovery().ServerPreferredResources()
	if err != nil {
		logging.Get().Err(err).Msgf("get api-resources failed.")
	}
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		for _, apiRes := range resource.APIResources {
			if apiRes.Kind == "Ingress" {
				supportedIngressApiVersion = append(supportedIngressApiVersion, resource.GroupVersion)
				break
			}
		}
	}
	logging.Get().Info().Msgf("kubernetes support ingress apiVersionList: %v", supportedIngressApiVersion)
	syncedFunc := func() bool { return true }
	if len(supportedIngressApiVersion) == 0 {
		ac.ingNetV1Synced = syncedFunc
		ac.ingNetV1BSynced = syncedFunc
		ac.ingExtV1BSynced = syncedFunc
	}
	for _, apiVersion := range supportedIngressApiVersion {
		switch apiVersion {
		case "networking.k8s.io/v1":
			ac.ingNetV1Lister = factory.Networking().V1().Ingresses().Lister()
			// Ingress
			factory.Networking().V1().Ingresses().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc:    ac.addIngress,
				UpdateFunc: ac.updateIngress,
				DeleteFunc: ac.deleteIngress,
			})
			ac.ingNetV1Synced = factory.Networking().V1().Ingresses().Informer().HasSynced
			ac.ingNetV1BSynced = syncedFunc
			ac.ingExtV1BSynced = syncedFunc
		case "networking.k8s.io/v1beta1":
			ac.ingNetV1Synced = syncedFunc
			ac.ingNetV1BSynced = syncedFunc
			ac.ingExtV1BSynced = syncedFunc
		case "extensions/v1beta1":
			ac.ingNetV1Synced = syncedFunc
			ac.ingNetV1BSynced = syncedFunc
			ac.ingExtV1BSynced = syncedFunc
		}
	}

	tensorFactory.Defense().V1().Honeypots().Lister()
	// Pods
	factory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addPod,
		UpdateFunc: ac.updatePod,
		DeleteFunc: ac.deletePod,
	})
	factory.Core().V1().Pods().Informer().AddIndexers(cache.Indexers{
		constants.PodIpIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return nil, fmt.Errorf("object is not a pod")
			}
			return []string{pod.Status.PodIP}, nil
		},
	})
	ac.podSynced = factory.Core().V1().Pods().Informer().HasSynced

	// Deployments
	factory.Apps().V1().Deployments().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addDeployment,
		UpdateFunc: ac.updateDeployment,
		DeleteFunc: ac.deleteDeployment,
	})
	ac.dpSynced = factory.Apps().V1().Deployments().Informer().HasSynced

	// DaemonSets
	factory.Apps().V1().DaemonSets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addDaemonSet,
		UpdateFunc: ac.updateDaemonSet,
		DeleteFunc: ac.deleteDaemonSet,
	})
	ac.dsSynced = factory.Apps().V1().DaemonSets().Informer().HasSynced

	// ReplicaSets
	factory.Apps().V1().ReplicaSets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addReplicaSet,
		UpdateFunc: ac.updateReplicaSet,
		DeleteFunc: ac.deleteReplicaSet,
	})
	ac.rsSynced = factory.Apps().V1().ReplicaSets().Informer().HasSynced

	// Roles
	factory.Rbac().V1().Roles().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addRole,
		UpdateFunc: ac.updateRole,
		DeleteFunc: ac.deleteRole,
	})
	ac.rlSynced = factory.Rbac().V1().Roles().Informer().HasSynced

	// ClusterRoles
	factory.Rbac().V1().ClusterRoles().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addClusterRole,
		UpdateFunc: ac.updateClusterRole,
		DeleteFunc: ac.deleteClusterRole,
	})
	ac.crlSynced = factory.Rbac().V1().ClusterRoles().Informer().HasSynced

	// Namespaces
	factory.Core().V1().Namespaces().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addNamespace,
		UpdateFunc: ac.updateNamespace,
		DeleteFunc: ac.deleteNamespace,
	})
	ac.nsSynced = factory.Core().V1().Namespaces().Informer().HasSynced

	// Service
	factory.Core().V1().Services().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addSvc,
		UpdateFunc: ac.updateSvc,
		DeleteFunc: ac.deleteSvc,
	})
	factory.Core().V1().Services().Informer().AddIndexers(cache.Indexers{
		constants.ServiceIpIndex: func(obj interface{}) ([]string, error) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				return nil, fmt.Errorf("object is not a Service")
			}
			return []string{service.Spec.ClusterIP}, nil
		},
	})
	ac.svcSynced = factory.Core().V1().Services().Informer().HasSynced

	// Endpoints
	factory.Core().V1().Endpoints().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addEndpoints,
		UpdateFunc: ac.updateEndpoints,
		DeleteFunc: ac.deleteEndpoints,
	})
	ac.endSynced = factory.Core().V1().Endpoints().Informer().HasSynced

	// Secret
	factory.Core().V1().Secrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addSecret,
		UpdateFunc: ac.updateSecret,
		DeleteFunc: ac.deleteSecret,
	})
	ac.secretSynced = factory.Core().V1().Secrets().Informer().HasSynced

	// PV
	factory.Core().V1().PersistentVolumes().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addPV,
		UpdateFunc: ac.updatePV,
		DeleteFunc: ac.deletePV,
	})
	ac.pvSynced = factory.Core().V1().PersistentVolumes().Informer().HasSynced

	// PVC
	factory.Core().V1().PersistentVolumeClaims().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addPVC,
		UpdateFunc: ac.updatePVC,
		DeleteFunc: ac.deletePVC,
	})
	ac.pvcSynced = factory.Core().V1().PersistentVolumeClaims().Informer().HasSynced

	// Nodes
	factory.Core().V1().Nodes().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addNode,
		UpdateFunc: ac.updateNode,
		DeleteFunc: ac.deleteNode,
	})
	ac.nodeSynced = factory.Core().V1().Nodes().Informer().HasSynced

	// ReplicationControllers
	factory.Core().V1().ReplicationControllers().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addReplicationController,
		UpdateFunc: ac.updateReplicationController,
		DeleteFunc: ac.deleteReplicationController,
	})
	ac.rcSynced = factory.Core().V1().ReplicationControllers().Informer().HasSynced

	// Jobs
	factory.Batch().V1().Jobs().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addJob,
		UpdateFunc: ac.updateJob,
		DeleteFunc: ac.deleteJob,
	})
	ac.jbSynced = factory.Batch().V1().Jobs().Informer().HasSynced

	// StatefulSets
	factory.Apps().V1().StatefulSets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addStatefulSet,
		UpdateFunc: ac.updateStatefulSet,
		DeleteFunc: ac.deleteStatefulSet,
	})
	ac.ssSynced = factory.Apps().V1().StatefulSets().Informer().HasSynced

	tensorFactory.Defense().V1().Honeypots().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addHoneySpot,
		UpdateFunc: ac.updateHoneySpot,
		DeleteFunc: ac.deleteHoneySpot,
	})
	ac.hpSynced = tensorFactory.Defense().V1().Honeypots().Informer().HasSynced

	return ac, nil
}

func (ac *Controller) Run(stopChan <-chan struct{}) {
	defer ac.queue.ShutDown()
	logging.Get().Info().Msg("wait for synced...")
	if !cache.WaitForNamedCacheSync("assetsController", stopChan, ac.dpSynced, ac.dsSynced, ac.podSynced, ac.rsSynced,
		ac.rlSynced, ac.crlSynced, ac.nsSynced, ac.nodeSynced, ac.jbSynced, ac.cjbSynced, ac.rcSynced, ac.ssSynced, ac.hpSynced, ac.ingNetV1Synced, ac.ingNetV1BSynced, ac.ingExtV1BSynced, ac.svcSynced, ac.endSynced,
		ac.secretSynced, ac.pvSynced, ac.pvcSynced) {
		return
	}
	ac.notifySync()
	wait.Until(ac.worker, time.Second, stopChan)
	<-stopChan
}

func (ac *Controller) addDeployment(obj interface{}) {
	d := obj.(*appsv1.Deployment)
	logging.Get().Debug().Msgf("add deployment %s/%s", d.Namespace, d.Name)

	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateDeployment(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.Deployment)
	newD := newObject.(*appsv1.Deployment)

	if newD.Generation != oldD.Generation {
		logging.Get().Debug().Msgf("update deployment %s", oldD.Name)
		ac.enqueue(newD, pkgassets.ActionUpdate)
	}
}

func (ac *Controller) deleteDeployment(obj interface{}) {
	d := obj.(*appsv1.Deployment)
	logging.Get().Debug().Msgf("delete deployment %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addDaemonSet(obj interface{}) {
	d := obj.(*appsv1.DaemonSet)
	logging.Get().Debug().Msgf("add daemonset %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateDaemonSet(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.DaemonSet)
	newD := newObject.(*appsv1.DaemonSet)
	if newD.Generation != oldD.Generation {
		logging.Get().Debug().Msgf("update daemonset %s", oldD.Name)
		ac.enqueue(newD, pkgassets.ActionUpdate)
	}
}

func (ac *Controller) deleteDaemonSet(obj interface{}) {
	d := obj.(*appsv1.DaemonSet)
	logging.Get().Debug().Msgf("delete daemonset %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addReplicaSet(obj interface{}) {
	d := obj.(*appsv1.ReplicaSet)
	logging.Get().Debug().Msgf("add replica set %s/%s", d.Namespace, d.Name)
	if d.OwnerReferences != nil && len(d.OwnerReferences) != 0 { // 表示该replicaSet为其他资源(如deployment)派生
		return
	}
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateReplicaSet(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.ReplicaSet)
	newD := newObject.(*appsv1.ReplicaSet)
	if newD.OwnerReferences != nil && len(newD.OwnerReferences) != 0 { // 表示该replicaSet为其他资源(如deployment)派生
		return
	}
	if newD.Generation != oldD.Generation {
		logging.Get().Debug().Msgf("update replica set %s", oldD.Name)
		ac.enqueue(newD, pkgassets.ActionUpdate)
	}
}

func (ac *Controller) deleteReplicaSet(obj interface{}) {
	d := obj.(*appsv1.ReplicaSet)
	logging.Get().Debug().Msgf("delete replica set %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addPod(obj interface{}) {
	d := obj.(*corev1.Pod)
	logging.Get().Debug().Msgf("add pod %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updatePod(oldObj, newObject interface{}) {
	oldD := oldObj.(*corev1.Pod)
	newD := newObject.(*corev1.Pod)
	logging.Get().Debug().Msgf("update pod %s", oldD.Name)

	ac.enqueue(newD, pkgassets.ActionUpdate)
}

func (ac *Controller) deletePod(obj interface{}) {
	d := obj.(*corev1.Pod)
	logging.Get().Debug().Msgf("delete pod %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addRole(obj interface{}) {
	d := obj.(*rbacv1.Role)
	logging.Get().Debug().Msgf("add role %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateRole(oldObj, newObject interface{}) {
	oldR := oldObj.(*rbacv1.Role)
	newR := newObject.(*rbacv1.Role)
	logging.Get().Debug().Msgf("update role %s", oldR.Name)
	ac.enqueue(newR, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteRole(obj interface{}) {
	d := obj.(*rbacv1.Role)
	logging.Get().Debug().Msgf("delete role %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addClusterRole(obj interface{}) {
	d := obj.(*rbacv1.ClusterRole)
	logging.Get().Debug().Msgf("add cluster role %s", d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateClusterRole(oldObj, newObject interface{}) {
	oldR := oldObj.(*rbacv1.ClusterRole)
	newR := newObject.(*rbacv1.ClusterRole)
	logging.Get().Debug().Msgf("update cluster role %s", oldR.Name)
	ac.enqueue(newR, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteClusterRole(obj interface{}) {
	d := obj.(*rbacv1.ClusterRole)
	logging.Get().Debug().Msgf("delete cluster role %s", d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addNamespace(obj interface{}) {
	d := obj.(*corev1.Namespace)
	logging.Get().Debug().Msgf("add namespace %s", d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateNamespace(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.Namespace)
	newR := newObject.(*corev1.Namespace)
	logging.Get().Debug().Msgf("update namespace %s", oldR.Name)
	ac.enqueue(newR, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteNamespace(obj interface{}) {
	d := obj.(*corev1.Namespace)
	logging.Get().Debug().Msgf("delete namespace %s", d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addNode(obj interface{}) {
	d := obj.(*corev1.Node)
	logging.Get().Debug().Msgf("add node %s", d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateNode(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.Node)
	newR := newObject.(*corev1.Node)
	logging.Get().Debug().Msgf("update node %s", oldR.Name)
	ac.enqueue(newR, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteNode(obj interface{}) {
	d := obj.(*corev1.Node)
	logging.Get().Debug().Msgf("delete node %s", d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addStatefulSet(obj interface{}) {
	d := obj.(*appsv1.StatefulSet)
	logging.Get().Debug().Msgf("add StatefulSet %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateStatefulSet(oldObj, newObject interface{}) {
	oldR := oldObj.(*appsv1.StatefulSet)
	newR := newObject.(*appsv1.StatefulSet)
	if newR.Generation != oldR.Generation {
		logging.Get().Debug().Msgf("update StatefulSet %s", oldR.Name)
		ac.enqueue(newR, pkgassets.ActionUpdate)
	}
}

func (ac *Controller) deleteStatefulSet(obj interface{}) {
	d := obj.(*appsv1.StatefulSet)
	logging.Get().Debug().Msgf("delete StatefulSet %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addJob(obj interface{}) {
	d := obj.(*batchv1.Job)
	logging.Get().Debug().Msgf("add Job %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateJob(oldObj, newObject interface{}) {
	oldR := oldObj.(*batchv1.Job)
	newR := newObject.(*batchv1.Job)
	logging.Get().Debug().Msgf("update Job %s", oldR.Name)
	if newR.OwnerReferences != nil && len(newR.OwnerReferences) != 0 { // 表示该job为其他资源(如cronjob)派生
		return
	}
	ac.enqueue(newR, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteJob(obj interface{}) {
	d := obj.(*batchv1.Job)
	logging.Get().Debug().Msgf("delete Job %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addCronJob(obj interface{}) {
	meta, err := meta.Accessor(obj)
	if err != nil {
		logging.Get().Error().Msg("invalid CronJob object")
		return
	}
	logging.Get().Debug().Msgf("add CronJob V1 %s/%s", meta.GetNamespace(), meta.GetName())
	ac.enqueue(obj, pkgassets.ActionAdd)
}

func (ac *Controller) updateCronJob(oldObj, newObject interface{}) {
	meta, err := meta.Accessor(oldObj)
	if err != nil {
		logging.Get().Error().Msg("invalid CronJob object")
		return
	}
	logging.Get().Debug().Msgf("update CronJob %s/%s", meta.GetNamespace(), meta.GetName())
	ac.enqueue(newObject, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteCronJob(obj interface{}) {
	meta, err := meta.Accessor(obj)
	if err != nil {
		logging.Get().Error().Msg("invalid CronJob object")
		return
	}
	logging.Get().Debug().Msgf("delete CronJob %s/%s", meta.GetNamespace(), meta.GetName())
	ac.enqueue(obj, pkgassets.ActionDelete)
}

func (ac *Controller) addReplicationController(obj interface{}) {
	d := obj.(*corev1.ReplicationController)
	logging.Get().Debug().Msgf("add ReplicationController %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateReplicationController(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.ReplicationController)
	newR := newObject.(*corev1.ReplicationController)
	if newR.Generation != oldR.Generation {
		logging.Get().Debug().Msgf("update ReplicationController %s", oldR.Name)
		ac.enqueue(newR, pkgassets.ActionUpdate)
	}
}

func (ac *Controller) deleteReplicationController(obj interface{}) {
	d := obj.(*corev1.ReplicationController)
	logging.Get().Debug().Msgf("delete ReplicationController %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) addHoneySpot(obj interface{}) {
	d := obj.(*defensev1.Honeypot)
	logging.Get().Debug().Msgf("add HoneySpot %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateHoneySpot(oldObj, newObject interface{}) {
	oldD := oldObj.(*defensev1.Honeypot)
	newD := newObject.(*defensev1.Honeypot)
	logging.Get().Debug().Msgf("update HoneySpot %s", oldD.Name)
	ac.enqueue(newD, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteHoneySpot(obj interface{}) {
	d := obj.(*defensev1.Honeypot)
	logging.Get().Debug().Msgf("delete HoneySpot %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionDelete)
}

func (ac *Controller) enqueue(obj interface{}, action pkgassets.Action) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		logging.Get().Err(err).Msgf("couldn't get object key for object %#v", obj)
		return
	}
	ac.queue.Add(&Assets{
		Object: obj,
		Type:   reflect.TypeOf(obj),
		key:    key,
		Action: action,
	})
}

func (ac *Controller) worker() {
	logging.Get().Info().Msg("start worker")
	for ac.processNextItem() {
	}
}

func (ac *Controller) processNextItem() bool {
	key, quit := ac.queue.Get()
	if quit {
		return false
	}
	defer ac.queue.Done(key)

	as := key.(*Assets)
	var err error

	switch as.Object.(type) {
	case *appsv1.Deployment:
		err = ac.syncWorkLoad(as, pkgassets.KindDeployment, func(namespace, name string) (interface{}, error) {
			return ac.dpLister.Deployments(namespace).Get(name)
		})
	case *appsv1.DaemonSet:
		err = ac.syncWorkLoad(as, pkgassets.KindDaemonSet, func(namespace, name string) (interface{}, error) {
			return ac.dsLister.DaemonSets(namespace).Get(name)
		})
	case *appsv1.ReplicaSet:
		err = ac.syncWorkLoad(as, pkgassets.KindReplicaSet, func(namespace, name string) (interface{}, error) {
			return ac.rsLister.ReplicaSets(namespace).Get(name)
		})
	case *appsv1.StatefulSet:
		err = ac.syncWorkLoad(as, pkgassets.KindStatefulSet, func(namespace, name string) (interface{}, error) {
			return ac.ssLister.StatefulSets(namespace).Get(name)
		})
	case *corev1.ReplicationController:
		err = ac.syncWorkLoad(as, pkgassets.KindReplicationController, func(namespace, name string) (interface{}, error) {
			return ac.rcLister.ReplicationControllers(namespace).Get(name)
		})
	case *batchv1.Job:
		err = ac.syncWorkLoad(as, pkgassets.KindJob, func(namespace, name string) (interface{}, error) {
			return ac.jbLister.Jobs(namespace).Get(name)
		})
	case *v1beta1.CronJob:
		err = ac.syncWorkLoad(as, pkgassets.KindCronJob, func(namespace, name string) (interface{}, error) {
			return ac.cjbLister.CronJobs(namespace).Get(name)
		})
	case *batchv1.CronJob:
		err = ac.syncWorkLoad(as, pkgassets.KindCronJob, func(namespace, name string) (interface{}, error) {
			return ac.cjbv1Lister.CronJobs(namespace).Get(name)
		})
	case *corev1.Pod:
		err = ac.syncPod(as.key)
	case *rbacv1.Role:
		err = ac.syncRole(as.key)
	case *netv1.Ingress:
		err = ac.syncIngress(as.key)
	case *corev1.Service:
		err = ac.syncService(as.key)
	case *corev1.Endpoints:
		err = ac.syncEndpoints(as.key)
	case *corev1.Secret:
		err = ac.syncSecret(as.key)
	case *corev1.PersistentVolume:
		err = ac.syncPV(as.key)
	case *corev1.PersistentVolumeClaim:
		err = ac.syncPVC(as.key)
	case *rbacv1.ClusterRole:
		err = ac.syncClusterRole(as.key)
	case *corev1.Namespace:
		err = ac.syncNamespace(as.key)
	case *corev1.Node:
		err = ac.syncNode(as.key)
	case *defensev1.Honeypot:
		err = ac.syncHoneySpot(as.key)
	default:
		logging.Get().Error().Msgf("invalid resource type %v", as.Type)
	}
	ac.handleErr(err, key)
	return true
}

func (ac *Controller) syncPod(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	pod, err := ac.podLister.Pods(namespace).Get(name)
	var res *pkgassets.TensorPod
	action := pkgassets.ActionAdd
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			res = &pkgassets.TensorPod{
				Cluster: ac.clusterKey,
				Pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
				},
			}
		} else {
			return err
		}
	} else {
		//static pod as tensor resource
		if len(pod.OwnerReferences) == 0 || pod.OwnerReferences[0].Kind == "Node" {
			res := pkgassets.NewResourceFromPodNoOwnerOrStaticPod(ac.clusterKey, pod)
			ac.sendToMainClusterManager(ctx, pkgassets.ActionAdd, pkgassets.TensorResources2Watch, res, nil)
		}

		owner, _ := ac.getUpperOwnerOfPod(pod)
		if owner == nil || owner.Kind == "Node" {
			owner = &metav1.OwnerReference{
				Kind: "Pod",
				Name: pod.Name,
			}
		}

		res = &pkgassets.TensorPod{
			Cluster:  ac.clusterKey,
			Pod:      pod,
			Owner:    owner,
			PoolInfo: ac.poolInfo,
		}
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Pods2Watch, res, nil)
}

func (ac *Controller) syncRole(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.rlLister.Roles(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}

	role := pkgassets.TensorRole{
		Cluster: ac.clusterKey,
		Role:    r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Roles2Watch, &role, nil)
}

func (ac *Controller) syncIngress(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.ingNetV1Lister.Ingresses(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &netv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}
	//
	for i := 0; i < len(r.Spec.Rules); i++ {
		for j := 0; j < len(r.Spec.Rules[i].HTTP.Paths); j++ {
			if r.Spec.Rules[i].HTTP.Paths[j].Backend.Service == nil {
				continue
			}
			if r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Port.Number != 0 {
				continue
			}
			svc, err := ac.svcLister.Services(namespace).Get(r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Name)
			if err != nil && ac.svcSynced() == false { //未缓存完成
				logging.Get().Err(err).Msgf("get svc failed from cache ,reEnqueue. namespace:%s,name:%s", namespace, r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Name)
				ac.enqueue(r, pkgassets.ActionAdd)
				return nil
			} else if svc != nil {
				for _, port := range svc.Spec.Ports {
					if port.Name == r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Port.Name {
						r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Port.Number = port.Port
						logging.Get().Err(err).Msgf("get svc success from cache . namespace:%s,name:%s", namespace, r.Spec.Rules[i].HTTP.Paths[j].Backend.Service.Name)
						break
					}
				}
			}
		}
	}

	ingress := pkgassets.TensorIngress{
		Cluster: ac.clusterKey,
		Ingress: r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Ingress2Watch, &ingress, nil)
}

func (ac *Controller) syncService(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.svcLister.Services(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}
	res := pkgassets.TensorService{
		Cluster: ac.clusterKey,
		Service: r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Services2Watch, &res, nil)
}

func (ac *Controller) syncEndpoints(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.endLister.Endpoints(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}
	serviceName := ""
	if action != pkgassets.ActionDelete {
		_, err := ac.svcLister.Services(namespace).Get(name)
		if err == nil {
			serviceName = name
		}
	}
	endpointsTmp := &pkgassets.EndpointsTmp{
		Endpoints:   r,
		ServiceName: serviceName,
	}

	res := pkgassets.TensorEndpoints{
		Cluster:      ac.clusterKey,
		EndpointsTmp: endpointsTmp,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Endpoints2Watch, &res, nil)
}

func (ac *Controller) syncSecret(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}

	res := pkgassets.TensorSecret{
		Cluster: ac.clusterKey,
		Secret:  r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Secrets2Watch, &res, nil)
}

func (ac *Controller) syncPV(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(name) == 0 {
		err := fmt.Errorf("empty  name from key: %s", key)
		logging.Get().Err(err).Msg("empty  name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.pvLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}

	res := pkgassets.TensorPV{
		Cluster:          ac.clusterKey,
		PersistentVolume: r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.PVs2Watch, &res, nil)
}

func (ac *Controller) syncPVC(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.pvcLister.PersistentVolumeClaims(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}
		} else {
			return err
		}
	}

	res := pkgassets.TensorPVC{
		Cluster:               ac.clusterKey,
		PersistentVolumeClaim: r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.PVCs2Watch, &res, nil)
}

func (ac *Controller) syncClusterRole(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", name)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	r, err := ac.crlLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			r = &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
		} else {
			return err
		}
	}

	role := pkgassets.TensorClusterRole{
		Cluster:     ac.clusterKey,
		ClusterRole: r,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.ClusterRoles2Watch, &role, nil)
}

func (ac *Controller) syncNamespace(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	ns, err := ac.nsLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			ns = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
		} else {
			return err
		}
	}
	res := pkgassets.TensorNamespace{
		Cluster:   ac.clusterKey,
		Namespace: ns,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Namespaces2Watch, &res, nil)
}

func (ac *Controller) syncNode(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	node, err := ac.nodeLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			node = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
		} else {
			return err
		}
	}
	n := &pkgassets.TensorNode{
		Cluster: ac.clusterKey,
		Node:    node,
	}
	n.TailorSelf()
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Nodes2Watch, n, nil)
}

func (ac *Controller) syncHoneySpot(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s", key)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	action := pkgassets.ActionAdd
	hp, err := ac.hpLister.Honeypots(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			hp = &defensev1.Honeypot{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}
		} else {
			return err
		}
	}
	n := &pkgassets.TensorHoneySpot{
		Cluster:  ac.clusterKey,
		Honeypot: hp,
	}
	return ac.sendToMainClusterManager(ctx, action, pkgassets.Honeyspots2Watch, n, nil)
}

func (ac *Controller) syncWorkLoad(asset *Assets, kind pkgassets.ResourceKind, f func(namespace, name string) (interface{}, error)) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(asset.key)
	if err != nil {
		return err
	}
	if len(namespace) == 0 || len(name) == 0 {
		err := fmt.Errorf("empty namespace or name from key: %s, kind: %s", asset.key, kind)
		logging.Get().Err(err).Msg("empty namespace or name")
		return err
	}
	var res *pkgassets.TensorResource
	action := asset.Action
	wl, err := f(namespace, name)
	if err != nil {
		if errors.IsNotFound(err) {
			action = pkgassets.ActionDelete
			res = &pkgassets.TensorResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Cluster: ac.clusterKey,
				Kind:    kind,
			}
		} else {
			return err
		}
	} else {
		res = pkgassets.TensorResourceFuncs[kind](ac.clusterKey, wl)
	}

	if res == nil {
		logging.Get().Error().Msgf("resource: %s is nil", asset.key)
		return err
	}

	bYaml, err := sigYaml.Marshal(pkgassets.PureObject(asset.Object))
	if err != nil {
		logging.Get().Error().Err(err).Str("asset", asset.key).Msgf("object marshal to yaml fails")
		return err
	}

	return ac.sendToMainClusterManager(context.Background(), action, pkgassets.TensorResources2Watch, res, bYaml)
}

func (ac *Controller) sendToMainClusterManager(ctx context.Context, action pkgassets.Action, watchedType pkgassets.WatchedType, obj pkgassets.IdentifiableItem, yamlData []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := ac.sendToMq(ctx, action, watchedType, obj, yamlData)

	if err == nil {
		if action != pkgassets.ActionDelete {
			ac.dupCache.Put(obj)
		} else {
			ac.dupCache.Remove(obj)
		}
	}
	return err
}

func (ac *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		ac.queue.Forget(key)
		return
	}
	if ac.queue.NumRequeues(key) < 10 {
		logging.Get().Err(err).Msg("Error syncing deployment")
		ac.queue.AddRateLimited(key)
		return
	}
	logging.Get().Info().Msgf("Dropping deployment %q out of queue %v", key, err)
	ac.queue.Forget(key)
}

func (ac *Controller) getUpperOwnerOfPod(pod *corev1.Pod) (*metav1.OwnerReference, bool) {
	if pod == nil {
		return nil, false
	}
	owner := metav1.GetControllerOf(pod)
	if owner != nil && owner.Kind == "ReplicaSet" {
		rs, err := ac.rsLister.ReplicaSets(pod.Namespace).Get(owner.Name)
		if err != nil {
			return nil, false
		}
		ownerOfOwner := metav1.GetControllerOf(rs)
		if ownerOfOwner != nil {
			owner = ownerOfOwner
		}
	}
	return owner, owner != nil
}

func (ac *Controller) sendToMq(ctx context.Context, action pkgassets.Action, watchedType pkgassets.WatchedType, obj interface{}, yamlData []byte) error {
	event := &pkgassets.ResourceEvent{
		ClusterKey: ac.clusterKey,
		Action:     action,
		Type:       watchedType,
		Resource:   obj,
		YamlData:   yamlData,
	}
	msg, err := json.Marshal(event)
	if err != nil {
		return err
	}
	key := ac.clusterKey
	if obj != nil {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			logging.Get().Err(err).Msg("meta accessor err")
			return err
		}
		key = fmt.Sprintf("%s/%s/%s/%s", ac.clusterKey, watchedType, accessor.GetNamespace(), accessor.GetName())
	}

	err = ac.mqWriter.Write(ctx, ac.topic, kafka.Message{
		Key:   []byte(key),
		Value: msg,
	})
	if err != nil {
		logging.Get().Err(err).Msgf("sent resource to mq error. resource: %+v.", obj)
	}
	return err
}

func (ac *Controller) notifySync() {
	logging.Get().Info().Msg("synced,notify for syncing")
	err := wait.PollImmediateUntil(3*time.Second, func() (bool, error) {
		err1 := ac.sendToMq(context.Background(), pkgassets.ActionSync, pkgassets.AssetsSync, nil, nil)
		if err1 != nil {
			logging.Get().Err(err1).Msg("sending AssetsSync err, will try again")
			return false, nil
		}
		return true, nil
	}, wait.NeverStop)
	if err != nil {
		logging.Get().Error().Msg("poll sending msg to mq err")
		return
	}
	logging.Get().Info().Msgf("send cluster synced,clusterKey:%s", ac.clusterKey)
}

func (ac *Controller) addSvc(obj interface{}) {
	d := obj.(*corev1.Service)
	logging.Get().Debug().Msgf("add svc  %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateSvc(oldObj, newObj interface{}) {
	oldS := oldObj.(*corev1.Service)
	newS := newObj.(*corev1.Service)
	logging.Get().Debug().Msgf("update svc %s", oldS.Name)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteSvc(obj interface{}) {
	svc := obj.(*corev1.Service)
	logging.Get().Debug().Msgf("delete svc %s/%s", svc.Namespace, svc.Name)
	ac.enqueue(svc, pkgassets.ActionDelete)
}

func (ac *Controller) addIngress(obj interface{}) {
	d := obj.(*netv1.Ingress)
	logging.Get().Debug().Msgf("add ingress  %s/%s", d.Namespace, d.Name)
	ac.enqueue(d, pkgassets.ActionAdd)
}

func (ac *Controller) updateIngress(oldObj, newObj interface{}) {
	oldS := oldObj.(*netv1.Ingress)
	newS := newObj.(*netv1.Ingress)
	logging.Get().Debug().Msgf("update ingress %s", oldS.Name)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteIngress(obj interface{}) {
	svc := obj.(*netv1.Ingress)
	logging.Get().Debug().Msgf("delete ingress %s/%s", svc.Namespace, svc.Name)
	ac.enqueue(svc, pkgassets.ActionDelete)
}

func (ac *Controller) addEndpoints(obj interface{}) {
	tmp := obj.(*corev1.Endpoints)
	logging.Get().Debug().Msgf("add endpoints  %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionAdd)
}

func (ac *Controller) updateEndpoints(oldObj, newObj interface{}) {
	oldS := oldObj.(*corev1.Endpoints)
	newS := newObj.(*corev1.Endpoints)
	logging.Get().Debug().Msgf("update endpoints %s", oldS.Name)
	tmp := &pkgassets.EndpointsTmp{
		Endpoints: newS,
	}
	// 添加去重校验:  部分 endpoints 无效的update太频繁
	if ac.dupCache.Check(tmp) {
		logging.Get().Debug().Msgf("skip unnecessary endpoints update event:%s", oldS.Name)
		return
	}
	ac.dupCache.Put(tmp)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteEndpoints(obj interface{}) {
	tmp := obj.(*corev1.Endpoints)
	logging.Get().Debug().Msgf("delete endpoints %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionDelete)
}

func (ac *Controller) addSecret(obj interface{}) {
	tmp := obj.(*corev1.Secret)
	logging.Get().Debug().Msgf("add secret  %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionAdd)
}

func (ac *Controller) updateSecret(oldObj, newObj interface{}) {
	oldS := oldObj.(*corev1.Secret)
	newS := newObj.(*corev1.Secret)
	logging.Get().Debug().Msgf("update secret %s", oldS.Name)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deleteSecret(obj interface{}) {
	tmp := obj.(*corev1.Secret)
	logging.Get().Debug().Msgf("delete secret %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionDelete)
}

func (ac *Controller) addPV(obj interface{}) {
	tmp := obj.(*corev1.PersistentVolume)
	logging.Get().Debug().Msgf("add pv  %s", tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionAdd)
}

func (ac *Controller) updatePV(oldObj, newObj interface{}) {
	oldS := oldObj.(*corev1.PersistentVolume)
	newS := newObj.(*corev1.PersistentVolume)
	logging.Get().Debug().Msgf("update pv %s", oldS.Name)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deletePV(obj interface{}) {
	tmp := obj.(*corev1.PersistentVolume)
	logging.Get().Debug().Msgf("delete pv %s", tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionDelete)
}

func (ac *Controller) addPVC(obj interface{}) {
	tmp := obj.(*corev1.PersistentVolumeClaim)
	logging.Get().Debug().Msgf("add pvc  %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionAdd)
}

func (ac *Controller) updatePVC(oldObj, newObj interface{}) {
	oldS := oldObj.(*corev1.PersistentVolumeClaim)
	newS := newObj.(*corev1.PersistentVolumeClaim)
	logging.Get().Debug().Msgf("update pvc %s", oldS.Name)
	ac.enqueue(newS, pkgassets.ActionUpdate)
}

func (ac *Controller) deletePVC(obj interface{}) {
	tmp := obj.(*corev1.PersistentVolumeClaim)
	logging.Get().Debug().Msgf("delete pvc %s/%s", tmp.Namespace, tmp.Name)
	ac.enqueue(tmp, pkgassets.ActionDelete)
}
