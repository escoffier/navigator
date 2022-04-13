package assets

import (
	"context"
	"encoding/json"
	"fmt"
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
	"reflect"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
	defenselisters "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/defense/v1"
	"time"
)

var (
	DeploymentType        = reflect.TypeOf(&appsv1.Deployment{})
	DaemonSetType         = reflect.TypeOf(&appsv1.DaemonSet{})
	PodType               = reflect.TypeOf(&corev1.Pod{})
	ReplicaSetType        = reflect.TypeOf(&appsv1.ReplicaSet{})
	JobType               = reflect.TypeOf(&batchv1.Job{})
	CronJobType           = reflect.TypeOf(&v1beta1.CronJob{})
	ReplicaControllerType = reflect.TypeOf(&corev1.ReplicationController{})
	StatefulSetType       = reflect.TypeOf(&appsv1.StatefulSet{})
	RoleType              = reflect.TypeOf(&rbacv1.Role{})
	ClusterRoleType       = reflect.TypeOf(&rbacv1.ClusterRole{})
	NamespaceType         = reflect.TypeOf(&corev1.Namespace{})
	NodeType              = reflect.TypeOf(&corev1.Node{})
	HoneySportType        = reflect.TypeOf(&defensev1.Honeypot{})
)

type Controller struct {
	podLister  corelisters.PodLister
	dpLister   applisters.DeploymentLister
	dsLister   applisters.DaemonSetLister
	jbLister   batchv1lister.JobLister
	cjbLister  v1beta1lister.CronJobLister
	rcLister   corelisters.ReplicationControllerLister
	ssLister   applisters.StatefulSetLister
	rsLister   applisters.ReplicaSetLister
	rlLister   rbaclisters.RoleLister
	crlLister  rbaclisters.ClusterRoleLister
	nsLister   corelisters.NamespaceLister
	nodeLister corelisters.NodeLister
	hpLister   defenselisters.HoneypotLister
	podSynced  cache.InformerSynced
	dsSynced   cache.InformerSynced
	dpSynced   cache.InformerSynced
	jbSynced   cache.InformerSynced
	cjbSynced  cache.InformerSynced
	rcSynced   cache.InformerSynced
	ssSynced   cache.InformerSynced
	rsSynced   cache.InformerSynced
	rlSynced   cache.InformerSynced
	crlSynced  cache.InformerSynced
	nsSynced   cache.InformerSynced
	nodeSynced cache.InformerSynced
	hpSynced   cache.InformerSynced
	queue      workqueue.RateLimitingInterface
	clusterKey string
	mqWriter   mq.MQWriter
	topic      string
}

type Assets struct {
	Type reflect.Type
	key  string
}

func NewAssetsController(factory informers.SharedInformerFactory, tensorFactory externalversions.SharedInformerFactory, writer mq.MQWriter, clusterKey, topic string) *Controller {
	ac := &Controller{
		podLister:  factory.Core().V1().Pods().Lister(),
		dpLister:   factory.Apps().V1().Deployments().Lister(),
		dsLister:   factory.Apps().V1().DaemonSets().Lister(),
		rsLister:   factory.Apps().V1().ReplicaSets().Lister(),
		ssLister:   factory.Apps().V1().StatefulSets().Lister(),
		rlLister:   factory.Rbac().V1().Roles().Lister(),
		crlLister:  factory.Rbac().V1().ClusterRoles().Lister(),
		nsLister:   factory.Core().V1().Namespaces().Lister(),
		nodeLister: factory.Core().V1().Nodes().Lister(),
		rcLister:   factory.Core().V1().ReplicationControllers().Lister(),
		jbLister:   factory.Batch().V1().Jobs().Lister(),
		cjbLister:  factory.Batch().V1beta1().CronJobs().Lister(),
		hpLister:   tensorFactory.Defense().V1().Honeypots().Lister(),
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "assets"),
		clusterKey: clusterKey,
		mqWriter:   writer,
		topic:      topic,
	}
	tensorFactory.Defense().V1().Honeypots().Lister()
	// Pods
	factory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addPod,
		UpdateFunc: ac.updatePod,
		DeleteFunc: ac.deletePod,
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

	//ReplicaSets
	factory.Apps().V1().ReplicaSets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addReplicaSet,
		UpdateFunc: ac.updateReplicaSet,
		DeleteFunc: ac.deleteReplicaSet,
	})
	ac.rsSynced = factory.Apps().V1().ReplicaSets().Informer().HasSynced

	//Roles
	factory.Rbac().V1().Roles().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addRole,
		UpdateFunc: ac.updateRole,
		DeleteFunc: ac.deleteRole,
	})
	ac.rlSynced = factory.Rbac().V1().Roles().Informer().HasSynced

	//ClusterRoles
	factory.Rbac().V1().ClusterRoles().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addClusterRole,
		UpdateFunc: ac.updateClusterRole,
		DeleteFunc: ac.deleteClusterRole,
	})
	ac.crlSynced = factory.Rbac().V1().ClusterRoles().Informer().HasSynced

	//Namespaces
	factory.Core().V1().Namespaces().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addNamespace,
		UpdateFunc: ac.updateNamespace,
		DeleteFunc: ac.deleteNamespace,
	})
	ac.nsSynced = factory.Core().V1().Namespaces().Informer().HasSynced

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

	// CronJobs
	factory.Batch().V1beta1().CronJobs().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ac.addCronJob,
		UpdateFunc: ac.updateCronJob,
		DeleteFunc: ac.deleteCronJob,
	})
	ac.cjbSynced = factory.Batch().V1beta1().CronJobs().Informer().HasSynced

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

	return ac
}

func (ac *Controller) Run(stopChan <-chan struct{}) {
	defer ac.queue.ShutDown()

	if !cache.WaitForNamedCacheSync("assetsController", stopChan, ac.dpSynced, ac.dsSynced, ac.podSynced, ac.rsSynced,
		ac.rlSynced, ac.crlSynced, ac.nsSynced, ac.nodeSynced, ac.jbSynced, ac.cjbSynced, ac.rcSynced, ac.ssSynced, ac.hpSynced) {
		return
	}
	ac.notifySync()
	wait.Until(ac.worker, time.Second, stopChan)
	<-stopChan
}

func (ac *Controller) addDeployment(obj interface{}) {
	d := obj.(*appsv1.Deployment)
	logging.Get().Info().Msgf("add deployment %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateDeployment(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.Deployment)
	newD := newObject.(*appsv1.Deployment)
	logging.Get().Info().Msgf("update deployment %s", oldD.Name)
	ac.enqueue(newD)
}

func (ac *Controller) deleteDeployment(obj interface{}) {
	d := obj.(*appsv1.Deployment)
	logging.Get().Info().Msgf("delete deployment %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addDaemonSet(obj interface{}) {
	d := obj.(*appsv1.DaemonSet)
	logging.Get().Info().Msgf("add daemonset %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateDaemonSet(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.DaemonSet)
	newD := newObject.(*appsv1.DaemonSet)
	logging.Get().Info().Msgf("update daemonset %s", oldD.Name)
	ac.enqueue(newD)
}

func (ac *Controller) deleteDaemonSet(obj interface{}) {
	d := obj.(*appsv1.DaemonSet)
	logging.Get().Info().Msgf("delete daemonset %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addReplicaSet(obj interface{}) {
	d := obj.(*appsv1.ReplicaSet)
	logging.Get().Info().Msgf("add replica set %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateReplicaSet(oldObj, newObject interface{}) {
	oldD := oldObj.(*appsv1.ReplicaSet)
	newD := newObject.(*appsv1.ReplicaSet)
	logging.Get().Info().Msgf("update replica set %s", oldD.Name)
	ac.enqueue(newD)
}

func (ac *Controller) deleteReplicaSet(obj interface{}) {
	d := obj.(*appsv1.ReplicaSet)
	logging.Get().Info().Msgf("delete replica set %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addPod(obj interface{}) {
	d := obj.(*corev1.Pod)
	logging.Get().Info().Msgf("add pod %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updatePod(oldObj, newObject interface{}) {
	oldD := oldObj.(*corev1.Pod)
	newD := newObject.(*corev1.Pod)
	logging.Get().Info().Msgf("update pod %s", oldD.Name)
	ac.enqueue(newD)
}

func (ac *Controller) deletePod(obj interface{}) {
	d := obj.(*corev1.Pod)
	logging.Get().Info().Msgf("delete pod %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addRole(obj interface{}) {
	d := obj.(*rbacv1.Role)
	logging.Get().Info().Msgf("add role %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateRole(oldObj, newObject interface{}) {
	oldR := oldObj.(*rbacv1.Role)
	newR := newObject.(*rbacv1.Role)
	logging.Get().Info().Msgf("update role %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteRole(obj interface{}) {
	d := obj.(*rbacv1.Role)
	logging.Get().Info().Msgf("delete role %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addClusterRole(obj interface{}) {
	d := obj.(*rbacv1.ClusterRole)
	logging.Get().Info().Msgf("add cluster role %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateClusterRole(oldObj, newObject interface{}) {
	oldR := oldObj.(*rbacv1.ClusterRole)
	newR := newObject.(*rbacv1.ClusterRole)
	logging.Get().Info().Msgf("update cluster role %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteClusterRole(obj interface{}) {
	d := obj.(*rbacv1.ClusterRole)
	logging.Get().Info().Msgf("delete cluster role %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addNamespace(obj interface{}) {
	d := obj.(*corev1.Namespace)
	logging.Get().Info().Msgf("add namespace %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateNamespace(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.Namespace)
	newR := newObject.(*corev1.Namespace)
	logging.Get().Info().Msgf("update namespace %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteNamespace(obj interface{}) {
	d := obj.(*corev1.Namespace)
	logging.Get().Info().Msgf("delete namespace %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addNode(obj interface{}) {
	d := obj.(*corev1.Node)
	logging.Get().Info().Msgf("add node %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateNode(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.Node)
	newR := newObject.(*corev1.Node)
	logging.Get().Info().Msgf("update node %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteNode(obj interface{}) {
	d := obj.(*corev1.Node)
	logging.Get().Info().Msgf("delete node %s", d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addStatefulSet(obj interface{}) {
	d := obj.(*appsv1.StatefulSet)
	logging.Get().Info().Msgf("add StatefulSet %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateStatefulSet(oldObj, newObject interface{}) {
	oldR := oldObj.(*appsv1.StatefulSet)
	newR := newObject.(*appsv1.StatefulSet)
	logging.Get().Info().Msgf("update StatefulSet %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteStatefulSet(obj interface{}) {
	d := obj.(*appsv1.StatefulSet)
	logging.Get().Info().Msgf("delete StatefulSet %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addJob(obj interface{}) {
	d := obj.(*batchv1.Job)
	logging.Get().Info().Msgf("add Job %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateJob(oldObj, newObject interface{}) {
	oldR := oldObj.(*batchv1.Job)
	newR := newObject.(*batchv1.Job)
	logging.Get().Info().Msgf("update Job %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteJob(obj interface{}) {
	d := obj.(*batchv1.Job)
	logging.Get().Info().Msgf("delete Job %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addCronJob(obj interface{}) {
	d := obj.(*v1beta1.CronJob)
	logging.Get().Info().Msgf("add CronJob %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateCronJob(oldObj, newObject interface{}) {
	oldR := oldObj.(*v1beta1.CronJob)
	newR := newObject.(*v1beta1.CronJob)
	logging.Get().Info().Msgf("update CronJob %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteCronJob(obj interface{}) {
	d := obj.(*v1beta1.CronJob)
	logging.Get().Info().Msgf("delete CronJob %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addReplicationController(obj interface{}) {
	d := obj.(*corev1.ReplicationController)
	logging.Get().Info().Msgf("add ReplicationController %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateReplicationController(oldObj, newObject interface{}) {
	oldR := oldObj.(*corev1.ReplicationController)
	newR := newObject.(*corev1.ReplicationController)
	logging.Get().Info().Msgf("update ReplicationController %s", oldR.Name)
	ac.enqueue(newR)
}

func (ac *Controller) deleteReplicationController(obj interface{}) {
	d := obj.(*corev1.ReplicationController)
	logging.Get().Info().Msgf("delete ReplicationController %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) addHoneySpot(obj interface{}) {
	d := obj.(*defensev1.Honeypot)
	logging.Get().Info().Msgf("add HoneySpot %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) updateHoneySpot(oldObj, newObject interface{}) {
	oldD := oldObj.(*defensev1.Honeypot)
	newD := newObject.(*defensev1.Honeypot)
	logging.Get().Info().Msgf("update HoneySpot %s", oldD.Name)
	ac.enqueue(newD)
}

func (ac *Controller) deleteHoneySpot(obj interface{}) {
	d := obj.(*defensev1.Honeypot)
	logging.Get().Info().Msgf("delete HoneySpot %s/%s", d.Namespace, d.Name)
	ac.enqueue(d)
}

func (ac *Controller) enqueue(obj interface{}) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		logging.Get().Err(err).Msgf("couldn't get object key for object %#v", obj)
		return
	}
	ac.queue.Add(&Assets{
		Type: reflect.TypeOf(obj),
		key:  key,
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

	switch as.Type {
	case DeploymentType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindDeployment, func(namespace, name string) (interface{}, error) {
			return ac.dpLister.Deployments(namespace).Get(name)
		})
	case DaemonSetType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindDaemonSet, func(namespace, name string) (interface{}, error) {
			return ac.dsLister.DaemonSets(namespace).Get(name)
		})
	case ReplicaSetType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindReplicaSet, func(namespace, name string) (interface{}, error) {
			return ac.rsLister.ReplicaSets(namespace).Get(name)
		})
	case StatefulSetType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindStatefulSet, func(namespace, name string) (interface{}, error) {
			return ac.ssLister.StatefulSets(namespace).Get(name)
		})
	case ReplicaControllerType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindReplicationController, func(namespace, name string) (interface{}, error) {
			return ac.rcLister.ReplicationControllers(namespace).Get(name)
		})
	case JobType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindJob, func(namespace, name string) (interface{}, error) {
			return ac.jbLister.Jobs(namespace).Get(name)
		})
	case CronJobType:
		err = ac.syncWorkLoad(as.key, pkgassets.KindCronJob, func(namespace, name string) (interface{}, error) {
			return ac.cjbLister.CronJobs(namespace).Get(name)
		})
	case PodType:
		err = ac.syncPod(as.key)
	case RoleType:
		err = ac.syncRole(as.key)
	case ClusterRoleType:
		err = ac.syncClusterRole(as.key)
	case NamespaceType:
		err = ac.syncNamespace(as.key)
	case NodeType:
		err = ac.syncNode(as.key)
	case HoneySportType:
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

	logging.Get().Info().Msgf("syncing pod %s", key)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
			return ac.SendToMq(ctx, pkgassets.ActionAdd, pkgassets.TensorResources2Watch, res)
		}

		owner, _ := ac.getUpperOwnerOfPod(pod)
		if owner == nil {
			owner = &metav1.OwnerReference{
				Kind: "NO_OWNER",
				Name: "NO_OWNER",
			}
		}

		res = &pkgassets.TensorPod{
			Cluster: ac.clusterKey,
			Pod:     pod,
			Owner:   owner,
		}
	}
	return ac.SendToMq(ctx, action, pkgassets.Pods2Watch, res)
}

func (ac *Controller) syncRole(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logging.Get().Debug().Msgf("syncing role %s", key)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
	return ac.SendToMq(ctx, action, pkgassets.Roles2Watch, role)
}

func (ac *Controller) syncClusterRole(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logging.Get().Debug().Msgf("syncing ClusterRole %s", key)
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
	return ac.SendToMq(ctx, action, pkgassets.ClusterRoles2Watch, role)
}

func (ac *Controller) syncNamespace(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logging.Get().Info().Msgf("syncing namespace %s", key)
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
	return ac.SendToMq(ctx, action, pkgassets.Namespaces2Watch, res)
}

func (ac *Controller) syncNode(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logging.Get().Debug().Msgf("syncing node %s", key)
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
	n := pkgassets.TensorNode{
		Cluster: ac.clusterKey,
		Node:    node,
	}
	return ac.SendToMq(ctx, action, pkgassets.Nodes2Watch, n)
}

func (ac *Controller) syncHoneySpot(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logging.Get().Debug().Msgf("syncing honeyspot %s", key)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
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
	n := pkgassets.TensorHoneySpot{
		Cluster:  ac.clusterKey,
		Honeypot: hp,
	}
	return ac.SendToMq(ctx, action, pkgassets.Honeyspots2Watch, n)
}

func (ac *Controller) syncWorkLoad(key string, kind pkgassets.ResourceKind, f func(namespace, name string) (interface{}, error)) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	var res *pkgassets.TensorResource
	action := pkgassets.ActionAdd
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
		logging.Get().Error().Msgf("resource: %s is nil", key)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ac.SendToMq(ctx, action, pkgassets.TensorResources2Watch, res)
}

func (ac *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		ac.queue.Forget(key)
		return
	}
	if ac.queue.NumRequeues(key) < 10 {
		logging.Get().Info().Msgf("Error syncing deployment %v", err)
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

func (ac *Controller) SendToMq(ctx context.Context, action pkgassets.AssetsAction, watchedType pkgassets.WatchedType, obj interface{}) error {
	event := &pkgassets.ResourceEvent{
		ClusterKey: ac.clusterKey,
		Action:     action,
		Type:       watchedType,
		Resource:   obj,
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
	logging.Get().Debug().Msgf("sent resource %s to mq successfully", key)
	if err != nil {
		logging.Get().Err(err).Msgf("sent resource to mq error. resource: %+v.", obj)
	}
	return err
}

func (ac *Controller) notifySync() {
	logging.Get().Info().Msg("notify for syncing")
	err := wait.PollImmediateUntil(3*time.Second, func() (bool, error) {
		err1 := ac.SendToMq(context.Background(), pkgassets.ActionSync, pkgassets.AssetsSync, nil)
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
}
