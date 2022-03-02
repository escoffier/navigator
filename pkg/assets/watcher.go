package assets

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
)

const (
	defaultStartWatchTimeout = 10 * time.Second
	resyncInterval           = 24 * time.Hour
)

type AssetsAction uint8
type WatchedType string

const (
	ActionAdd AssetsAction = iota
	ActionDelete
	ActionUpdate

	Endpoints2Watch           WatchedType = "endpoints"
	Services2Watch            WatchedType = "services"
	Pods2Watch                WatchedType = "pods"
	Namespaces2Watch          WatchedType = "namespaces"
	ReplicaSets2Watch         WatchedType = "replicasets"
	Roles2Watch               WatchedType = "roles"
	ClusterRoles2Watch        WatchedType = "clusterroles"
	RoleBindings2Watch        WatchedType = "rolebindings"
	ClusterRoleBindings2Watch WatchedType = "clusterrolebindings"
	ServiceAccounts2Watch     WatchedType = "serviceaccounts"
	TensorResources2Watch     WatchedType = "tensorresources"
	Nodes2Watch               WatchedType = "nodes"
)

type AssetsCallback interface {
	// called before watch events
	BeforWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) ClusterCallback

	WatchedTypes() map[WatchedType]struct{}
	Name() string
}

type ClusterCallback interface {
	OnPodEvent(newPod, oldPod *corev1.Pod, action AssetsAction) error
	OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action AssetsAction) error
	OnServiceEvent(newSvc, oldEvc *corev1.Service, action AssetsAction) error
	OnRoleEvent(newRole, oldRole *rbacv1.Role, action AssetsAction) error
	OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action AssetsAction) error
	OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action AssetsAction) error
	OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action AssetsAction) error
	OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action AssetsAction) error
	OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action AssetsAction) error
	OnTensorResourceEvent(newResource, oldResource *TensorResource, action AssetsAction) error
	OnNodeEvent(newNode, oldNode *corev1.Node, action AssetsAction) error
	AfterDataSynced(ctx context.Context, dataSynced bool)
	OnHoneyspot(newHoneyspot, oldHoneyspot *defensev1.Honeypot, action AssetsAction) error
	Name() string
}

type Watcher struct {
	callbacks         []AssetsCallback
	honeyspotCallback AssetsCallback
	clusterChans      map[string]chan struct{}
	sync.RWMutex
}

func (w *Watcher) AddCallback(cb AssetsCallback) {
	w.callbacks = append(w.callbacks, cb)
}

func (w *Watcher) getClusterStopChan(clusterName string) (chan struct{}, bool) {
	w.RLock()
	defer w.RUnlock()

	ch, exist := w.clusterChans[clusterName]
	return ch, exist
}

func (w *Watcher) putClusterStopChan(clusterName string, ch chan struct{}) {
	w.Lock()
	defer w.Unlock()

	w.clusterChans[clusterName] = ch
}

func (w *Watcher) StopWatch(ctx context.Context, clusters []string) error {
	for _, cluster := range clusters {
		stopChan, exist := w.getClusterStopChan(cluster)
		if exist && stopChan != nil {
			close(stopChan)
		}
		w.Lock()
		delete(w.clusterChans, cluster)
		w.Unlock()
	}
	return nil
}

type informerStatus struct {
	informer   *cache.SharedIndexInformer
	synced     bool
	targetType reflect.Type
}

type resourceEvent struct {
	newResource *TensorResource
	oldResource *TensorResource
	action      AssetsAction
}

type ResourceFactoryFunc func(cluster string, obj interface{}) (*TensorResource, error)

func getInformerFuncForResources(echan chan resourceEvent, cluster string, resFactory ResourceFactoryFunc) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(newObj interface{}) {
			if newObj == nil {
				logging.GetLogger().Error().Msg("nil obj")
				return
			}
			res, err := resFactory(cluster, newObj)
			if err == nil {
				e := resourceEvent{
					newResource: res,
					action:      ActionAdd,
				}
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case echan <- e:
				case <-timer.C:
					logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. data: %+v. action: add", res)
				}
			} else {
				logging.GetLogger().Warn().Msgf("err new resource from obj: %v. data: %+v", err, newObj)
			}
		},
		DeleteFunc: func(oldObj interface{}) {
			if oldObj == nil {
				logging.GetLogger().Error().Msg("nil obj")
			}
			res, err := resFactory(cluster, oldObj)
			if err == nil {
				e := resourceEvent{
					oldResource: res,
					action:      ActionDelete,
				}
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case echan <- e:
				case <-timer.C:
					logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. data: %+v. action: delete", res)
				}
			} else {
				logging.GetLogger().Warn().Msgf("err new resource from obj: %v. data: %+v", err, oldObj)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if oldObj == nil || newObj == nil {
				logging.GetLogger().Error().Msg("nil obj")
			}
			oldRes, oerr := resFactory(cluster, oldObj)
			newRes, nerr := resFactory(cluster, newObj)
			if oerr == nil && nerr == nil {
				e := resourceEvent{
					oldResource: oldRes,
					newResource: newRes,
					action:      ActionUpdate,
				}
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case echan <- e:
				case <-timer.C:
					logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. new data: %+v. old data: %+v action: update", newRes, oldRes)
				}
			} else {
				logging.GetLogger().Warn().Msgf("err new resource from obj: %v %v. data: %+v %+v", oerr, nerr, oldObj, newObj)
			}
		},
	}
}

func ShouldResourceBeFiltered(res *TensorResource) bool {
	switch res.Kind {
	case KindReplicaSet:
		if len(res.OwnerReferences) == 0 {
			return false
		}
		for _, or := range res.OwnerReferences {
			if or.Controller != nil && *or.Controller {
				if or.Kind == string(KindDeployment) {
					return true
				}
			}
		}
	case KindJob:
		if len(res.OwnerReferences) == 0 {
			return false
		}
		for _, or := range res.OwnerReferences {
			if or.Controller != nil && *or.Controller {
				if or.Kind == string(KindCronJob) {
					return true
				}
			}
		}
	}
	return false
}

func (w *Watcher) watchForCluster(ctx context.Context, clusterKey string, newClient *Clientset) {
	toWatchedTypes := make(map[WatchedType]struct{}, 4)
	callbacks := make([]ClusterCallback, len(w.callbacks))
	for i, cb := range w.callbacks {
		for t := range cb.WatchedTypes() {
			toWatchedTypes[t] = struct{}{}
		}
		callbacks[i] = cb.BeforWatchNewCluster(ctx, clusterKey, resyncInterval)
	}

	// whether to watch tensor resources; need pod informer.
	var tsResEventsChan chan resourceEvent
	_, toWatchResources := toWatchedTypes[TensorResources2Watch]
	if toWatchResources {
		tsResEventsChan = make(chan resourceEvent, 500)
	}

	informerFactory := informers.NewSharedInformerFactory(newClient, resyncInterval)
	defenseInforerFactory := externalversions.NewSharedInformerFactory(newClient.TensorClientset, resyncInterval)

	informerStatuses := make([]*informerStatus, 0, 5)

	if _, toWatch := toWatchedTypes[Endpoints2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching endpoints for cluster %s", clusterKey)
		// watch endpoints
		endPointsInformer := informerFactory.Core().V1().Endpoints().Informer()
		var ept *corev1.Endpoints
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &endPointsInformer,
			targetType: reflect.TypeOf(ept),
		})

		endPointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				ept, ok := newObj.(*corev1.Endpoints)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
					return
				}
				for _, cb := range callbacks {
					eptErr := cb.OnEndPointEvent(ept, nil, ActionAdd)
					if eptErr != nil {
						logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
					}
				}

			},
			DeleteFunc: func(newObj interface{}) {
				ept, ok := newObj.(*corev1.Endpoints)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
					return
				}
				for _, cb := range callbacks {
					eptErr := cb.OnEndPointEvent(nil, ept, ActionDelete)
					if eptErr != nil {
						logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newEpt, ok := newObj.(*corev1.Endpoints)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
					return
				}
				oldEpt, ok := oldObj.(*corev1.Endpoints)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
					return
				}
				for _, cb := range callbacks {
					eptErr := cb.OnEndPointEvent(newEpt, oldEpt, ActionUpdate)
					if eptErr != nil {
						logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if toWatchResources {
		logging.GetLogger().Info().Msgf("start watching resources for cluster %s", clusterKey)

		go func(clusterCallbacks []ClusterCallback, resChan chan resourceEvent) {
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("Panic for receiving resource events: %v. stack: %s", r, debug.Stack())
				}
			}()

			for event := range resChan {
				for _, cb := range clusterCallbacks {
					func(cback ClusterCallback) {
						defer func() {
							if r := recover(); r != nil {
								logging.GetLogger().Error().Msgf("Panic for callback: %v. stack: %s", r, debug.Stack())
							}
						}()

						evtErr := cback.OnTensorResourceEvent(event.newResource, event.oldResource, event.action)
						if evtErr != nil {
							logging.GetLogger().Err(evtErr).Msgf("Callback %s for resource events error. ", cback.Name())
						}
					}(cb)

				}
			}
		}(callbacks, tsResEventsChan)

		informerWatchTargets := func(clusterKey string, informer cache.SharedIndexInformer, targetType reflect.Type, resFactory ResourceFactoryFunc) {
			informerStatuses = append(informerStatuses, &informerStatus{
				synced:     false,
				informer:   &informer,
				targetType: targetType,
			})
			informer.AddEventHandler(getInformerFuncForResources(tsResEventsChan, clusterKey, resFactory))
		}
		// replicasets
		rsInformer := informerFactory.Apps().V1().ReplicaSets().Informer()
		var rs *appsv1.ReplicaSet
		informerWatchTargets(clusterKey, rsInformer, reflect.TypeOf(rs), func(clusterKey string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*appsv1.ReplicaSet)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromReplicaSet(clusterKey, rs), nil
		})

		// statefulsets
		ssInformer := informerFactory.Apps().V1().StatefulSets().Informer()
		var ss *appsv1.StatefulSet
		informerWatchTargets(clusterKey, ssInformer, reflect.TypeOf(ss), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*appsv1.StatefulSet)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromStatefulSet(cluster, rs), nil
		})

		// daemonsets
		dsInformer := informerFactory.Apps().V1().DaemonSets().Informer()
		var ds *appsv1.DaemonSet
		informerWatchTargets(clusterKey, dsInformer, reflect.TypeOf(ds), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*appsv1.DaemonSet)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromDaemonSet(cluster, rs), nil
		})

		// deployments
		dmInformer := informerFactory.Apps().V1().Deployments().Informer()
		var dm *appsv1.Deployment
		informerWatchTargets(clusterKey, dmInformer, reflect.TypeOf(dm), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*appsv1.Deployment)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromDeployment(cluster, rs), nil
		})

		// ReplicationControllers
		rcInformer := informerFactory.Core().V1().ReplicationControllers().Informer()
		var rc *corev1.ReplicationController
		informerWatchTargets(clusterKey, rcInformer, reflect.TypeOf(rc), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*corev1.ReplicationController)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromReplicationController(cluster, rs), nil
		})

		// jobs
		jobsInformer := informerFactory.Batch().V1().Jobs().Informer()
		var jb *batchv1.Job
		informerWatchTargets(clusterKey, jobsInformer, reflect.TypeOf(jb), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*batchv1.Job)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromJob(cluster, rs), nil
		})

		// cronjobs
		cjInformer := informerFactory.Batch().V1beta1().CronJobs().Informer()
		var cj *batchv1beta.CronJob
		informerWatchTargets(clusterKey, cjInformer, reflect.TypeOf(cj), func(cluster string, obj interface{}) (*TensorResource, error) {
			if obj == nil {
				return nil, errors.New("nil obj")
			}
			rs, ok := obj.(*batchv1beta.CronJob)
			if !ok {
				return nil, errors.New("cast error")
			}
			return newResourceFromCronJob(cluster, rs), nil
		})
	}

	if _, toWatch := toWatchedTypes[Namespaces2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching namespaces for cluster %s", clusterKey)
		nsInformer := informerFactory.Core().V1().Namespaces().Informer()
		var ns *corev1.Namespace
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &nsInformer,
			targetType: reflect.TypeOf(ns),
		})

		nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newNs, ok := newObj.(*corev1.Namespace)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnNamespaceEvent(newNs, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on service event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldNs, ok := oldObj.(*corev1.Namespace)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnNamespaceEvent(nil, oldNs, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on service event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newNs, ok := newObj.(*corev1.Namespace)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				oldNs, ok := oldObj.(*corev1.Namespace)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}

				for _, cb := range callbacks {
					eptErr := cb.OnNamespaceEvent(newNs, oldNs, ActionUpdate)
					if eptErr != nil {
						logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
					}
				}
			},
		})
	}
	if _, toWatch := toWatchedTypes[Services2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching services for cluster %s", clusterKey)
		servicesInformer := informerFactory.Core().V1().Services().Informer()
		var svc *corev1.Service
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &servicesInformer,
			targetType: reflect.TypeOf(svc),
		})

		servicesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newSvc, ok := newObj.(*corev1.Service)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnServiceEvent(newSvc, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on service event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldSvc, ok := oldObj.(*corev1.Service)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnServiceEvent(nil, oldSvc, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on service event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newSvc, ok := newObj.(*corev1.Service)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}
				oldSvc, ok := oldObj.(*corev1.Service)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Service")
					return
				}

				for _, cb := range callbacks {
					eptErr := cb.OnServiceEvent(newSvc, oldSvc, ActionUpdate)
					if eptErr != nil {
						logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if _, toWatch := toWatchedTypes[Roles2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching roles for cluster %s", clusterKey)
		rolesInformer := informerFactory.Rbac().V1().Roles().Informer()
		var role *rbacv1.Role
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &rolesInformer,
			targetType: reflect.TypeOf(role),
		})

		rolesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newRole, ok := newObj.(*rbacv1.Role)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.Role")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnRoleEvent(newRole, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on service event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldRole, ok := oldObj.(*rbacv1.Role)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *rbacv1.Role")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnRoleEvent(nil, oldRole, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on role    event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newRole, ok := newObj.(*rbacv1.Role)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.Role")
					return
				}
				oldRole, ok := oldObj.(*rbacv1.Role)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.Role")
					return
				}

				for _, cb := range callbacks {
					roleErr := cb.OnRoleEvent(newRole, oldRole, ActionUpdate)
					if roleErr != nil {
						logging.GetLogger().Err(roleErr).Msg(fmt.Sprintf("on role event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if _, toWatch := toWatchedTypes[ServiceAccounts2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching service accounts for cluster %s", clusterKey)
		saInformer := informerFactory.Core().V1().ServiceAccounts().Informer()
		var sa *corev1.ServiceAccount
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &saInformer,
			targetType: reflect.TypeOf(sa),
		})

	}
	if _, toWatch := toWatchedTypes[ClusterRoles2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching clusterroles for cluster %s", clusterKey)
		rolesInformer := informerFactory.Rbac().V1().ClusterRoles().Informer()
		var role *rbacv1.ClusterRole
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &rolesInformer,
			targetType: reflect.TypeOf(role),
		})

		rolesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newRole, ok := newObj.(*rbacv1.ClusterRole)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRole")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnClusterRoleEvent(newRole, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on clusterrole event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldRole, ok := oldObj.(*rbacv1.ClusterRole)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *rbacv1.ClusterRole")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnClusterRoleEvent(nil, oldRole, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on cluterrole event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newRole, ok := newObj.(*rbacv1.ClusterRole)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRole")
					return
				}
				oldRole, ok := oldObj.(*rbacv1.ClusterRole)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRole")
					return
				}

				for _, cb := range callbacks {
					roleErr := cb.OnClusterRoleEvent(newRole, oldRole, ActionUpdate)
					if roleErr != nil {
						logging.GetLogger().Err(roleErr).Msg(fmt.Sprintf("on ClusterRole event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if _, toWatch := toWatchedTypes[ClusterRoleBindings2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching clusterRoleBindings for cluster %s", clusterKey)
		bindingsInformer := informerFactory.Rbac().V1().ClusterRoleBindings().Informer()
		var binding *rbacv1.ClusterRoleBinding
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &bindingsInformer,
			targetType: reflect.TypeOf(binding),
		})

		bindingsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newB, ok := newObj.(*rbacv1.ClusterRoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRoleBinding")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnClusterRoleBindingEvent(newB, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on ClusterRoleBinding event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldB, ok := oldObj.(*rbacv1.ClusterRoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *rbacv1.ClusterRoleBinding")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnClusterRoleBindingEvent(nil, oldB, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on ClusterRoleBinding event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newB, ok := newObj.(*rbacv1.ClusterRoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRoleBinding")
					return
				}
				oldB, ok := oldObj.(*rbacv1.ClusterRoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.ClusterRoleBinding")
					return
				}

				for _, cb := range callbacks {
					roleErr := cb.OnClusterRoleBindingEvent(newB, oldB, ActionUpdate)
					if roleErr != nil {
						logging.GetLogger().Err(roleErr).Msg(fmt.Sprintf("on ClusterRoleBinding event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if _, toWatch := toWatchedTypes[RoleBindings2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching roleBindings for cluster %s", clusterKey)
		rolesInformer := informerFactory.Rbac().V1().RoleBindings().Informer()
		var role *rbacv1.RoleBinding
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &rolesInformer,
			targetType: reflect.TypeOf(role),
		})

		rolesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newB, ok := newObj.(*rbacv1.RoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.RoleBinding")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnRoleBindingEvent(newB, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on RoleBinding event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldB, ok := oldObj.(*rbacv1.RoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *rbacv1.RoleBinding")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnRoleBindingEvent(nil, oldB, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on RoleBinding event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newB, ok := newObj.(*rbacv1.RoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.RoleBinding")
					return
				}
				oldB, ok := oldObj.(*rbacv1.RoleBinding)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *rbacv1.RoleBinding")
					return
				}

				for _, cb := range callbacks {
					roleErr := cb.OnRoleBindingEvent(newB, oldB, ActionUpdate)
					if roleErr != nil {
						logging.GetLogger().Err(roleErr).Msg(fmt.Sprintf("on rolebinding event %s error", cb.Name()))
					}
				}
			},
		})
	}
	if _, toWatch := toWatchedTypes[Nodes2Watch]; toWatch {
		logging.GetLogger().Info().Msgf("start watching nodes for cluster %s", clusterKey)
		nodesInformer := informerFactory.Core().V1().Nodes().Informer()
		var node *corev1.Node
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &nodesInformer,
			targetType: reflect.TypeOf(node),
		})

		nodesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				newNode, ok := newObj.(*corev1.Node)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Node")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnNodeEvent(newNode, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on newNode event %s error", cb.Name()))
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				oldNode, ok := oldObj.(*corev1.Node)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to (*corev1.Node)")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnNodeEvent(nil, oldNode, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on RoleBinding event %s error", cb.Name()))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newNode, ok := newObj.(*corev1.Node)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Node")
					return
				}
				oldNode, ok := oldObj.(*corev1.Node)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Node")
					return
				}

				for _, cb := range callbacks {
					roleErr := cb.OnNodeEvent(newNode, oldNode, ActionUpdate)
					if roleErr != nil {
						logging.GetLogger().Err(roleErr).Msg(fmt.Sprintf("on rolebinding event %s error", cb.Name()))
					}
				}
			},
		})
	}

	if _, podsWatch := toWatchedTypes[Pods2Watch]; podsWatch {
		// inform of pods
		logging.GetLogger().Info().Msgf("start watching pods for cluster %s", clusterKey)
		podInformer := informerFactory.Core().V1().Pods().Informer()
		var p *corev1.Pod
		informerStatuses = append(informerStatuses, &informerStatus{
			synced:     false,
			informer:   &podInformer,
			targetType: reflect.TypeOf(p),
		})
		podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnPodEvent(pod, nil, ActionAdd)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on pod event %s error", cb.Name()))
					}
				}

				// send no owner pods to tensor resources
				if toWatchResources {
					if len(pod.OwnerReferences) == 0 || pod.OwnerReferences[0].Kind == "Node" { // for no owner pods, we will watch them for tensor resources.
						res := newResourceFromPodNoOwnerOrStaticPod(clusterKey, pod)
						e := resourceEvent{
							oldResource: nil,
							newResource: res,
							action:      ActionAdd,
						}
						timer := time.NewTimer(500 * time.Millisecond)
						select {
						case tsResEventsChan <- e:
						case <-timer.C:
							logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. new data: %+v. action: add", res)
						}
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}

				for _, cb := range callbacks {
					evtErr := cb.OnPodEvent(nil, pod, ActionDelete)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on pod event %s error", cb.Name()))
					}
				}

				if toWatchResources {
					if len(pod.OwnerReferences) == 0 || pod.OwnerReferences[0].Kind == "Node" { // for no owner pods, we will watch them for tensor resources.
						res := newResourceFromPodNoOwnerOrStaticPod(clusterKey, pod)
						e := resourceEvent{
							oldResource: res,
							newResource: nil,
							action:      ActionDelete,
						}
						timer := time.NewTimer(500 * time.Millisecond)
						select {
						case tsResEventsChan <- e:
						case <-timer.C:
							logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. new data: %+v. action: delete", res)
						}
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newPod, ok := newObj.(*corev1.Pod)
				if !ok {
					return
				}
				oldPod, ok := oldObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnPodEvent(newPod, oldPod, ActionUpdate)
					if evtErr != nil {
						logging.GetLogger().Err(evtErr).Msg(fmt.Sprintf("on pod event %s error", cb.Name()))
					}
				}

				if toWatchResources {
					if len(newPod.OwnerReferences) == 0 || newPod.OwnerReferences[0].Kind == "Node" { // for no owner pods, we will watch them for tensor resources.
						newRes := newResourceFromPodNoOwnerOrStaticPod(clusterKey, newPod)
						oldRes := newResourceFromPodNoOwnerOrStaticPod(clusterKey, oldPod)
						e := resourceEvent{
							oldResource: oldRes,
							newResource: newRes,
							action:      ActionUpdate,
						}
						timer := time.NewTimer(500 * time.Millisecond)
						select {
						case tsResEventsChan <- e:
						case <-timer.C:
							logging.GetLogger().Warn().Msgf("Timeout for sending events to the event channel. new data: %+v. old data: %+v. action: update", newRes, oldRes)
						}
					}
				}
			},
		})
	}

	honeyspotInformers := defenseInforerFactory.Defense().V1().Honeypots().Informer()

	honeyspotInformers.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			hs, ok := obj.(*defensev1.Honeypot)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Endpoints")
				return
			}
			for _, cb := range callbacks {
				eptErr := cb.OnHoneyspot(hs, nil, ActionAdd)
				if eptErr != nil {
					logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on honeyspot event %s error", cb.Name()))
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newHs, ok := newObj.(*defensev1.Honeypot)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *defensev1.Honeypot")
				return
			}
			oldHs, ok := oldObj.(*defensev1.Honeypot)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *defensev1.Honeypot")
				return
			}
			for _, cb := range callbacks {
				eptErr := cb.OnHoneyspot(newHs, oldHs, ActionUpdate)
				if eptErr != nil {
					logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on honeyspot event %s error", cb.Name()))
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			hs, ok := obj.(*defensev1.Honeypot)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *defensev1.Honeypot")
				return
			}
			for _, cb := range callbacks {
				eptErr := cb.OnHoneyspot(nil, hs, ActionDelete)
				if eptErr != nil {
					logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on honeyspot event %s error", cb.Name()))
				}
			}
		},
	})
	honeyspotSynced := honeyspotInformers.HasSynced

	stopChan := make(chan struct{})
	w.putClusterStopChan(clusterKey, stopChan)

	informerFactory.Start(stopChan)
	defenseInforerFactory.Start(stopChan)

	go func() {
		if ok := cache.WaitForCacheSync(stopChan, honeyspotSynced); !ok {
			logging.GetLogger().Warn().Msgf("cluster %s synced failed for %s", clusterKey, "honeyspot")
		}
	}()

	// async wait for cache sync
	go func(cname string, ifactory informers.SharedInformerFactory, stopChan chan struct{}, informers []*informerStatus, clusterCallbacks []ClusterCallback) {
		syncSucc := true
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic when wait for cluster %s informers cache synced: %v. stack: %s", cname, r, debug.Stack())
			}

			// callbacks after sync
			for _, cb := range clusterCallbacks {
				cb.AfterDataSynced(ctx, syncSucc)
			}
		}()

		syncedStatus := ifactory.WaitForCacheSync(stopChan)
		for _, ift := range informers {
			ift.synced = syncedStatus[ift.targetType]
			if !ift.synced {
				logging.GetLogger().Warn().Msgf("cluster %s synced failed for %v", cname, ift.targetType)
				syncSucc = false
			}
		}

		// cutIdx is the check start index from the last failed sync
		syncedIdx := -1
		for {
			// wait for the podInformers and endpoints informers to complete all initial resource listing
			for i, ifm := range informers {
				if i <= syncedIdx {
					continue
				}
				if !(*ifm.informer).GetController().HasSynced() {
					break
				}
				syncedIdx = i
			}
			if syncedIdx+1 == len(informers) {
				break
			}
			time.Sleep(2 * time.Second)
		}

		logging.GetLogger().Info().Msgf("cluster %s synced status: %v", cname, syncSucc)

	}(clusterKey, informerFactory, stopChan, informerStatuses, callbacks)

	logging.GetLogger().Info().Msg(fmt.Sprintf("Wait for informers for cluster %s cache synced", clusterKey))
}
func (w *Watcher) StartsToWatch(ctx context.Context, k8sClients map[string]*Clientset) error {
	logging.GetLogger().Info().Msg("starts to watch kubernetes informers")

	if k8sClients == nil || len(k8sClients) == 0 {
		logging.GetLogger().Info().Msg("no Kubeclient given")
		return nil
	}

	for clusterKey, newClient := range k8sClients {
		_, exist := w.getClusterStopChan(clusterKey)
		if exist {
			logging.GetLogger().Warn().Msg(fmt.Sprintf("The cluster %s is already watched", clusterKey))
			continue
		}
		w.watchForCluster(ctx, clusterKey, newClient)
	}

	return nil
}

func NewWatcher() *Watcher {
	return &Watcher{
		callbacks:    make([]AssetsCallback, 0, 2),
		clusterChans: make(map[string]chan struct{}, 2),
	}
}
