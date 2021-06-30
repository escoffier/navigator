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
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultStartWatchTimeout = 10 * time.Second
)

type AssetsAction uint8
type WatchedType string

const (
	ActionAdd AssetsAction = iota
	ActionDelete
	ActionUpdate

	Endpoints2Watch       WatchedType = "endpoints"
	Services2Watch        WatchedType = "services"
	Pods2Watch            WatchedType = "pods"
	TensorResources2Watch WatchedType = "tensorresources"
)

type AssetsCallback interface {
	// called before watch events
	BeforWatchNewCluster(ctx context.Context, clusterName string) ClusterCallback

	WatchedTypes() map[WatchedType]struct{}
	Name() string
}

type ClusterCallback interface {
	OnPodEvent(newPod, oldPod *corev1.Pod, action AssetsAction) error
	OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action AssetsAction) error
	OnServiceEvent(newSvc, oldEvc *corev1.Service, action AssetsAction) error
	OnTensorResourceEvent(newResource, oldResource *TensorResource, action AssetsAction) error
	AfterDataSynced(ctx context.Context, dataSynced bool)
	Name() string
}

type Watcher struct {
	callbacks    []AssetsCallback
	clusterChans map[string]chan struct{}
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

type informerSyncMsg struct {
	ClusterName string
	Errored     bool
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
func (w *Watcher) StartsToWatch(ctx context.Context, k8sClients map[string]*kubernetes.Clientset) error {
	if util.IsNonSingletonPodInTestingEnv() {
		logging.GetLogger().Info().Msg("In Testing env and console not singleton. Disable ")
		return nil
	}

	logging.GetLogger().Info().Msg("starts to watch kubernetes informers")

	if k8sClients == nil || len(k8sClients) == 0 {
		logging.GetLogger().Info().Msg("no Kubeclient given")
		return nil
	}

	syncChan := make(chan informerSyncMsg, len(k8sClients))
	for clusterName, newClient := range k8sClients {
		stopChan, exist := w.getClusterStopChan(clusterName)
		if exist {
			logging.GetLogger().Warn().Msg(fmt.Sprintf("The cluster %s is already watched", clusterName))
			continue
		}

		toWatchedTypes := make(map[WatchedType]struct{}, 4)
		callbacks := make([]ClusterCallback, len(w.callbacks))
		for i, cb := range w.callbacks {
			for t := range cb.WatchedTypes() {
				toWatchedTypes[t] = struct{}{}
			}
			callbacks[i] = cb.BeforWatchNewCluster(ctx, clusterName)
		}

		// whether to watch tensor resources; need pod informer.
		var tsResEventsChan chan resourceEvent
		_, toWatchResources := toWatchedTypes[TensorResources2Watch]
		if toWatchResources {
			tsResEventsChan = make(chan resourceEvent, 50)
		}

		informerFactory := informers.NewSharedInformerFactory(newClient, time.Minute*2)

		informerStatuses := make([]*informerStatus, 0, 5)
		if _, podsWatch := toWatchedTypes[Pods2Watch]; podsWatch {
			logging.GetLogger().Info().Msg("start watching pods")
			// inform of pods
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
						if len(pod.OwnerReferences) == 0 { // for no owner pods, we will watch them for tensor resources.
							res := newResourceFromPodNoOwner(clusterName, pod)
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
						if len(pod.OwnerReferences) == 0 { // for no owner pods, we will watch them for tensor resources.
							res := newResourceFromPodNoOwner(clusterName, pod)
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
						if len(newPod.OwnerReferences) == 0 { // for no owner pods, we will watch them for tensor resources.
							newRes := newResourceFromPodNoOwner(clusterName, newPod)
							oldRes := newResourceFromPodNoOwner(clusterName, oldPod)
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

		if _, toWatch := toWatchedTypes[Endpoints2Watch]; toWatch {
			logging.GetLogger().Info().Msg("start watching endpoints")
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
			logging.GetLogger().Info().Msg("start watching resources")

			go func() {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic for receiving resource events: %v. stack: %s", r, debug.Stack())
					}
				}()

				for event := range tsResEventsChan {
					for _, cb := range callbacks {
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
			}()

			informerWatchTargets := func(informer cache.SharedIndexInformer, targetType reflect.Type, resFactory ResourceFactoryFunc) {
				informerStatuses = append(informerStatuses, &informerStatus{
					synced:     false,
					informer:   &informer,
					targetType: targetType,
				})
				informer.AddEventHandler(getInformerFuncForResources(tsResEventsChan, clusterName, resFactory))
			}
			// replicasets
			rsInformer := informerFactory.Apps().V1().ReplicaSets().Informer()
			var rs *appsv1.ReplicaSet
			informerWatchTargets(rsInformer, reflect.TypeOf(rs), func(cluster string, obj interface{}) (*TensorResource, error) {
				if obj == nil {
					return nil, errors.New("nil obj")
				}
				rs, ok := obj.(*appsv1.ReplicaSet)
				if !ok {
					return nil, errors.New("cast error")
				}
				return newResourceFromReplicaSet(cluster, rs), nil
			})

			// statefulsets
			ssInformer := informerFactory.Apps().V1().StatefulSets().Informer()
			var ss *appsv1.StatefulSet
			informerWatchTargets(ssInformer, reflect.TypeOf(ss), func(cluster string, obj interface{}) (*TensorResource, error) {
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
			informerWatchTargets(dsInformer, reflect.TypeOf(ds), func(cluster string, obj interface{}) (*TensorResource, error) {
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
			informerWatchTargets(dmInformer, reflect.TypeOf(dm), func(cluster string, obj interface{}) (*TensorResource, error) {
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
			informerWatchTargets(rcInformer, reflect.TypeOf(rc), func(cluster string, obj interface{}) (*TensorResource, error) {
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
			informerWatchTargets(jobsInformer, reflect.TypeOf(jb), func(cluster string, obj interface{}) (*TensorResource, error) {
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
			informerWatchTargets(cjInformer, reflect.TypeOf(cj), func(cluster string, obj interface{}) (*TensorResource, error) {
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

		if _, toWatch := toWatchedTypes[Services2Watch]; toWatch {
			logging.GetLogger().Info().Msg("start watching services")
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

		stopChan = make(chan struct{})
		w.putClusterStopChan(clusterName, stopChan)

		informerFactory.Start(stopChan)

		// async wait for cache sync
		go func(cname string, ifactory informers.SharedInformerFactory, stopChan chan struct{}, informers []*informerStatus) {
			syncSucc := true
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("panic when wait for cluster %s informers cache synced: %v. stack: %s", cname, r, debug.Stack())
				}

				syncChan <- informerSyncMsg{
					ClusterName: cname,
					Errored:     !syncSucc,
				}
			}()

			syncedStatus := ifactory.WaitForCacheSync(stopChan)
			for _, ift := range informers {
				ift.synced = syncedStatus[ift.targetType]
				syncSucc = syncSucc && ift.synced
				if !ift.synced {
					logging.GetLogger().Warn().Msgf("cluster %s synced failed for %v", cname, ift.targetType)
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

			logging.GetLogger().Info().Msgf("cluster %s synced status: %v", clusterName, syncSucc)

			// callbacks after sync
			for _, cb := range callbacks {
				cb.AfterDataSynced(ctx, syncSucc)
			}

		}(clusterName, informerFactory, stopChan, informerStatuses)

		logging.GetLogger().Info().Msg(fmt.Sprintf("Wait for informers for cluster %s cache synced", clusterName))

	}

	erroredClusters := make([]string, 0, 1)
	timeoutTimer := time.NewTimer(defaultStartWatchTimeout)

LOOP:
	for _ = range k8sClients {
		select {
		case msg := <-syncChan:
			if msg.Errored {
				erroredClusters = append(erroredClusters, msg.ClusterName)
			}
		case <-timeoutTimer.C:
			logging.GetLogger().Warn().Msgf("Wait for all clusters (%v) timeout(%v)", k8sClients, defaultStartWatchTimeout)
			break LOOP
		}
	}

	if len(erroredClusters) > 0 {
		return fmt.Errorf("Clusters (%v) wait for cache sync failed", erroredClusters)
	}
	return nil
}

func NewWatcher() *Watcher {
	return &Watcher{
		callbacks:    make([]AssetsCallback, 0, 2),
		clusterChans: make(map[string]chan struct{}, 2),
	}
}
