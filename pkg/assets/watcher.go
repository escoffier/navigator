package assets

import (
	"context"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	appsv1 "k8s.io/api/apps/v1"
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

	Endpoints2Watch   WatchedType = "endpoints"
	Services2Watch    WatchedType = "services"
	Pods2Watch        WatchedType = "pods"
	ReplicaSets2Watch WatchedType = "replicasets"
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
	OnReplicaSetEvent(newRs, oldRs *appsv1.ReplicaSet, action AssetsAction) error
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

		// To consider: maybe it's better to watch StatefulSets, Deployments, ReplicaSets, Jobs, etc
		// instead of watching pods?
		// statefulsetInformer := informerFactory.Apps().V1().StatefulSets()
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

		if _, toWatch := toWatchedTypes[ReplicaSets2Watch]; toWatch {
			logging.GetLogger().Info().Msg("start watching replicasets")

			rsInformer := informerFactory.Apps().V1().ReplicaSets().Informer()
			var rs *appsv1.ReplicaSet
			informerStatuses = append(informerStatuses, &informerStatus{
				synced:     false,
				informer:   &rsInformer,
				targetType: reflect.TypeOf(rs),
			})

			rsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc: func(newObj interface{}) {
					newRs, ok := newObj.(*appsv1.ReplicaSet)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *appsv1.ReplicaSet")
						return
					}
					for _, cb := range callbacks {
						eventErr := cb.OnReplicaSetEvent(newRs, nil, ActionAdd)
						if eventErr != nil {
							logging.GetLogger().Err(eventErr).Msg(fmt.Sprintf("on rs event %s error", cb.Name()))
						}
					}
				},
				DeleteFunc: func(oldObj interface{}) {
					oldRs, ok := oldObj.(*appsv1.ReplicaSet)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *appsv1.ReplicaSet")
						return
					}
					for _, cb := range callbacks {
						eventErr := cb.OnReplicaSetEvent(nil, oldRs, ActionDelete)
						if eventErr != nil {
							logging.GetLogger().Err(eventErr).Msg(fmt.Sprintf("on rs event %s error", cb.Name()))
						}
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					newRs, ok := newObj.(*appsv1.ReplicaSet)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *appsv1.ReplicaSet")
						return
					}
					oldRs, ok := oldObj.(*appsv1.ReplicaSet)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *appsv1.ReplicaSet")
						return
					}

					for _, cb := range callbacks {
						eptErr := cb.OnReplicaSetEvent(newRs, oldRs, ActionUpdate)
						if eptErr != nil {
							logging.GetLogger().Err(eptErr).Msg(fmt.Sprintf("on endpoint event %s error", cb.Name()))
						}
					}
				},
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
