package assets

import (
	"context"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultStartWatchTimeout = 10 * time.Second
)

type AssetsAction uint8

const (
	ActionAdd AssetsAction = iota
	ActionDelete
	ActionUpdate
)

type AssetsCallback interface {
	// called before watch events
	BeforWatchNewCluster(ctx context.Context, clusterName string) ClusterCallback

	Name() string
}

type ClusterCallback interface {
	OnPodEvent(newPod, oldPod *corev1.Pod, action AssetsAction) error
	OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action AssetsAction) error
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
func (w *Watcher) StartsToWatch(ctx context.Context, k8sClients map[string]*kubernetes.Clientset) error {
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

		callbacks := make([]ClusterCallback, len(w.callbacks))
		for i, cb := range w.callbacks {
			callbacks[i] = cb.BeforWatchNewCluster(ctx, clusterName)
		}

		// To consider: maybe it's better to watch StatefulSets, Deployments, ReplicaSets, Jobs, etc
		// instead of watching pods?
		// statefulsetInformer := informerFactory.Apps().V1().StatefulSets()
		informerFactory := informers.NewSharedInformerFactory(newClient, time.Minute*2)

		// inform of pods
		podInformer := informerFactory.Core().V1().Pods().Informer()
		podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, cb := range callbacks {
					evtErr := cb.OnPodEvent(pod, nil, ActionAdd)
					logging.GetLogger().Info().Msgf("cluster %s On pod event (add) for callback %s: %+v", clusterName, cb.Name(), pod)
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

		// watch endpoints
		endPointsInformer := informerFactory.Core().V1().Endpoints().Informer()
		endPointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				ept, ok := newObj.(*corev1.Endpoints)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
					return
				}
				for _, cb := range callbacks {
					logging.GetLogger().Info().Msgf("cluster %s On endpoints event (add) for callback %s: %+v", clusterName, ept)
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
					logging.GetLogger().Info().Msgf("cluster %s On endpoints event (delete) for callback %s: %+v", clusterName, ept)
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

		stopChan = make(chan struct{})
		w.putClusterStopChan(clusterName, stopChan)

		informerFactory.Start(stopChan)

		// async wait for cache sync
		go func(cname string, ifactory informers.SharedInformerFactory, podInformer, eptInformer *cache.SharedIndexInformer, stopChan chan struct{}) {
			var podSynced, eptSynced bool
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("panic when wait for cluster %s informers cache synced: %v. stack: %s", cname, r, debug.Stack())
				}

				syncChan <- informerSyncMsg{
					ClusterName: cname,
					Errored:     !podSynced || !eptSynced,
				}
			}()

			syncedStatus := ifactory.WaitForCacheSync(stopChan)
			var podType *corev1.Pod
			var eptType *corev1.Endpoints
			podSynced = syncedStatus[reflect.TypeOf(podType)]
			eptSynced = syncedStatus[reflect.TypeOf(eptType)]
			if !podSynced {
				logging.GetLogger().Warn().Msgf("Cluster %s pod synced failed", cname)
			}
			if !eptSynced {
				logging.GetLogger().Warn().Msgf("Cluster %s Endpoints synced failed", cname)
			}

			for {
				// wait for the podInformers and endpoints informers to complete all initial resource listing
				if (*podInformer).GetController().HasSynced() /* && (*eptInformer).GetController().HasSynced()*/ { // Returns true once this controller has completed an initial resource listing
					break
				}
				time.Sleep(2 * time.Second)
			}

			logging.GetLogger().Info().Msgf("cluster %s synced status: pods-%v endpoisnts-%v", clusterName, podSynced, eptSynced)

			// callbacks after sync
			for _, cb := range callbacks {
				cb.AfterDataSynced(ctx, podSynced && eptSynced)
			}

		}(clusterName, informerFactory, &podInformer, &endPointsInformer, stopChan)

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
