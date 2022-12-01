package assets

import (
	"context"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	corev1 "k8s.io/api/core/v1"
)

type Action uint8
type WatchedType string

// FATAL: don't alter this const block!!!
const (
	ActionAdd Action = iota
	ActionDelete
	ActionUpdate
	ActionSync
)

const (
	cacheMaxSize = 128 * 1024
	cacheTTL     = 3 * time.Hour

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
	Honeyspots2Watch          WatchedType = "honeyspots"
	AssetsSync                WatchedType = "assetssync"
	RawContainer              WatchedType = "rawcontainer"
	ContainerSync             WatchedType = "containersync"
	ContainerSyncStart        WatchedType = "containersyncstart"
)

type Callback interface {
	// BeforeWatchNewCluster called before watch events
	BeforeWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) ClusterCallback

	WatchedTypes() map[WatchedType]struct{}
	Name() string
}

type ClusterCallback interface {
	OnTensorResourceEvent(newResource, oldResource *TensorResource, action Action) error
	OnNodeEvent(newNode, oldNode *corev1.Node, action Action) error
	AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string)
	OnTensorPod(pod *TensorPod, action Action) error
	OnTensorRole(role *TensorRole, action Action) error
	OnTensorClusterRole(clusterRole *TensorClusterRole, action Action) error
	OnTensorNamespace(ns *TensorNamespace, action Action) error
	OnTensorNode(node *TensorNode, action Action) error
	OnHoneyspot(honeyspot *TensorHoneySpot, action Action) error
	OnRawContainer(container *TensorRawContainer, action Action) error
	OnSync(*TensorSync) error
	Name() string
}

type ResourceEvent struct {
	Action     Action      `json:"action"`
	Type       WatchedType `json:"type"`
	ClusterKey string
	Resource   interface{} `json:"resource"`
}

type clusterCallbacks struct {
	clusterKey string
	callbacks  []ClusterCallback
}
type Watcher struct {
	consumer            mq.Reader
	callbacks           []Callback
	callbacksOfClusters *sync.Map // clusterKey-> clusterCallbacks
	topic               string
	groupID             string
	dupCache            *DuplicationCheckingCache

	ccMutex sync.Mutex
}

func NewWatcher(reader mq.Reader, topic, groupID string) *Watcher {
	w := &Watcher{
		consumer:            reader,
		callbacks:           nil,
		callbacksOfClusters: new(sync.Map),
		topic:               topic,
		groupID:             groupID,
		dupCache:            NewDuplicationCheckingCache(cacheTTL, cacheMaxSize),
	}
	return w
}

func (w *Watcher) getOrCreateClusterCallbacks(clusterKey string) clusterCallbacks {
	o, exist := w.callbacksOfClusters.Load(clusterKey)
	if exist && o != nil {
		cbs := o.(clusterCallbacks)
		return cbs
	}
	w.ccMutex.Lock()
	defer w.ccMutex.Unlock()

	o, exist = w.callbacksOfClusters.Load(clusterKey)
	if exist && o != nil {
		cbs := o.(clusterCallbacks)
		return cbs
	}
	cbs := clusterCallbacks{
		clusterKey: clusterKey,
		callbacks:  make([]ClusterCallback, len(w.callbacks)),
	}
	for i, cb := range w.callbacks {
		cbs.callbacks[i] = cb.BeforeWatchNewCluster(context.Background(), clusterKey, 0)
	}
	w.callbacksOfClusters.Store(clusterKey, cbs)

	return cbs
}

func (w *Watcher) AddCallback(cb Callback) {
	w.callbacks = append(w.callbacks, cb)
}

func (w *Watcher) Run(stopCh <-chan struct{}) {
	w.consumer.Subscribe(w.topic, w.groupID, w.process)

	<-stopCh
}

func (w *Watcher) process(ctx context.Context, message kafka.Message) error {
	event := &ResourceEvent{}
	rawMsg := json.RawMessage{}
	event.Resource = &rawMsg
	err := json.Unmarshal(message.Value, event)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshal message err")
		return err
	}

	cbs := w.getOrCreateClusterCallbacks(event.ClusterKey)
	switch event.Type {
	case AssetsSync:
		logging.Get().Info().Msgf("cluster %s synced", string(message.Key))

		for _, cb := range cbs.callbacks {
			cb.AfterDataSynced(context.Background(), true, string(message.Key))
		}
	case TensorResources2Watch:
		res := &TensorResource{}
		err = json.Unmarshal(rawMsg, res)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorResource err")
			return err
		}

		if res.Namespace == "" {
			logging.Get().Warn().Msgf("action: %v empty keyname: %+v", event.Action, res)
		}

		if event.Action == ActionDelete || res.DuplicatedChecked() || !w.dupCache.Check(res) {
			errored := false
			for _, cb := range cbs.callbacks {

				err := cb.OnTensorResourceEvent(res, nil, event.Action)
				if err != nil {
					logging.Get().Err(err).Str("key", res.KeyName()).Msg("process res err")
					errored = true
				}
			}
			if !errored && !res.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(res)
			}
		} else {
			logging.Get().Info().Str("key", res.KeyName()).Str("idStr", res.IdentityString()).Msg("duplicated and bypass.")
		}

	case Pods2Watch:
		pod := &TensorPod{}
		err = json.Unmarshal(rawMsg, pod)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorPod err")
			return err
		}
		if pod.Namespace == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", pod)
		}
		if event.Action == ActionDelete || pod.DuplicatedChecked() || !w.dupCache.Check(pod) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorPod(pod, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process pod err: %v", pod)
					errored = true
					continue
				}
			}
			if !errored && !pod.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(pod)
			}
		} else {
			logging.Get().Info().Str("key", pod.KeyName()).Str("idStr", pod.IdentityString()).Msg("duplicated and bypass.")
		}
	case Roles2Watch:
		role := &TensorRole{}
		err = json.Unmarshal(rawMsg, role)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		if role.Namespace == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", role)
		}
		if event.Action == ActionDelete || role.DuplicatedChecked() || !w.dupCache.Check(role) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorRole(role, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process role err: %v", role)
					errored = true
					continue
				}
			}
			if !errored && !role.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(role)
			}
		} else {
			logging.Get().Info().Str("key", role.KeyName()).Str("idStr", role.IdentityString()).Msg("duplicated and bypass.")
		}
	case ClusterRoles2Watch:
		role := &TensorClusterRole{}
		err = json.Unmarshal(rawMsg, role)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		if role.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", role)
		}
		if event.Action == ActionDelete || role.DuplicatedChecked() || !w.dupCache.Check(role) {
			errored := false
			for _, cb := range cbs.callbacks {
				err = cb.OnTensorClusterRole(role, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process clusterrole err: %v", role)
					continue
				}
			}
			if !errored && !role.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(role)
			}
		} else {
			logging.Get().Info().Str("key", role.KeyName()).Str("idStr", role.IdentityString()).Msg("duplicated and bypass.")
		}
	case Namespaces2Watch:
		ns := &TensorNamespace{}
		err = json.Unmarshal(rawMsg, ns)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		if ns.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", ns)
		}
		if event.Action == ActionDelete || ns.DuplicatedChecked() || !w.dupCache.Check(ns) {
			errored := false
			for _, cb := range cbs.callbacks {
				err = cb.OnTensorNamespace(ns, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process namespace err: %v", ns)
					errored = true
					continue
				}
			}
			if !errored && !ns.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(ns)
			}
		} else {
			logging.Get().Info().Str("key", ns.KeyName()).Str("idStr", ns.IdentityString()).Msg("duplicated and bypass.")
		}
	case Nodes2Watch:
		node := &TensorNode{}
		err = json.Unmarshal(rawMsg, node)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorNode err")
			return err
		}
		if node.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", node)
		}
		if event.Action == ActionDelete || node.DuplicatedChecked() || !w.dupCache.Check(node) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorNode(node, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process node err: %v", node)
					errored = true
					continue
				}
			}
			if !errored && !node.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(node)
			}
		} else {
			logging.Get().Info().Str("key", node.KeyName()).Str("idStr", node.IdentityString()).Msg("duplicated and bypass.")
		}
	case Honeyspots2Watch:
		hp := &TensorHoneySpot{}
		err = json.Unmarshal(rawMsg, hp)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal Honeyspots err")
			return err
		}
		if hp.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", hp)
		}
		if event.Action == ActionDelete || hp.DuplicatedChecked() || !w.dupCache.Check(hp) {
			errored := false
			for _, cb := range cbs.callbacks {
				err = cb.OnHoneyspot(hp, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process honeyspot err: %v", hp)
					errored = true
					continue
				}
			}
			if !errored && !hp.DuplicatedChecked() && event.Action != ActionDelete {
				w.dupCache.Put(hp)
			}
		} else {
			logging.Get().Info().Str("key", hp.KeyName()).Str("idStr", hp.IdentityString()).Msg("duplicated and bypass.")
		}
	case RawContainer:
		logging.Get().Debug().Msg("processing raw container")
		rc := &TensorRawContainer{}
		err = json.Unmarshal(rawMsg, rc)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal raw container err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err = cb.OnRawContainer(rc, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process raw container err: %v", rc)
				continue
			}
		}
	case ContainerSync:
		logging.Get().Debug().Msg("sync raw container")
		ts := &TensorSync{}
		err = json.Unmarshal(rawMsg, ts)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal container sync err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err = cb.OnSync(ts)
			if err != nil {
				logging.Get().Err(err).Msgf("sync raw container err: %v", ts)
				continue
			}
		}
	case ContainerSyncStart:
		ts := &TensorSync{}
		err = json.Unmarshal(rawMsg, ts)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal container sync err")
			return err
		}
		logging.Get().Info().Msgf("raw container at host %s/%s start syncing at %v",
			ts.Cluster, ts.NodeName, ts.SyncTime)
	}
	return nil
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
