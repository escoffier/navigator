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

type AssetsAction uint8
type WatchedType string

const (
	ActionAdd AssetsAction = iota
	ActionDelete
	ActionUpdate
	ActionSync

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
)

type AssetsCallback interface {
	// BeforeWatchNewCluster called before watch events
	BeforeWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) ClusterCallback

	WatchedTypes() map[WatchedType]struct{}
	Name() string
}

type ClusterCallback interface {
	OnTensorResourceEvent(newResource, oldResource *TensorResource, action AssetsAction) error
	OnNodeEvent(newNode, oldNode *corev1.Node, action AssetsAction) error
	AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string)
	OnTensorPod(pod *TensorPod, action AssetsAction) error
	OnTensorRole(role *TensorRole, action AssetsAction) error
	OnTensorClusterRole(clusterRole *TensorClusterRole, action AssetsAction) error
	OnTensorNamespace(ns *TensorNamespace, action AssetsAction) error
	OnTensorNode(node *TensorNode, action AssetsAction) error
	OnHoneyspot(honeyspot *TensorHoneySpot, action AssetsAction) error
	Name() string
}

type ResourceEvent struct {
	Action     AssetsAction `json:"action"`
	Type       WatchedType  `json:"type"`
	ClusterKey string
	Resource   interface{} `json:"resource"`
}

type clusterCallbacks struct {
	clusterKey string
	callbacks  []ClusterCallback
}
type Watcher struct {
	consumer            mq.Reader
	callbacks           []AssetsCallback
	callbacksOfClusters *sync.Map // clusterKey-> clusterCallbacks
	topic               string
	groupID             string

	ccMutex sync.Mutex
}

func NewWatcher(reader mq.Reader, topic, groupID string) *Watcher {
	w := &Watcher{
		consumer:            reader,
		callbacks:           nil,
		callbacksOfClusters: new(sync.Map),
		topic:               topic,
		groupID:             groupID,
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
		callbacks: make([]ClusterCallback, len(w.callbacks)),
	}
	for i, cb := range w.callbacks {
		cbs.callbacks[i] = cb.BeforeWatchNewCluster(context.Background(), clusterKey, 0)
	}
	w.callbacksOfClusters.Store(clusterKey, cbs)

	return cbs
}

func (w *Watcher) AddCallback(cb AssetsCallback) {
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
		for _, cb := range cbs.callbacks {
			cb.OnTensorResourceEvent(res, nil, event.Action)
		}
	case Pods2Watch:
		pod := &TensorPod{}
		err = json.Unmarshal(rawMsg, pod)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorPod err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err := cb.OnTensorPod(pod, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process pod err: %v", pod)
				continue
			}
		}
	case Roles2Watch:
		role := &TensorRole{}
		err = json.Unmarshal(rawMsg, role)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err := cb.OnTensorRole(role, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process role err: %v", role)
				continue
			}
		}
	case ClusterRoles2Watch:
		role := &TensorClusterRole{}
		err = json.Unmarshal(rawMsg, role)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err = cb.OnTensorClusterRole(role, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process clusterrole err: %v", role)
				continue
			}
		}
	case Namespaces2Watch:
		ns := &TensorNamespace{}
		err = json.Unmarshal(rawMsg, ns)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorRole err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err = cb.OnTensorNamespace(ns, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process namespace err: %v", ns)
				continue
			}
		}
	case Nodes2Watch:
		node := &TensorNode{}
		err = json.Unmarshal(rawMsg, node)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorNode err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err := cb.OnTensorNode(node, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process node err: %v", node)
				continue
			}
		}
	case Honeyspots2Watch:
		hp := &TensorHoneySpot{}
		err = json.Unmarshal(rawMsg, hp)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal Honeyspots err")
			return err
		}
		for _, cb := range cbs.callbacks {
			err = cb.OnHoneyspot(hp, event.Action)
			if err != nil {
				logging.Get().Err(err).Msgf("process honeyspot err: %v", hp)
				continue
			}
		}
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
