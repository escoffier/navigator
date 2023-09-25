package assets

import (
	"context"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
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
	Ingress2Watch             WatchedType = "ingresses"
	Secrets2Watch             WatchedType = "secrets"
	PVs2Watch                 WatchedType = "pvs"
	PVCs2Watch                WatchedType = "pvcs"
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
	// OnNodeEvent(newNode, oldNode *corev1.Node, action Action) error   // 未调用
	AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string)
	OnTensorPod(pod *TensorPod, action Action) error
	OnTensorRole(role *TensorRole, action Action) error
	OnTensorClusterRole(clusterRole *TensorClusterRole, action Action) error
	OnTensorNamespace(ns *TensorNamespace, action Action) error
	OnTensorNode(node *TensorNode, action Action) error
	OnTensorIngress(node *TensorIngress, action Action) error
	OnTensorService(node *TensorService, action Action) error
	OnTensorEndpoints(node *TensorEndpoints, action Action) error
	OnTensorSecret(node *TensorSecret, action Action) error
	OnTensorPV(node *TensorPV, action Action) error
	OnTensorPVC(node *TensorPVC, action Action) error
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
	YamlData   []byte      `json:"yamlData"`
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
	logging.Get().Debug().Msgf("kafka offset :%d,time:%v", message.Offset, message.Time)

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
			if !errored && !res.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(res)
				} else {
					w.dupCache.Remove(res)
				}
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
			if !errored && !pod.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(pod)
				} else {
					w.dupCache.Remove(pod)
				}
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
			if !errored && !role.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(role)
				} else {
					w.dupCache.Remove(role)
				}
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
			if !errored && !role.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(role)
				} else {
					w.dupCache.Remove(role)
				}
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
			if !errored && !ns.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(ns)
				} else {
					w.dupCache.Remove(ns)
				}
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
			if !errored && !node.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(node)
				} else {
					w.dupCache.Remove(node)
				}
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
			if !errored && !hp.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(hp)
				} else {
					w.dupCache.Remove(hp)
				}
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
	case Ingress2Watch:
		logging.Get().Debug().Msg("processing ingress")
		ingre := &TensorIngress{}
		err = json.Unmarshal(rawMsg, ingre)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorIngress err")
			return err
		}
		if ingre.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", ingre)
		}
		if event.Action == ActionDelete || ingre.DuplicatedChecked() || !w.dupCache.Check(ingre) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorIngress(ingre, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process ingress err: %v", ingre)
					errored = true
					continue
				}
			}
			if !errored && !ingre.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(ingre)
				} else {
					w.dupCache.Remove(ingre)
				}
			}
		} else {
			logging.Get().Info().Str("key", ingre.KeyName()).Str("idStr", ingre.IdentityString()).Msg("duplicated and bypass.")
		}
	case Services2Watch:
		obj := &TensorService{}
		err = json.Unmarshal(rawMsg, obj)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorService err")
			return err
		}
		logging.Get().Debug().Msgf("processing service,svcName:%s", obj.Service.Name)

		if obj.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", obj)
		}
		if event.Action == ActionDelete || obj.DuplicatedChecked() || !w.dupCache.Check(obj) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorService(obj, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process service err: %v", obj)
					errored = true
					continue
				}
			}
			if !errored && !obj.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(obj)
				} else {
					w.dupCache.Remove(obj)
				}
			}
		} else {
			logging.Get().Info().Str("key", obj.KeyName()).Str("idStr", obj.IdentityString()).Msg("duplicated and bypass.")
		}
	case Endpoints2Watch:
		logging.Get().Debug().Msg("processing endpoints")
		obj := &TensorEndpoints{}
		err = json.Unmarshal(rawMsg, obj)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorEndpoints err")
			return err
		}
		if obj.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", obj)
		}
		if event.Action == ActionDelete || obj.DuplicatedChecked() || !w.dupCache.Check(obj) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorEndpoints(obj, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process endpoints err: %v", obj)
					errored = true
					continue
				}
			}
			if !errored && !obj.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(obj)
				} else {
					w.dupCache.Remove(obj)
				}
			}
		} else {
			logging.Get().Info().Str("key", obj.KeyName()).Str("idStr", obj.IdentityString()).Msg("duplicated and bypass.")
		}
	case Secrets2Watch:
		logging.Get().Debug().Msg("processing secret")
		obj := &TensorSecret{}
		err = json.Unmarshal(rawMsg, obj)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorSecret err")
			return err
		}
		if obj.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", obj)
		}
		if event.Action == ActionDelete || obj.DuplicatedChecked() || !w.dupCache.Check(obj) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorSecret(obj, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process secret err: %v", obj)
					errored = true
					continue
				}
			}
			if !errored && !obj.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(obj)
				} else {
					w.dupCache.Remove(obj)
				}
			}
		} else {
			logging.Get().Info().Str("key", obj.KeyName()).Str("idStr", obj.IdentityString()).Msg("duplicated and bypass.")
		}
	case PVs2Watch:
		obj := &TensorPV{}
		err = json.Unmarshal(rawMsg, obj)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorPV err")
			return err
		}
		if obj.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", obj)
		}
		logging.Get().Debug().Msgf("processing pv %s", obj.Name)
		if event.Action == ActionDelete || obj.DuplicatedChecked() || !w.dupCache.Check(obj) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorPV(obj, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process pv err: %v", obj)
					errored = true
					continue
				}
			}
			if !errored && !obj.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(obj)
				} else {
					w.dupCache.Remove(obj)
				}
			}
		} else {
			logging.Get().Info().Str("key", obj.KeyName()).Str("idStr", obj.IdentityString()).Msg("duplicated and bypass.")
		}
	case PVCs2Watch:
		obj := &TensorPVC{}
		err = json.Unmarshal(rawMsg, obj)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal TensorPVC err")
			return err
		}
		if obj.Name == "" {
			logging.Get().Warn().Msgf("empty keyname: %+v", obj)
		}
		logging.Get().Debug().Msgf("processing pvc %s", obj.Name)
		if event.Action == ActionDelete || obj.DuplicatedChecked() || !w.dupCache.Check(obj) {
			errored := false
			for _, cb := range cbs.callbacks {
				err := cb.OnTensorPVC(obj, event.Action)
				if err != nil {
					logging.Get().Err(err).Msgf("process pvc err: %v", obj)
					errored = true
					continue
				}
			}
			if !errored && !obj.DuplicatedChecked() {
				if event.Action != ActionDelete {
					w.dupCache.Put(obj)
				} else {
					w.dupCache.Remove(obj)
				}
			}
		} else {
			logging.Get().Info().Str("key", obj.KeyName()).Str("idStr", obj.IdentityString()).Msg("duplicated and bypass.")
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
