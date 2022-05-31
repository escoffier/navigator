package kubemonitor

import (
	"context"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	name = "kubiscanMonitor"
)

type KubeStorageFactory func(clusterName string) KubeStorage

type KubeStorage interface {
	SetRoleRisky(name, namespace string) error
	SetClusterRoleRisky(name string) error
	RemoveRole(name, namespace string) (existed bool, err error)
	RemoveClusterRole(name string) (existed bool, err error)
	IsRoleRisky(name, namespace string) bool
	IsClusterRoleRisky(name string) bool
}

func NewMemStorage(clusterKey string) KubeStorage {
	return newMemStorage(clusterKey)
}

type KubeRiskyMonitor struct {
	outputChan     chan KubeMonitorEvent
	storageFactory KubeStorageFactory
	rules          []*RiskyRoleItem
}

func NewKubeRiskMonitor(rules []*RiskyRoleItem, fac KubeStorageFactory) (*KubeRiskyMonitor, error) {
	m := KubeRiskyMonitor{
		outputChan:     make(chan KubeMonitorEvent, 100),
		storageFactory: fac,
		rules:          rules,
	}
	return &m, nil
}
func (w *KubeRiskyMonitor) OutputChannel() <-chan KubeMonitorEvent {
	return w.outputChan
}

// called before watch events
func (w *KubeRiskyMonitor) BeforeWatchNewCluster(ctx context.Context, clusterKey string, resyncTTL time.Duration) assets.ClusterCallback {
	cm := &KubeClusterMonitor{
		clusterKey:   clusterKey,
		parent:       w,
		storage:      w.storageFactory(clusterKey),
		clusterRoles: make(map[string]*rbacv1.ClusterRole, 10),
		roles:        make(map[string]*rbacv1.Role, 20),
		eventCh:      make(chan detectionEvent, 200),
	}
	cm.engine = NewEngine(w.rules, cm, cm.storage)
	cm.asyncDetection()
	return cm
}

func (w *KubeRiskyMonitor) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Roles2Watch:               {},
		assets.ClusterRoles2Watch:        {},
		assets.RoleBindings2Watch:        {},
		assets.ClusterRoleBindings2Watch: {},
	}
}

func (w *KubeRiskyMonitor) Name() string {
	return name
}

type detectionEvent struct {
	role               *rbacv1.Role
	clusterRole        *rbacv1.ClusterRole
	roleBinding        *rbacv1.RoleBinding
	clusterRoleBinding *rbacv1.ClusterRoleBinding
	kind               Kind
}
type KubeClusterMonitor struct {
	sync.RWMutex
	parent       *KubeRiskyMonitor
	engine       *Engine
	storage      KubeStorage
	clusterKey   string
	clusterRoles map[string]*rbacv1.ClusterRole // name -> Role
	roles        map[string]*rbacv1.Role        // namespace/name -> Role
	eventCh      chan detectionEvent
}

func (l *KubeClusterMonitor) asyncDetection() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		for evt := range l.eventCh {
			l.detectEvent(context.Background(), evt)
		}
	}()
}

func (l *KubeClusterMonitor) sendToOutput(outputEvt KubeMonitorEvent) {
	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case l.parent.outputChan <- outputEvt:
	case <-timer.C:
		logging.GetLogger().Warn().Msgf("send output channel timeout for data: %+v", outputEvt)
	}
}
func (l *KubeClusterMonitor) detectEvent(ctx context.Context, evt detectionEvent) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when consuming events: %v. event: %+v Stack: %s", r, evt, debug.Stack())
		}
	}()

	switch evt.kind {
	case KindRole:
		if evt.role == nil {
			return
		}
		risky, items := l.engine.IsRiskyRole(evt.role)
		if risky {
			l.storage.SetRoleRisky(evt.role.Name, evt.role.Namespace)
			l.sendToOutput(KubeMonitorEvent{
				ClusterKey:   l.clusterKey,
				RiskyItems:   items,
				Kind:         KindRole,
				TargetRole:   evt.role,
				targetObject: evt.role,
			})
		}
	case KindClusterRole:
		if evt.clusterRole == nil {
			return
		}
		risky, items := l.engine.IsRiskyClusterRole(evt.clusterRole)
		if risky {
			l.storage.SetClusterRoleRisky(evt.clusterRole.Name)
			l.sendToOutput(KubeMonitorEvent{
				ClusterKey:        l.clusterKey,
				RiskyItems:        items,
				Kind:              KindClusterRole,
				TargetClusterRole: evt.clusterRole,
				targetObject:      evt.clusterRole,
			})
		}
	case KindClusterRoleBinding:
	case KindRoleBinding:
	}
}

func (l *KubeClusterMonitor) GetClusterRole(name string) (*rbacv1.ClusterRole, bool) {
	l.RLock()
	defer l.RUnlock()

	cr, ok := l.clusterRoles[name]
	return cr, ok
}
func (l *KubeClusterMonitor) GetRole(name, namespace string) (*rbacv1.Role, bool) {
	l.RLock()
	defer l.RUnlock()

	r, ok := l.roles[getKeyFrom(namespace, name)]
	return r, ok
}

func (l *KubeClusterMonitor) OnTensorPod(pod *assets.TensorPod, action assets.AssetsAction) error {
	return nil
}

func (l *KubeClusterMonitor) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// do nothing
	return nil
}

func (l *KubeClusterMonitor) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (l *KubeClusterMonitor) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (l *KubeClusterMonitor) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	// do nothing
	return nil
}

func (l *KubeClusterMonitor) upsertRole(role *rbacv1.Role) {
	l.Lock()
	defer l.Unlock()

	l.roles[getKeyFromRole(role)] = role
}

func (l *KubeClusterMonitor) upsertClusterRole(crole *rbacv1.ClusterRole) {
	l.Lock()
	defer l.Unlock()

	l.clusterRoles[getKeyFromRole(crole)] = crole
}

type RoleInterface interface {
	GetName() string
	GetNamespace() string
}

func getKeyFromRole(r RoleInterface) string {
	return getKeyFrom(r.GetName(), r.GetNamespace())
}

func getKeyFrom(elems ...string) string {
	return strings.Join(elems, "/")
}
func (l *KubeClusterMonitor) deleteRole(role RoleInterface) {
	l.Lock()
	defer l.Unlock()

	delete(l.roles, getKeyFromRole(role))
}

func (l *KubeClusterMonitor) OnTensorRole(tensorRole *assets.TensorRole, action assets.AssetsAction) error {
	role := tensorRole.Role
	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if role == nil {
			return nil
		}

		// send to the detection goroutine to detect in serialization
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case l.eventCh <- detectionEvent{
			role: role,
			kind: KindRole,
		}:
		case <-timer.C:
			logging.GetLogger().Warn().Msg("send eventCh timeout")
		}

		l.upsertRole(role)
	case assets.ActionDelete:
		if role == nil {
			return nil
		}
		l.deleteRole(role)
		l.storage.RemoveRole(role.GetName(), role.GetNamespace())
	}

	return nil
}

func (l *KubeClusterMonitor) OnTensorClusterRole(tensorRole *assets.TensorClusterRole, action assets.AssetsAction) error {
	clusterRole := tensorRole.ClusterRole
	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if clusterRole == nil {
			return nil
		}

		// send to the detection goroutine to detect in serialization
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case l.eventCh <- detectionEvent{
			clusterRole: clusterRole,
			kind:        KindClusterRole,
		}:
		case <-timer.C:
			logging.GetLogger().Warn().Msg("send eventCh timeout")
		}

		l.upsertClusterRole(clusterRole)
	case assets.ActionDelete:
		if clusterRole == nil {
			return nil
		}
		l.deleteRole(clusterRole)
		l.storage.RemoveClusterRole(clusterRole.GetName())
	}
	return nil
}

func (l *KubeClusterMonitor) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnHoneyspot(honeyspot *assets.TensorHoneySpot, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnTensorNamespace(namespace *assets.TensorNamespace, action assets.AssetsAction) error {
	return nil
}

func (l *KubeClusterMonitor) OnTensorNode(node *assets.TensorNode, action assets.AssetsAction) error {
	return nil
}

func (l *KubeClusterMonitor) AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string) {

}
func (l *KubeClusterMonitor) Name() string {
	return name
}
