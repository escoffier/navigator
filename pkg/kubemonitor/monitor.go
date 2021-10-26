package kubemonitor

import (
	"context"
	"fmt"
	"runtime/debug"
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

func NewMemStorage(clusterName string) KubeStorage {
	return newMemStorage(clusterName)
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
func (w *KubeRiskyMonitor) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncTTL time.Duration) assets.ClusterCallback {
	cm := &KubeClusterMonitor{
		clusterName:  clusterName,
		parent:       w,
		storage:      w.storageFactory(clusterName),
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
	clusterName  string
	clusterRoles map[string]*rbacv1.ClusterRole // name -> Role
	roles        map[string]*rbacv1.Role        // namespace/name -> Role
	eventCh      chan detectionEvent
}

func (api *KubeClusterMonitor) asyncDetection() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		for evt := range api.eventCh {
			api.detectEvent(context.Background(), evt)
		}
	}()
}

func (api *KubeClusterMonitor) sendToOutput(outputEvt KubeMonitorEvent) {
	outputEvt.Cluster = api.clusterName

	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case api.parent.outputChan <- outputEvt:
	case <-timer.C:
		logging.GetLogger().Warn().Msgf("send output channel timeout for data: %+v", outputEvt)
	}
}
func (api *KubeClusterMonitor) detectEvent(ctx context.Context, evt detectionEvent) {
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
		risky, items := api.engine.IsRiskyRole(evt.role)
		if risky {
			api.storage.SetRoleRisky(evt.role.Name, evt.role.Namespace)
			api.sendToOutput(KubeMonitorEvent{
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
		risky, items := api.engine.IsRiskyClusterRole(evt.clusterRole)
		if risky {
			api.storage.SetClusterRoleRisky(evt.clusterRole.Name)
			api.sendToOutput(KubeMonitorEvent{
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

func (api *KubeClusterMonitor) GetClusterRole(name string) (*rbacv1.ClusterRole, bool) {
	api.RLock()
	defer api.RUnlock()

	cr, ok := api.clusterRoles[name]
	return cr, ok
}
func (api *KubeClusterMonitor) GetRole(name, namespace string) (*rbacv1.Role, bool) {
	api.RLock()
	defer api.RUnlock()

	r, ok := api.roles[getKeyFromNameAndNS(namespace, name)]
	return r, ok
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
	return getKeyFromNameAndNS(r.GetName(), r.GetNamespace())
}

func getKeyFromNameAndNS(name, namespace string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
func (l *KubeClusterMonitor) deleteRole(role RoleInterface) {
	l.Lock()
	defer l.Unlock()

	delete(l.roles, getKeyFromRole(role))
}

func (l *KubeClusterMonitor) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if newRole == nil {
			return nil
		}

		// send to the detection goroutine to detect in serialization
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case l.eventCh <- detectionEvent{
			role: newRole,
			kind: KindRole,
		}:
		case <-timer.C:
			logging.GetLogger().Warn().Msg("send eventCh timeout")
		}
		// send to the detection goroutine to detect in serialization
		l.eventCh <- detectionEvent{
			role: newRole,
			kind: KindRole,
		}

		l.upsertRole(newRole)
	case assets.ActionDelete:
		if oldRole == nil {
			return nil
		}
		l.deleteRole(oldRole)
		l.storage.RemoveRole(oldRole.GetName(), oldRole.GetNamespace())
	}

	return nil
}
func (l *KubeClusterMonitor) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		if newCRole == nil {
			return nil
		}

		// send to the detection goroutine to detect in serialization
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case l.eventCh <- detectionEvent{
			clusterRole: newCRole,
			kind:        KindClusterRole,
		}:
		case <-timer.C:
			logging.GetLogger().Warn().Msg("send eventCh timeout")
		}

		l.upsertClusterRole(newCRole)
	case assets.ActionDelete:
		if oldCRole == nil {
			return nil
		}
		l.deleteRole(oldCRole)
		l.storage.RemoveClusterRole(oldCRole.GetName())
	}
	return nil
}
func (l *KubeClusterMonitor) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.AssetsAction) error {
	return nil
}
func (l *KubeClusterMonitor) AfterDataSynced(ctx context.Context, dataSynced bool) {

}
func (l *KubeClusterMonitor) Name() string {
	return name
}
