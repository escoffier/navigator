package kubemonitor

import (
	"context"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func NewMemStorage(clusterKey string) KubeStorage {
	return newMemStorage(clusterKey)
}

type KubeRiskyMonitor struct {
	outputChan     chan *KubeMonitorEvent
	storageFactory KubeStorageFactory
	rbRules        []*RiskyRoleItem
	resRules       []ResourceMonitorRule
}

func NewKubeRiskMonitor(conf Configuration, fac KubeStorageFactory) (*KubeRiskyMonitor, error) {
	m := KubeRiskyMonitor{
		outputChan:     make(chan *KubeMonitorEvent, 100),
		storageFactory: fac,
		rbRules:        conf.RBRules,
		resRules:       conf.ResourceRules,
	}
	return &m, nil
}
func (w *KubeRiskyMonitor) OutputChannel() <-chan *KubeMonitorEvent {
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
	cm.engine = NewEngine(w.rbRules, cm, cm.storage)
	cm.asyncDetection()
	return cm
}

func (w *KubeRiskyMonitor) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Roles2Watch:               {},
		assets.ClusterRoles2Watch:        {},
		assets.RoleBindings2Watch:        {},
		assets.ClusterRoleBindings2Watch: {},
		assets.TensorResources2Watch:     {},
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
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		for evt := range l.eventCh {
			l.detectEvent(context.Background(), evt)
		}
	}()
}

func (l *KubeClusterMonitor) sendToOutput(outputEvt *KubeMonitorEvent) {
	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case l.parent.outputChan <- outputEvt:
	case <-timer.C:
		logging.Get().Warn().Msgf("send output channel timeout for data: %+v", outputEvt)
	}
}

func GetRuleNameFromRBRule(item *RiskyRoleItem, kind string) string {
	sb := strings.Builder{}
	sb.WriteString(kind)
	sb.WriteByte(':')
	sb.WriteString(item.Metadata.Name)
	return sb.String()
}

func (l *KubeClusterMonitor) generateEventsFromClusterRole(role *rbacv1.ClusterRole, rules []*RiskyRoleItem) {
	if role == nil {
		return
	}

	for _, rule := range rules {
		evt := KubeMonitorEvent{
			ClusterKey: l.clusterKey,
			TargetObject: ResourceIdentifier{
				Name:       role.Name,
				Kind:       "clusterRole",
				Namespace:  "-",
				ClusterKey: l.clusterKey,
			},
			RuleName:   GetRuleNameFromRBRule(rule, "clusterRole"),
			ContextKVs: make([]ContextKV, 0, 3),
		}
		evt.ContextKVs = append(evt.ContextKVs, ContextKV{
			Key: "roleCreateTime",
			KeyMulti: map[string]string{
				"en": "Role Created Time",
				"zh": "Role创建时间",
			},
			DefaultValue: role.CreationTimestamp.Local().Format(time.RFC3339),
		})
		rulesBytes, err := json.Marshal(role.Rules)
		if err == nil {
			evt.ContextKVs = append(evt.ContextKVs, ContextKV{
				Key: "roleRules",
				KeyMulti: map[string]string{
					"en": "Role Rules",
					"zh": "Role规则",
				},
				DefaultValue: string(rulesBytes),
			})
		}
		labelBytes, err := yaml.Marshal(role.Labels)
		if err == nil {
			evt.ContextKVs = append(evt.ContextKVs, ContextKV{
				Key: "roleLabels",
				KeyMulti: map[string]string{
					"en": "Role Labels",
					"zh": "Role标签",
				},
				DefaultValue: string(labelBytes),
			})
		}
		l.sendToOutput(&evt)
	}
}

func (l *KubeClusterMonitor) generateEventsFromRole(role *rbacv1.Role, rules []*RiskyRoleItem) {
	if role == nil {
		return
	}

	for _, rule := range rules {
		evt := KubeMonitorEvent{
			ClusterKey: l.clusterKey,
			TargetObject: ResourceIdentifier{
				Name:       role.Name,
				Kind:       "role",
				Namespace:  role.Namespace,
				ClusterKey: l.clusterKey,
			},
			RuleName:   GetRuleNameFromRBRule(rule, "role"),
			ContextKVs: make([]ContextKV, 0, 3),
		}
		evt.ContextKVs = append(evt.ContextKVs, ContextKV{
			Key: "roleCreateTime",
			KeyMulti: map[string]string{
				"en": "Role Created Time",
				"zh": "Role创建时间",
			},
			DefaultValue: role.CreationTimestamp.Local().Format(time.RFC3339),
		})
		rulesBytes, err := json.Marshal(role.Rules)
		if err == nil {
			evt.ContextKVs = append(evt.ContextKVs, ContextKV{
				Key: "roleRules",
				KeyMulti: map[string]string{
					"en": "Role Rules",
					"zh": "Role规则",
				},
				DefaultValue: string(rulesBytes),
			})
		}
		labelBytes, err := yaml.Marshal(role.Labels)
		if err == nil {
			evt.ContextKVs = append(evt.ContextKVs, ContextKV{
				Key: "roleLabels",
				KeyMulti: map[string]string{
					"en": "Role Labels",
					"zh": "Role标签",
				},
				DefaultValue: string(labelBytes),
			})
		}

		l.sendToOutput(&evt)
	}
}

func (l *KubeClusterMonitor) detectEvent(ctx context.Context, evt detectionEvent) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic when consuming events: %v. event: %+v Stack: %s", r, evt, debug.Stack())
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
			l.generateEventsFromRole(evt.role, items)
		}
	case KindClusterRole:
		if evt.clusterRole == nil {
			return
		}
		risky, items := l.engine.IsRiskyClusterRole(evt.clusterRole)
		if risky {
			l.storage.SetClusterRoleRisky(evt.clusterRole.Name)
			l.generateEventsFromClusterRole(evt.clusterRole, items)
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
	if action == assets.ActionDelete { // ignore delation
		return nil
	}
	if newResource == nil {
		return nil
	}

	switch newResource.Kind {
	case "ReplicaSet":
		for _, or := range newResource.OwnerReferences {
			if or.Controller != nil && *or.Controller {
				if or.Kind == "Deployment" {
					logging.Get().Info().Str("name", newResource.Name).Str("kind", string(newResource.Kind)).Str("ns", newResource.Namespace).Msg("replicaset has deployment owner. ignored")
					return nil
				}
			}
		}
	case "Job":
		for _, or := range newResource.OwnerReferences {
			if or.Controller != nil && *or.Controller {
				if or.Kind == "CronJob" {
					logging.Get().Info().Str("name", newResource.Name).Str("kind", string(newResource.Kind)).Str("ns", newResource.Namespace).Msg("job has cronjob owner. ignored")
					return nil
				}
			}
		}
	}

	for _, rule := range l.parent.resRules {
		signals, err := rule.Match(context.Background(), newResource)
		if err == nil && len(signals) > 0 {
			for _, signal := range signals {
				evt := KubeMonitorEvent{
					ClusterKey: l.clusterKey,
					TargetObject: ResourceIdentifier{
						Name:       newResource.Name,
						Kind:       string(newResource.Kind),
						Namespace:  newResource.Namespace,
						ClusterKey: l.clusterKey,
					},
					RuleName:      rule.RuleName(),
					ContextKVs:    signal.Ctxs,
					ctxIdentifier: signal.CtxIdentifier,
				}
				l.sendToOutput(&evt)
			}

		}
	}
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
		defer timer.Stop()

		select {
		case l.eventCh <- detectionEvent{
			role: role,
			kind: KindRole,
		}:
		case <-timer.C:
			logging.Get().Warn().Msg("send eventCh timeout")
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

		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()

		select {
		case l.eventCh <- detectionEvent{
			clusterRole: clusterRole,
			kind:        KindClusterRole,
		}:
		case <-timer.C:
			logging.Get().Warn().Msg("send eventCh timeout")
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
