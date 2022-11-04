package assets

import (
	// don't replace it; need the order of fields for marshal
	"encoding/json"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
)

type ResourceKind string

const (
	KindReplicaSet            ResourceKind = "ReplicaSet"
	KindDaemonSet             ResourceKind = "DaemonSet"
	KindStatefulSet           ResourceKind = "StatefulSet"
	KindReplicationController ResourceKind = "ReplicationController"
	KindDeployment            ResourceKind = "Deployment"
	KindJob                   ResourceKind = "Job"
	KindCronJob               ResourceKind = "CronJob"
	KindPodNoOwner            ResourceKind = "Pod"
)

type ConvertFunc func(cluster string, wl interface{}) *TensorResource

var TensorResourceFuncs = map[ResourceKind]ConvertFunc{
	KindDeployment:            NewResourceFromDeployment,
	KindReplicaSet:            NewResourceFromReplicaSet,
	KindDaemonSet:             ResourceFromDaemonSet,
	KindStatefulSet:           NewResourceFromStatefulSet,
	KindReplicationController: NewResourceFromReplicationController,
	KindJob:                   NewResourceFromJob,
	KindCronJob:               NewResourceFromCronJob,
}

/*
TensorResource is an abstract concept: it's a general abstraction of the deployment unit in a kubernetes cluster. They are all pod controllers or the controller of the controller of pods.
It could be a ReplicaSet, DaemonSet, StatefulSet, ReplicationController, Deployment, Job. The Kind field will identify the type of it.
All fields are immutable.
*/
type TensorResource struct {
	metav1.ObjectMeta
	Cluster       string                  `json:"cluster"`
	Kind          ResourceKind            `json:"kind"`
	originRef     interface{}             `json:"origin_ref"` // the original object
	LabelSelector *metav1.LabelSelector   `json:"label_selector"`
	PodTemplate   *corev1.PodTemplateSpec `json:"pod_template"`
	CreateTime    time.Time               `json:"create_time"`
	dupChecked    bool
}

func (r *TensorResource) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (r *TensorResource) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorResource) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(r.Cluster)
	sb.WriteRune('\n')
	sb.WriteString(string(r.Kind))
	sb.WriteRune('\n')
	sb.WriteString(r.Name)
	sb.WriteRune('\n')
	sb.WriteString(r.Namespace)
	return sb.String()
}
func (r *TensorResource) IdentityString() string {
	sb := strings.Builder{}
	if r.PodTemplate != nil {
		specBytes, err := json.Marshal(r.PodTemplate.Spec)
		if err == nil {
			sb.WriteString(string(specBytes))
		}
	}
	return sb.String()
}

type PoolInfo struct {
	PoolName    string `json:"poolName"`
	PoolUID     string `json:"poolUID"`
	PoolPodName string `json:"poolPodName"`
	PoolPodUID  string `json:"poolPodUID"`
}

type TensorPod struct {
	*corev1.Pod
	Cluster    string                 `json:"cluster"`
	Owner      *metav1.OwnerReference `json:"owner"`
	PoolInfo   *PoolInfo              `json:"poolInfo"`
	dupChecked bool
}

func (r *TensorPod) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorPod) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (p *TensorPod) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Pod")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}
func (p *TensorPod) IdentityString() string {
	sb := strings.Builder{}
	podSpecBytes, err := json.Marshal(p.Spec)
	if err == nil {
		sb.WriteString(string(podSpecBytes))
	}
	return sb.String()
}

type TensorRole struct {
	Cluster string
	*rbacv1.Role
	dupChecked bool
}

func (r *TensorRole) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorRole) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (p *TensorRole) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Role")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}
func (p *TensorRole) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(p.ResourceVersion)
	return sb.String()
}

type TensorClusterRole struct {
	Cluster string
	*rbacv1.ClusterRole
	dupChecked bool
}

func (r *TensorClusterRole) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorClusterRole) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (p *TensorClusterRole) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Role")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}
func (p *TensorClusterRole) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(p.ResourceVersion)
	return sb.String()
}

type TensorNamespace struct {
	Cluster string
	*corev1.Namespace
	dupChecked bool
}

func (r *TensorNamespace) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorNamespace) SetDuplicatedChecked(c bool) {
	r.dupChecked = c
}
func (p *TensorNamespace) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Namespace")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	return sb.String()
}
func (p *TensorNamespace) IdentityString() string {
	return ""
}

type TensorNode struct {
	Cluster string
	*corev1.Node
	dupChecked bool
}

func (r *TensorNode) DuplicatedChecked() bool {
	return r.dupChecked
}
func (p *TensorNode) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Node")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	return sb.String()
}

func (r *TensorNode) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (p *TensorNode) TailorSelf() {
	p.Spec = corev1.NodeSpec{}
	p.Status = corev1.NodeStatus{
		Phase:      p.Status.Phase,
		Addresses:  p.Status.Addresses,
		NodeInfo:   p.Status.NodeInfo,
		Conditions: p.Status.Conditions,
	}
}
func (p *TensorNode) IdentityString() string {
	sb := strings.Builder{}
	// specBytes, err := json.Marshal(p.Spec)
	// if err == nil {
	// 	sb.WriteString(string(specBytes))
	// }
	// sb.WriteRune('\n')
	sb.WriteString(string(p.Status.Phase))
	sb.WriteRune('\n')
	condBytes, err := json.Marshal(p.Status.Conditions)
	if err == nil {
		sb.WriteString(string(condBytes))
	}
	sb.WriteRune('\n')

	addrBytes, err := json.Marshal(p.Status.Addresses)
	if err == nil {
		sb.WriteString(string(addrBytes))
	}
	sb.WriteRune('\n')
	ninfo, err := json.Marshal(p.Status.NodeInfo)
	if err == nil {
		sb.WriteString(string(ninfo))
	}

	return sb.String()
}

type TensorHoneySpot struct {
	Cluster string
	*defensev1.Honeypot
	dupChecked bool
}

func (r *TensorHoneySpot) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorHoneySpot) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (r *TensorHoneySpot) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(r.Cluster)
	sb.WriteRune('\n')
	sb.WriteString(string(r.Kind))
	sb.WriteRune('\n')
	sb.WriteString(r.Name)
	sb.WriteRune('\n')
	sb.WriteString(r.Namespace)
	return sb.String()
}
func (r *TensorHoneySpot) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(r.ResourceVersion)
	return sb.String()
}

func NewResourceFromPodNoOwnerOrStaticPod(cluster string, pod *corev1.Pod) *TensorResource {
	if pod == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta:    *pod.ObjectMeta.DeepCopy(),
		Kind:          KindPodNoOwner,
		Cluster:       cluster,
		originRef:     pod,
		LabelSelector: nil,
		//OwnerReferences: pod.OwnerReferences,
		//Labels:          pod.Labels,
		PodTemplate: &corev1.PodTemplateSpec{Spec: pod.Spec},
		CreateTime:  pod.CreationTimestamp.Time,
	}
	return &res
}
func NewResourceFromReplicationController(cluster string, wl interface{}) *TensorResource {
	rs := wl.(*corev1.ReplicationController)
	if rs == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *rs.ObjectMeta.DeepCopy(),
		Kind:       KindReplicationController,
		Cluster:    cluster,
		//UID:           string(rs.UID),
		originRef:     rs,
		LabelSelector: &metav1.LabelSelector{MatchLabels: rs.Spec.Selector},
		//OwnerReferences: rs.OwnerReferences,
		//Labels:          rs.Labels,
		PodTemplate: rs.Spec.Template,
		CreateTime:  rs.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromReplicaSet(cluster string, wl interface{}) *TensorResource {
	rs, ok := wl.(*appsv1.ReplicaSet)
	if !ok {
		return nil
	}
	if rs == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *rs.ObjectMeta.DeepCopy(),
		Kind:       KindReplicaSet,
		Cluster:    cluster,
		//Namespace:       rs.Namespace,
		//Name:            rs.Name,
		//UID:           string(rs.UID),
		originRef:     rs,
		LabelSelector: rs.Spec.Selector,
		//OwnerReferences: rs.OwnerReferences,
		//Labels:          rs.Labels,
		PodTemplate: &rs.Spec.Template,
		CreateTime:  rs.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromStatefulSet(cluster string, obj interface{}) *TensorResource {
	ss, ok := obj.(*appsv1.StatefulSet)
	if !ok {
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindStatefulSet,
		Cluster:    cluster,
		//Namespace:       ss.Namespace,
		//Name:            ss.Name,
		//UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		//OwnerReferences: ss.OwnerReferences,
		//Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func ResourceFromDaemonSet(cluster string, wl interface{}) *TensorResource {
	ds := wl.(*appsv1.DaemonSet)
	return NewResourceFromDaemonSet(cluster, ds)
}

func NewResourceFromDaemonSet(cluster string, ss *appsv1.DaemonSet) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindDaemonSet,
		Cluster:    cluster,
		//Namespace:       ss.Namespace,
		//Name:            ss.Name,
		//UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		//OwnerReferences: ss.OwnerReferences,
		//Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromDeployment(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*appsv1.Deployment)
	if !ok {
		logging.Get().Error().Msg("not deployment")
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindDeployment,
		Cluster:    cluster,
		//UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		//OwnerReferences: ss.OwnerReferences,
		//Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}
func NewResourceFromCronJob(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*batchv1beta.CronJob)
	if !ok {
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindCronJob,
		Cluster:    cluster,
		//Namespace:       ss.Namespace,
		//Name:            ss.Name,
		//UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.JobTemplate.Spec.Selector,
		//OwnerReferences: ss.OwnerReferences,
		//Labels:          ss.Labels,
		PodTemplate: &ss.Spec.JobTemplate.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromJob(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*batchv1.Job)
	if !ok {
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindJob,
		Cluster:    cluster,
		//Namespace:       ss.Namespace,
		//Name:            ss.Name,
		//UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		//OwnerReferences: ss.OwnerReferences,
		//Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func (r *TensorResource) GetReplicaSet() (*appsv1.ReplicaSet, bool) {
	rs, ok := r.originRef.(*appsv1.ReplicaSet)
	return rs, ok
}

func (r *TensorResource) GetDaemonSet() (*appsv1.DaemonSet, bool) {
	rs, ok := r.originRef.(*appsv1.DaemonSet)
	return rs, ok
}

func (r *TensorResource) GetStatefulSet() (*appsv1.StatefulSet, bool) {
	rs, ok := r.originRef.(*appsv1.StatefulSet)
	return rs, ok
}

func (r *TensorResource) GetDeployment() (*appsv1.Deployment, bool) {
	rs, ok := r.originRef.(*appsv1.Deployment)
	return rs, ok
}

func (r *TensorResource) GetJob() (*batchv1.Job, bool) {
	rs, ok := r.originRef.(*batchv1.Job)
	return rs, ok
}

func (r *TensorResource) GetCronJob() (*batchv1beta.CronJob, bool) {
	rs, ok := r.originRef.(*batchv1beta.CronJob)
	return rs, ok
}

func (r *TensorResource) GetPod() (*corev1.Pod, bool) {
	rs, ok := r.originRef.(*corev1.Pod)
	return rs, ok
}

func (r *TensorResource) GetReplicationController() (*corev1.ReplicationController, bool) {
	rs, ok := r.originRef.(*corev1.ReplicationController)
	return rs, ok
}
