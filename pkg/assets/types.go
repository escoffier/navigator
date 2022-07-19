package assets

import (
	"gitlab.com/security-rd/go-pkg/logging"
	rbacv1 "k8s.io/api/rbac/v1"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
}

type PoolInfo struct {
	PoolName    string `json:"poolName"`
	PoolUID     string `json:"poolUID"`
	PoolPodName string `json:"poolPodName"`
	PoolPodUID  string `json:"poolPodUID"`
}

type TensorPod struct {
	*corev1.Pod
	Cluster  string                 `json:"cluster"`
	Owner    *metav1.OwnerReference `json:"owner"`
	PoolInfo *PoolInfo              `json:"poolInfo"`
}

type TensorRole struct {
	Cluster string
	*rbacv1.Role
}

type TensorClusterRole struct {
	Cluster string
	*rbacv1.ClusterRole
}

type TensorNamespace struct {
	Cluster string
	*corev1.Namespace
}

type TensorNode struct {
	Cluster string
	*corev1.Node
}

type TensorHoneySpot struct {
	Cluster string
	*defensev1.Honeypot
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
