package assets

import (
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

/*
TensorResource is an abstract concept: it's a general abstraction of the deployment unit in a kubernetes cluster. They are all pod controllers or the controller of the controller of pods.
It could be a ReplicaSet, DaemonSet, StatefulSet, ReplicationController, Deployment, Job. The Kind field will identify the type of it.
All fields are immutable.
*/
type TensorResource struct {
	Kind            ResourceKind
	Cluster         string
	Namespace       string
	Name            string
	UID             string
	originRef       interface{} // the original object
	LabelSelector   *metav1.LabelSelector
	OwnerReferences []metav1.OwnerReference
	Labels          map[string]string
	PodTemplate     *corev1.PodTemplateSpec
	CreateTime      time.Time
}

func newResourceFromPodNoOwner(cluster string, pod *corev1.Pod) *TensorResource {
	if pod == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindPodNoOwner,
		Cluster:         cluster,
		Namespace:       pod.Namespace,
		Name:            pod.Name,
		UID:             string(pod.UID),
		originRef:       pod,
		LabelSelector:   nil,
		OwnerReferences: pod.OwnerReferences,
		Labels:          pod.Labels,
		PodTemplate:     &corev1.PodTemplateSpec{Spec: pod.Spec},
		CreateTime:      pod.CreationTimestamp.Time,
	}
	return &res
}
func newResourceFromReplicationController(cluster string, rs *corev1.ReplicationController) *TensorResource {
	if rs == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindReplicationController,
		Cluster:         cluster,
		Namespace:       rs.Namespace,
		Name:            rs.Name,
		UID:             string(rs.UID),
		originRef:       rs,
		LabelSelector:   &metav1.LabelSelector{MatchLabels: rs.Spec.Selector},
		OwnerReferences: rs.OwnerReferences,
		Labels:          rs.Labels,
		PodTemplate:     rs.Spec.Template,
		CreateTime:      rs.CreationTimestamp.Time,
	}
	return &res
}

func newResourceFromReplicaSet(cluster string, rs *appsv1.ReplicaSet) *TensorResource {
	if rs == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindReplicaSet,
		Cluster:         cluster,
		Namespace:       rs.Namespace,
		Name:            rs.Name,
		UID:             string(rs.UID),
		originRef:       rs,
		LabelSelector:   rs.Spec.Selector,
		OwnerReferences: rs.OwnerReferences,
		Labels:          rs.Labels,
		PodTemplate:     &rs.Spec.Template,
		CreateTime:      rs.CreationTimestamp.Time,
	}
	return &res
}

func newResourceFromStatefulSet(cluster string, ss *appsv1.StatefulSet) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindStatefulSet,
		Cluster:         cluster,
		Namespace:       ss.Namespace,
		Name:            ss.Name,
		UID:             string(ss.UID),
		originRef:       ss,
		LabelSelector:   ss.Spec.Selector,
		OwnerReferences: ss.OwnerReferences,
		Labels:          ss.Labels,
		PodTemplate:     &ss.Spec.Template,
		CreateTime:      ss.CreationTimestamp.Time,
	}
	return &res
}

func newResourceFromDaemonSet(cluster string, ss *appsv1.DaemonSet) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindDaemonSet,
		Cluster:         cluster,
		Namespace:       ss.Namespace,
		Name:            ss.Name,
		UID:             string(ss.UID),
		originRef:       ss,
		LabelSelector:   ss.Spec.Selector,
		OwnerReferences: ss.OwnerReferences,
		Labels:          ss.Labels,
		PodTemplate:     &ss.Spec.Template,
		CreateTime:      ss.CreationTimestamp.Time,
	}
	return &res
}

func newResourceFromDeployment(cluster string, ss *appsv1.Deployment) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindDeployment,
		Cluster:         cluster,
		Namespace:       ss.Namespace,
		Name:            ss.Name,
		UID:             string(ss.UID),
		originRef:       ss,
		LabelSelector:   ss.Spec.Selector,
		OwnerReferences: ss.OwnerReferences,
		Labels:          ss.Labels,
		PodTemplate:     &ss.Spec.Template,
		CreateTime:      ss.CreationTimestamp.Time,
	}
	return &res
}
func newResourceFromCronJob(cluster string, ss *batchv1beta.CronJob) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindCronJob,
		Cluster:         cluster,
		Namespace:       ss.Namespace,
		Name:            ss.Name,
		UID:             string(ss.UID),
		originRef:       ss,
		LabelSelector:   ss.Spec.JobTemplate.Spec.Selector,
		OwnerReferences: ss.OwnerReferences,
		Labels:          ss.Labels,
		PodTemplate:     &ss.Spec.JobTemplate.Spec.Template,
		CreateTime:      ss.CreationTimestamp.Time,
	}
	return &res
}

func newResourceFromJob(cluster string, ss *batchv1.Job) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		Kind:            KindJob,
		Cluster:         cluster,
		Namespace:       ss.Namespace,
		Name:            ss.Name,
		UID:             string(ss.UID),
		originRef:       ss,
		LabelSelector:   ss.Spec.Selector,
		OwnerReferences: ss.OwnerReferences,
		Labels:          ss.Labels,
		PodTemplate:     &ss.Spec.Template,
		CreateTime:      ss.CreationTimestamp.Time,
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
