package assets

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// NodeIsReady 检查node是否处于ready状态
// 只有当node的`存在`Ready状态且为true，且磁盘空间压力、内存压力、进程压力、网络配置都为false时 nodes才算可用。
// https://kubernetes.io/zh/docs/concepts/architecture/nodes/#condition
func NodeIsReady(node *corev1.Node) bool {
	var isReady bool
	for _, v := range node.Status.Conditions {
		switch v.Type {
		case corev1.NodeReady:
			// 只有当存在 Ready 条件，且此条件为true时，节点才可用
			if v.Status == corev1.ConditionTrue {
				isReady = true
			} else {
				return false
			}

		case corev1.NodeDiskPressure, corev1.NodeMemoryPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable:
			// 当资源压力不为false时，即为true或者unknown时，表示节点不可用
			if v.Status != corev1.ConditionFalse {
				return false
			}
		}
	}

	return isReady
}

func PureObject(object interface{}) interface{} {
	key1 := "kubectl.kubernetes.io/last-applied-configuration"
	switch o := object.(type) {
	case *appsv1.Deployment:
		o.APIVersion = ResourceKindApiVersion[KindDeployment]
		o.Kind = string(KindDeployment)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = appsv1.DeploymentStatus{}
		object = o
	case *appsv1.DaemonSet:
		o.APIVersion = ResourceKindApiVersion[KindDaemonSet]
		o.Kind = string(KindDaemonSet)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = appsv1.DaemonSetStatus{}
		object = o
	case *appsv1.ReplicaSet:
		o.APIVersion = ResourceKindApiVersion[KindReplicaSet]
		o.Kind = string(KindReplicaSet)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = appsv1.ReplicaSetStatus{}
		object = o
	case *appsv1.StatefulSet:
		o.APIVersion = ResourceKindApiVersion[KindStatefulSet]
		o.Kind = string(KindStatefulSet)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = appsv1.StatefulSetStatus{}
		object = o
	case *corev1.ReplicationController:
		o.APIVersion = ResourceKindApiVersion[KindReplicationController]
		o.Kind = string(KindReplicationController)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = corev1.ReplicationControllerStatus{}
		object = o
	case *batchv1.Job:
		o.APIVersion = ResourceKindApiVersion[KindJob]
		o.Kind = string(KindJob)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = batchv1.JobStatus{}
		object = o
	case *v1beta1.CronJob:
		o.APIVersion = ResourceKindApiVersion[KindCronJob]
		o.Kind = string(KindCronJob)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = v1beta1.CronJobStatus{}
		object = o
	case *batchv1.CronJob:
		o.APIVersion = ResourceKindApiVersion[KindCronJob]
		o.Kind = string(KindCronJob)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = batchv1.CronJobStatus{}
		object = o
	case *corev1.Pod:
		o.APIVersion = ResourceKindApiVersion[KindPodNoOwner]
		o.Kind = string(KindPodNoOwner)
		o.ObjectMeta.SetManagedFields(nil)
		annotations := o.ObjectMeta.GetAnnotations()
		delete(annotations, key1)
		o.ObjectMeta.SetAnnotations(annotations)
		o.Status = corev1.PodStatus{}
		object = o
	}
	return object
}
