package nodeinfo

import (
	"context"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodResInfo struct {
	data       *sync.Map // {namespace}/{podName} -> Resource
	agent      *containerassets.Agent
	clusterKey string
}

func NewPodResInfo(agent *containerassets.Agent, clusterKey string) *PodResInfo {
	return &PodResInfo{
		data:       new(sync.Map),
		agent:      agent,
		clusterKey: clusterKey,
	}
}

func (pr *PodResInfo) GetPod(namespace, name string) (*Resource, bool) {
	obj, exist := pr.data.Load(getKey(namespace, name))
	if !exist || obj == nil {
		return nil, false
	}
	return obj.(*Resource), true
}

func (pr *PodResInfo) OnAdd(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		logging.Get().Debug().Str("raw-container", "add pod event").Msg("skip pod before ip address not yet allocated")
		return
	}
	key, _ := cache.MetaNamespaceKeyFunc(pod)
	var owner *Resource = &Resource{}
	owner.Name, owner.Kind = util.GetOwnerOfPod(pod)
	pr.data.Store(key, owner)
	logging.Get().Debug().Msgf("raw-container - add pod: %s/%s owner: %s/%s", pod.Namespace, pod.Name, owner.Kind, owner.Name)

	var volumeMounts []model.Mounts
	for _, c := range pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			volumeMounts = append(volumeMounts, model.Mounts{
				MountPath:   m.MountPath,
				SubPath:     m.SubPath,
				SubPathExpr: m.SubPathExpr,
			})
		}
	}
	pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionAdd, &assets.TensorRawContainer{TensorRawContainer: &model.TensorRawContainer{
		Namespace:    pod.Namespace,
		PodName:      pod.Name,
		PodUid:       string(pod.UID),
		ResourceName: owner.Name,
		ResourceKind: owner.Kind,
		K8sManaged:   true,
		VolumeMounts: volumeMounts,
		IP:           pod.Status.PodIP,
	}})
}

func (pr *PodResInfo) OnDelete(pod *corev1.Pod) {
	pr.data.Delete(getKey(pod.Namespace, pod.Name))
}

func (pr *PodResInfo) OnUpdate(oldPod, newPod *corev1.Pod) {
	var owner Resource
	owner.Name, owner.Kind = util.GetOwnerOfPod(newPod)
	logging.Get().Debug().Msgf("raw-container - update pod: %s/%s owner: %s/%s", newPod.Namespace, newPod.Name, owner.Kind, owner.Name)
	for _, status := range newPod.Status.ContainerStatuses {
		if status.State.Terminated != nil {
			containerID := strings.TrimPrefix(status.ContainerID, "docker://")
			pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionDelete, &assets.TensorRawContainer{TensorRawContainer: &model.TensorRawContainer{
				ContainerID:  containerID,
				Namespace:    newPod.Namespace,
				PodName:      newPod.Name,
				PodUid:       string(newPod.UID),
				ResourceName: owner.Name,
				ResourceKind: owner.Kind,
				K8sManaged:   true,
				Status:       assets.Exited,
				ClusterKey:   pr.clusterKey,
			}})
		}
	}
	if newPod.Status.PodIP == "" {
		logging.Get().Debug().Str("raw-container", "update pod event").Msg("skip pod before ip address not yet allocated")
		return
	}

	var volumeMounts []model.Mounts
	for _, c := range newPod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			volumeMounts = append(volumeMounts, model.Mounts{
				MountPath:   m.MountPath,
				SubPath:     m.SubPath,
				SubPathExpr: m.SubPathExpr,
			})
		}
	}
	pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionUpdate, &assets.TensorRawContainer{TensorRawContainer: &model.TensorRawContainer{
		Namespace:    newPod.Namespace,
		PodName:      newPod.Name,
		PodUid:       string(newPod.UID),
		ResourceName: owner.Name,
		ResourceKind: owner.Kind,
		K8sManaged:   true,
		ClusterKey:   pr.clusterKey,
		VolumeMounts: volumeMounts,
		IP:           newPod.Status.PodIP,
	}})
}

func (pr *PodResInfo) Name() string {
	return "pod_res_info_watcher"
}
