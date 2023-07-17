package nodeinfo

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"strings"
	"sync"
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

func (pr *PodResInfo) OnAdd(newPod *PodEvent, containerInfo ContainerInfoManager) {
	owner := newPod.FinalOwnerResource(context.Background())
	pr.data.Store(getKey(newPod.Pod.Namespace, newPod.Pod.Name), newPod.FinalOwnerResource(context.Background()))
	logging.Get().Debug().Msgf("raw-container - add pod: %s/%s owner: %s/%s", newPod.Pod.Namespace, newPod.Pod.Name, owner.Kind, owner.Name)
	if newPod.Pod.Status.PodIP == "" {
		logging.Get().Debug().Str("raw-container", "add pod event").Msg("skip pod before ip address not yet allocated")
		return
	}

	var volumeMounts []model.Mounts
	for _, c := range newPod.Pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			volumeMounts = append(volumeMounts, model.Mounts{
				MountPath:   m.MountPath,
				SubPath:     m.SubPath,
				SubPathExpr: m.SubPathExpr,
			})
		}
	}
	pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionAdd, &model.TensorRawContainer{
		Namespace:    newPod.Pod.Namespace,
		PodName:      newPod.Pod.Name,
		PodUid:       string(newPod.Pod.UID),
		ResourceName: owner.Name,
		ResourceKind: owner.Kind,
		K8sManaged:   true,
		VolumeMounts: volumeMounts,
		IP:           newPod.Pod.Status.PodIP,
	})
}

func (pr *PodResInfo) OnDelete(oldPod *PodEvent) {
	pr.data.Delete(getKey(oldPod.Pod.Namespace, oldPod.Pod.Name))
}

func (pr *PodResInfo) OnUpdate(oldPod, newPod *PodEvent, containerInfo ContainerInfoManager) {
	owner := newPod.FinalOwnerResource(context.Background())
	logging.Get().Debug().Msgf("raw-container - update pod: %s/%s owner: %s/%s", newPod.Pod.Namespace, newPod.Pod.Name, owner.Kind, owner.Name)
	for _, status := range newPod.Pod.Status.ContainerStatuses {
		if status.State.Terminated != nil {
			containerID := strings.TrimPrefix(status.ContainerID, "docker://")
			pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionDelete, &model.TensorRawContainer{
				ContainerID:  containerID,
				Namespace:    newPod.Pod.Namespace,
				PodName:      newPod.Pod.Name,
				PodUid:       string(newPod.Pod.UID),
				ResourceName: owner.Name,
				ResourceKind: owner.Kind,
				K8sManaged:   true,
				Status:       assets.Exited,
				ClusterKey:   pr.clusterKey,
			})
		}
	}
	if newPod.Pod.Status.PodIP == "" {
		logging.Get().Debug().Str("raw-container", "update pod event").Msg("skip pod before ip address not yet allocated")
		return
	}

	var volumeMounts []model.Mounts
	for _, c := range newPod.Pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			volumeMounts = append(volumeMounts, model.Mounts{
				MountPath:   m.MountPath,
				SubPath:     m.SubPath,
				SubPathExpr: m.SubPathExpr,
			})
		}
	}
	pr.agent.HandlerContainerEvent(context.Background(), pr.clusterKey, assets.ActionUpdate, &model.TensorRawContainer{
		Namespace:    newPod.Pod.Namespace,
		PodName:      newPod.Pod.Name,
		PodUid:       string(newPod.Pod.UID),
		ResourceName: owner.Name,
		ResourceKind: owner.Kind,
		K8sManaged:   true,
		ClusterKey:   pr.clusterKey,
		VolumeMounts: volumeMounts,
		IP:           newPod.Pod.Status.PodIP,
	})
}

func (pr *PodResInfo) Name() string {
	return "pod_res_info_watcher"
}
