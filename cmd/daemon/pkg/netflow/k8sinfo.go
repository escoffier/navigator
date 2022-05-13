package netflow

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
)

const (
	NoneValue = "None"
)

type NodePodsInfo struct {
	resInfos      *sync.Map // map[string]*daemon.K8sResData
	containerInfo nodeinfo.ContainerInfoManager
}

func NewNodePodInfo(containerInfo nodeinfo.ContainerInfoManager) *NodePodsInfo {
	info := &NodePodsInfo{
		resInfos:      new(sync.Map),
		containerInfo: containerInfo,
	}

	return info
}

func (n *NodePodsInfo) getContainerData(pod *corev1.Pod) map[string]*daemon.ContainerData {
	containerData := make(map[string]*daemon.ContainerData, len(pod.Status.ContainerStatuses))

	for _, container := range pod.Status.ContainerStatuses {
		if len(pod.Status.ContainerStatuses) != 1 {
			running := container.State.Running
			if running == nil {
				continue
			}
		}

		cPid, id, err := n.containerInfo.GetContainerPid(container.ContainerID)
		if len(container.Name) == 0 || err != nil {
			logging.Get().Warn().Msgf("get container info failed, namespace : %v, pod name : %v. err: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}

		//save container information
		containerData[id] = &daemon.ContainerData{
			ContainerName: container.Name,
			ContainerPid:  cPid,
		}
	}

	if len(containerData) == 0 {
		logging.Get().Warn().Msgf("get container id failed, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
	}

	return containerData
}
func (n *NodePodsInfo) OnAdd(newPod *nodeinfo.PodEvent) {
	if newPod.Pod == nil {
		return
	}
	if newPod.Pod.Spec.HostNetwork || newPod.Pod.Status.PodIP == "" || newPod.Pod.Status.PodIP == NoneValue {
		return
	}

	n.savePodData(newPod)
}

func (n *NodePodsInfo) OnDelete(oldPod *nodeinfo.PodEvent) {
	if oldPod.Pod == nil {
		return
	}
	if oldPod.Pod.Spec.HostNetwork || oldPod.Pod.Status.PodIP == "" || oldPod.Pod.Status.PodIP == NoneValue {
		return
	}
	n.deletePodResData(oldPod.Pod.Status.PodIP)
}

func (n *NodePodsInfo) OnUpdate(oldPod, newPod *nodeinfo.PodEvent) {
	n.OnAdd(newPod)
}

func (n *NodePodsInfo) Name() string {
	return "netflow_watcher"
}

func (n *NodePodsInfo) savePodData(podEvt *nodeinfo.PodEvent) {
	if podEvt.Pod == nil {
		return
	}

	podIP := podEvt.Pod.Status.PodIP
	_, ok := n.resInfos.Load(podIP)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	res := podEvt.FinalOwnerResource(context.Background())
	rsData.OwnerName = res.Name
	rsData.Kind = res.Kind
	rsData.PodName = podEvt.Pod.Name
	rsData.Namespace = podEvt.Pod.Namespace
	rsData.ContainerInfo = n.getContainerData(podEvt.Pod)
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo, 2)

	n.resInfos.LoadOrStore(podIP, &rsData)
}

func (n *NodePodsInfo) deletePodResData(ip string) {
	if len(ip) == 0 {
		return
	}

	n.resInfos.Delete(ip)
}

func (n *NodePodsInfo) GetPodDataByPodIP(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, errors.Errorf("ip address is error")
	}

	v, ok := n.resInfos.Load(ip)
	if !ok {
		return nil, errors.Errorf("can not find k8s resource data by %s", ip)
	}

	return v.(*daemon.K8sResData), nil
}
