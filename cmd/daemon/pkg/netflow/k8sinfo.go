package netflow

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	NoneValue = "None"
)

type NodePodsInfo struct {
	resInfos      *sync.Map // map[string]*daemon.K8sResData
	k8sCli        *kubernetes.Clientset
	containerInfo nodeinfo.ContainerInfoManager
}

func NewNodePodInfo(cri nodeinfo.ContainerInfoManager, k8sCli *kubernetes.Clientset) *NodePodsInfo {
	info := &NodePodsInfo{
		resInfos:      new(sync.Map),
		k8sCli:        k8sCli,
		containerInfo: cri,
	}

	return info
}

func (n *NodePodsInfo) getContainerData(pod *corev1.Pod) (map[string]*daemon.ContainerData, error) {
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
		return nil, errors.Errorf("container id is nil, ns : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
	}

	return containerData, nil
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

	var err error
	var rsData daemon.K8sResData
	rsData.ContainerInfo, err = n.getContainerData(podEvt.Pod)
	if err != nil {
		return
	}
	res := podEvt.FinalOwnerResource(context.Background())
	rsData.OwnerName = res.Name
	rsData.Kind = res.Kind
	rsData.PodName = podEvt.Pod.Name
	rsData.Namespace = podEvt.Pod.Namespace
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

func (n *NodePodsInfo) UpdateContainerData(ip, ns, podName string) error {
	data, err := n.GetPodDataByPodIP(ip)
	if err != nil {
		return errors.Errorf("get pod info by ip failed, ns : %v, pod name : %v, %+v", ns, podName, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pod, err := n.k8sCli.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return errors.Errorf("get pod failed, ns : %v, pod name : %v, err : %+v", ns, podName, err)
	}

	data.ContainerInfo, err = n.getContainerData(pod)
	if err != nil {
		return errors.Errorf("update container failed, ns : %v, pod name : %v, %+v", ns, podName, err)
	}

	logging.Get().Debug().Msgf("update container id success, ns : %v, pod name : %v.", ns, podName)
	return nil
}
