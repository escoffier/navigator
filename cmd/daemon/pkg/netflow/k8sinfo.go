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
	resInfos *sync.Map // map[string]*daemon.K8sResData
	k8sCli   *kubernetes.Clientset
}

func NewNodePodInfo(k8sCli *kubernetes.Clientset) *NodePodsInfo {
	info := &NodePodsInfo{
		resInfos: new(sync.Map),
		k8sCli:   k8sCli,
	}

	return info
}

func (n *NodePodsInfo) getContainerData(pod *corev1.Pod, containerInfo nodeinfo.ContainerInfoManager) (map[string]*daemon.ContainerData, error) {
	containerData := make(map[string]*daemon.ContainerData)

	for _, container := range pod.Status.ContainerStatuses {
		if len(pod.Status.ContainerStatuses) != 1 {
			running := container.State.Running
			if running == nil {
				continue
			}
		}
		//check container id
		if len(container.ContainerID) == 0 {
			logging.Get().Warn().Msgf("container is nil, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
			continue
		}
		//get container pid
		cPid, id, err := containerInfo.GetContainerPid(container.ContainerID)
		if len(container.Name) == 0 || err != nil {
			logging.Get().Warn().Msgf("get container info failed, namespace : %v, pod name : %v. err: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}
		//print debug log
		//if pod.GetNamespace() == "testzfc" {
		//	logging.Get().Info().Msgf("pod name : %+v, id : %+v, container name : %+v.", pod.GetName(), id, container.Name)
		//}
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

func (n *NodePodsInfo) OnAdd(newPod *nodeinfo.PodEvent, containerInfo nodeinfo.ContainerInfoManager) {
	if newPod.Pod == nil {
		return
	}

	if newPod.Pod.Spec.HostNetwork || newPod.Pod.Status.PodIP == "" || newPod.Pod.Status.PodIP == NoneValue {
		return
	}

	n.savePodData(newPod, containerInfo)
}

func (n *NodePodsInfo) OnDelete(oldPod *nodeinfo.PodEvent) {
	if oldPod.Pod == nil {
		return
	}

	if oldPod.Pod.Spec.HostNetwork || oldPod.Pod.Status.PodIP == "" || oldPod.Pod.Status.PodIP == NoneValue {
		return
	}
	n.DeleteResData(oldPod.Pod.Status.PodIP)
}

func (n *NodePodsInfo) OnUpdate(oldPod, newPod *nodeinfo.PodEvent, containerInfo nodeinfo.ContainerInfoManager) {
	n.OnAdd(newPod, containerInfo)
}

func (n *NodePodsInfo) Name() string {
	return "netflow_watcher"
}

func (n *NodePodsInfo) savePodData(podEvt *nodeinfo.PodEvent, containerInfo nodeinfo.ContainerInfoManager) {
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
	rsData.ContainerInfo, err = n.getContainerData(podEvt.Pod, containerInfo)
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

func (n *NodePodsInfo) DeleteResData(ip string) {
	if len(ip) == 0 {
		return
	}

	n.resInfos.Delete(ip)
}

func (n *NodePodsInfo) SaveContainerData(ip, containerId string, container *daemon.ContainerData) {
	if len(ip) == 0 || len(containerId) == 0 || container == nil {
		return
	}

	_, ok := n.resInfos.Load(ip)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	rsData.ContainerInfo = make(map[string]*daemon.ContainerData, 1)
	rsData.ContainerInfo[containerId] = container
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo, 2)
	// save
	n.resInfos.LoadOrStore(ip, &rsData)
}

func (n *NodePodsInfo) GetResDataByIp(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, errors.Errorf("ip address is error")
	}

	v, ok := n.resInfos.Load(ip)
	if !ok {
		return nil, errors.Errorf("can not find k8s resource data by %s", ip)
	}

	return v.(*daemon.K8sResData), nil
}

func (n *NodePodsInfo) UpdateContainerData(crim nodeinfo.ContainerInfoManager, ip, ns, podName string) error {
	data, err := n.GetResDataByIp(ip)
	if err != nil {
		return errors.Errorf("get pod info by ip failed, ns : %v, pod name : %v, %+v", ns, podName, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pod, err := n.k8sCli.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return errors.Errorf("get pod failed, ns : %v, pod name : %v, err : %+v", ns, podName, err)
	}

	data.ContainerInfo, err = n.getContainerData(pod, crim)
	if err != nil {
		return errors.Errorf("update container failed, ns : %v, pod name : %v, %+v", ns, podName, err)
	}

	logging.Get().Debug().Msgf("update container id success, ns : %v, pod name : %v.", ns, podName)
	return nil
}
