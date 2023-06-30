package netflow

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg"
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
	resInfos  *sync.Map // map[string]*daemon.K8sResData
	k8sCli    *kubernetes.Clientset
	policyCli microseg.PolicyClient
}

func NewNodePodInfo(k8sCli *kubernetes.Clientset, policyCli microseg.PolicyClient) *NodePodsInfo {
	info := &NodePodsInfo{
		resInfos:  new(sync.Map),
		k8sCli:    k8sCli,
		policyCli: policyCli,
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

	if newPod.Pod.Spec.HostNetwork {
		return
	}

	n.savePodData(newPod, containerInfo)
}

func (n *NodePodsInfo) OnDelete(oldPod *nodeinfo.PodEvent) {
	if oldPod.Pod == nil {
		return
	}

	if oldPod.Pod.Spec.HostNetwork {
		return
	}

	for _, podIp := range oldPod.Pod.Status.PodIPs {
		if podIp.IP == "" || podIp.IP == NoneValue {
			continue
		}
		n.DeleteResData(podIp.IP)
	}
	if len(oldPod.Pod.Status.PodIPs) > 0 && n.policyCli != nil {
		ip := oldPod.Pod.Status.PodIPs[0]
		if value, exist := n.resInfos.Load(ip); exist {
			resData := value.(*daemon.K8sResData)
			for _, c := range resData.ContainerInfo {
				err := n.policyCli.DeleteContaier(c.ContainerPid, podID(oldPod.Pod))
				if err != nil {
					logging.Get().Warn().Msgf("container %s (pid: %d) to dp err: %v",
						c.ContainerName, c.ContainerPid, err)
					continue
				}
				break
			}
		}
	}
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
	//need save
	keys := make([]string, 0)
	for _, podIP := range podEvt.Pod.Status.PodIPs {
		if podIP.IP == "" || podIP.IP == NoneValue {
			continue
		}

		_, ok := n.resInfos.Load(podIP.IP)
		if ok {
			continue
		}
		keys = append(keys, podIP.IP)
	}
	//check ip
	if len(keys) == 0 {
		return
	}

	var err error
	var rsData daemon.K8sResData
	rsData.ContainerInfo, err = n.getContainerData(podEvt.Pod, containerInfo)
	if err != nil {
		return
	}

	if n.policyCli != nil {
		logging.Get().Info().Msgf("to dp %d", len(rsData.ContainerInfo))

		for _, c := range rsData.ContainerInfo {
			err := n.policyCli.AddContainer(c.ContainerPid, podID(podEvt.Pod))
			if err != nil {
				logging.Get().Warn().Msgf("container %s (pid: %d) to dp err: %v",
					c.ContainerName, c.ContainerPid, err)
			}
			break
		}
	}
	res := podEvt.FinalOwnerResource(context.Background())
	rsData.OwnerName = res.Name
	rsData.Kind = res.Kind
	rsData.PodName = podEvt.Pod.Name
	rsData.Namespace = podEvt.Pod.Namespace
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo, 2)

	for _, ip := range keys {
		//logging.Get().Info().Msgf("save pods : %+v.", ip)
		n.resInfos.LoadOrStore(ip, &rsData)
	}
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

func (n *NodePodsInfo) GetResDataByIp(ip string) (*daemon.K8sResData, bool) {
	if len(ip) == 0 {
		return nil, false
	}

	v, ok := n.resInfos.Load(ip)
	if !ok {
		return nil, false
	}

	return v.(*daemon.K8sResData), true
}

func (n *NodePodsInfo) UpdateContainerData(crim nodeinfo.ContainerInfoManager, ip, ns, podName string) error {
	data, ok := n.GetResDataByIp(ip)
	if !ok {
		return errors.Errorf("get pod info by ip failed, ns : %v, pod name : %v", ns, podName)
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

func podID(pod *corev1.Pod) uint64 {
	str := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}
