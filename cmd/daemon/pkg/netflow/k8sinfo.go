package netflow

import (
	"context"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
	policyCli     microseg.PolicyClient
	containerInfo nodeinfo.ContainerInfoManager
}

func NewNodePodInfo(k8sCli *kubernetes.Clientset) *NodePodsInfo {
	info := &NodePodsInfo{
		resInfos: new(sync.Map),
		k8sCli:   k8sCli,
	}

	return info
}

func (n *NodePodsInfo) getContainerData(pod *corev1.Pod) (map[string]*daemon.ContainerData, error) {
	containerData := make(map[string]*daemon.ContainerData)

	for _, container := range pod.Status.ContainerStatuses {
		if len(pod.Status.ContainerStatuses) != 1 {
			running := container.State.Running
			if running == nil {
				continue
			}
		}
		if container.State.Running == nil {
			continue
		}
		//check container id
		if len(container.ContainerID) == 0 {
			logging.Get().Debug().Str("pod", pod.GetNamespace()+pod.GetName()).Msgf("container id is nil")
			continue
		}
		//get container pid
		cPid, id, err := n.containerInfo.GetContainerPid(container.ContainerID)
		if len(container.Name) == 0 || err != nil {
			logging.Get().Debug().Str("pod", pod.GetNamespace()+pod.GetName()).Msgf("get container pid failed : %v", err)
			continue
		}
		//save container information
		containerData[id] = &daemon.ContainerData{
			ContainerName: container.Name,
			ContainerPid:  cPid,
		}
	}

	if len(containerData) == 0 {
		return nil, errors.Errorf("container data is nil, ns : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
	}

	return containerData, nil
}

func (n *NodePodsInfo) OnAdd(pod *corev1.Pod) {
	logging.Get().Info().Msgf("add pod %s/%s", pod.Namespace, pod.Name)
	if pod.Spec.HostNetwork {
		return
	}
	n.savePodData(pod)
}

func (n *NodePodsInfo) OnDelete(oldPod *corev1.Pod) {
	if oldPod == nil {
		return
	}

	if oldPod.Spec.HostNetwork {
		return
	}

	for _, podIp := range oldPod.Status.PodIPs {
		if podIp.IP == "" || podIp.IP == NoneValue {
			continue
		}
		n.DeleteResData(podIp.IP)
	}
}

func (n *NodePodsInfo) OnUpdate(oldPod, newPod *corev1.Pod) {
	n.OnAdd(newPod)
}

func (n *NodePodsInfo) Name() string {
	return "netflow_watcher"
}

func (n *NodePodsInfo) savePodData(pod *corev1.Pod) {
	logging.Get().Debug().Str("microseg", "common").Msgf("save pod %s/%s", pod.Namespace, pod.Name)
	//need save
	keys := make([]string, 0)
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP == "" || podIP.IP == NoneValue {
			continue
		}

		_, ok := n.resInfos.Load(podIP.IP)
		if ok {
			continue
		}
		keys = append(keys, podIP.IP)
	}

	var err error
	var rsData daemon.K8sResData
	rsData.ContainerInfo, err = n.getContainerData(pod)
	if err != nil {
		logging.Get().Err(err).Str("module", "netflow").Msgf("get pod(%s/%s) contaier info err", pod.Namespace, pod.Name)
		return
	}

	var res nodeinfo.Resource
	res.Name, res.Kind = util.GetOwnerOfPod(pod)
	rsData.OwnerName = res.Name
	rsData.Kind = res.Kind
	rsData.PodName = pod.Name
	rsData.PodUid = string(pod.GetUID())
	rsData.Namespace = pod.Namespace
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo, 2)

	for _, ip := range keys {
		logging.Get().Info().Msgf("save pods : %+v.", ip)
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

func (n *NodePodsInfo) UpdateContainerData(ip, ns, podName string) error {
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

	data.ContainerInfo, err = n.getContainerData(pod)
	if err != nil {
		return errors.Errorf("update container failed, ns : %v, pod name : %v, %+v", ns, podName, err)
	}

	logging.Get().Debug().Msgf("update container id success, ns : %v, pod name : %v.", ns, podName)
	return nil
}

func (n *NodePodsInfo) SetContainerManager(containerInfo nodeinfo.ContainerInfoManager) {
	n.containerInfo = containerInfo
}
