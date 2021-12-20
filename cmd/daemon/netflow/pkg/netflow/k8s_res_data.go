package netflow

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
)

type OwnerRef struct {
	Name string
	Kind string
}

type PodInfo struct {
	containerStatuses map[string]string // container ID -> container Name
	hostIP            string
	hostNetwork       bool
}

type K8sResInfos struct {
	resInfos          *sync.Map // map[string]*daemon.K8sResData
	podContainerInfos *sync.Map // map[string]*PodInfo stores the infos in the current node
}

func newK8sResInfos() *K8sResInfos {
	return &K8sResInfos{
		resInfos:          new(sync.Map),
		podContainerInfos: new(sync.Map),
	}
}

func getPodInfoKey(podName, namespace string) string {
	return fmt.Sprintf("%s/%s", namespace, podName)
}
func (kri *K8sResInfos) savePodInfo(podName string, namespace string, podInfo *PodInfo) {
	kri.podContainerInfos.Store(getPodInfoKey(podName, namespace), podInfo)
}

func (kri *K8sResInfos) getPodInfo(podName, namespace string) (*PodInfo, bool) {
	v, ok := kri.podContainerInfos.Load(getPodInfoKey(podName, namespace))
	if ok {
		return v.(*PodInfo), true
	}
	return nil, false
}

func (kri *K8sResInfos) deletePodInfo(podName string, namespace string) {
	kri.podContainerInfos.Delete(getPodInfoKey(podName, namespace))
}

func (kri *K8sResInfos) SaveK8sResData(ip, name, kind, namespace, service, podName, nodeIp string) {
	if len(ip) == 0 || len(name) == 0 || len(namespace) == 0 {
		return
	}

	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var resData daemon.K8sResData
	resData.Cluster = service
	resData.Name = name
	resData.Kind = kind
	resData.PodName = podName
	resData.NodeIp = nodeIp
	resData.Namespace = namespace
	kri.resInfos.LoadOrStore(ip, &resData)
}

func (kri *K8sResInfos) DeleteK8sResData(ip string) {
	if len(ip) == 0 {
		return
	}

	kri.resInfos.Delete(ip)
}

func (kri *K8sResInfos) GetK8sResData(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, nil
	}

	v, ok := kri.resInfos.Load(ip)
	if !ok {
		return nil, errors.Errorf("can not find k8s res data by %s", ip)
	}

	return v.(*daemon.K8sResData), nil
}

func (kri *K8sResInfos) UpdateK8sResDataWithEndpoints(ip, name, kind, namespace, service string) {

	v, ok := kri.resInfos.Load(ip)
	if ok {
		value := v.(*daemon.K8sResData)
		if service == "" || value.Kind == "Service" {
			return
		}

		value.Name = name
		value.Kind = "Service"
	} else {
		var resData daemon.K8sResData
		resData.Name = name
		if kind == "endpoint" {
			kind = "Service"
		}
		resData.Kind = kind
		resData.Namespace = namespace
		kri.resInfos.LoadOrStore(ip, &resData)
	}
}

func (kri *K8sResInfos) UpdateK8sResData(ip, name, kind, namespace, service, podname, hostIp string) {
	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var resData daemon.K8sResData
	resData.Name = name
	resData.Kind = kind
	resData.NodeIp = hostIp
	resData.Namespace = namespace
	resData.PodName = podname
	kri.resInfos.Store(ip, &resData)
}
