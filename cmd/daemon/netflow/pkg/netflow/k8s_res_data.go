package netflow

import (
	"sync"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
)

type K8sResInfos struct {
	resInfos *sync.Map // map[string]*daemon.K8sResData
}

func newK8sResInfos() *K8sResInfos {
	return &K8sResInfos{
		resInfos: new(sync.Map),
	}
}

func (kri *K8sResInfos) SaveK8sResData(ip, ownerName, kind, namespace, podName string, containerInfo map[string]*daemon.ContainerData) {
	if len(ip) == 0 || len(ownerName) == 0 || len(namespace) == 0 || len(containerInfo) == 0 {
		return
	}

	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	rsData.OwnerName = ownerName
	rsData.Kind = kind
	rsData.PodName = podName
	rsData.Namespace = namespace
	rsData.ContainerInfo = containerInfo
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo)
	kri.resInfos.LoadOrStore(ip, &rsData)
}

func (kri *K8sResInfos) DeleteK8sResData(ip string) {
	if len(ip) == 0 {
		return
	}

	kri.resInfos.Delete(ip)
}

func (kri *K8sResInfos) GetK8sResData(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, errors.Errorf("ip address is error")
	}

	v, ok := kri.resInfos.Load(ip)
	if !ok {
		return nil, errors.Errorf("can not find k8s resource data by %s", ip)
	}

	return v.(*daemon.K8sResData), nil
}

func (kri *K8sResInfos) UpdateK8sResData(ip, ownerName, kind, namespace, podname string, containerInfo map[string]*daemon.ContainerData) {
	if len(ip) == 0 || len(ownerName) == 0 || len(namespace) == 0 || len(containerInfo) == 0 {
		return
	}

	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	rsData.OwnerName = ownerName
	rsData.Kind = kind
	rsData.Namespace = namespace
	rsData.PodName = podname
	rsData.ContainerInfo = containerInfo
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo)
	kri.resInfos.Store(ip, &rsData)
}
