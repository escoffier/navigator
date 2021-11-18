package netflow

import (
	"fmt"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
)

type OwnerRef struct {
	Name string
	Kind string
}

type K8sResInfos struct {
	mutex    sync.RWMutex
	ResInfos map[string]*daemon.K8sResData
}

func (kri *K8sResInfos) SaveK8sResData(ip, name, kind, namespace, service, podName, nodeIp string) {
	if len(ip) == 0 || len(name) == 0 || len(namespace) == 0 {
		return
	}

	kri.mutex.Lock()
	defer kri.mutex.Unlock()

	_, ok := kri.ResInfos[ip]
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
	kri.ResInfos[ip] = &resData
}

func (kri *K8sResInfos) DeleteK8sResData(ip string) {
	if len(ip) == 0 {
		return
	}

	kri.mutex.Lock()
	defer kri.mutex.Unlock()

	delete(kri.ResInfos, ip)
}

func (kri *K8sResInfos) GetK8sResData(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, nil
	}

	kri.mutex.RLock()
	defer kri.mutex.RUnlock()

	value, ok := kri.ResInfos[ip]
	if !ok {
		return nil, fmt.Errorf("can not find k8s res data by %s", ip)
	}

	return value, nil
}

func (kri *K8sResInfos) UpdateK8sResDataWithEndpoints(ip, name, kind, namespace, service string) {
	kri.mutex.Lock()
	defer kri.mutex.Unlock()

	value, ok := kri.ResInfos[ip]
	if ok {
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
		kri.ResInfos[ip] = &resData
	}
}

func (kri *K8sResInfos) UpdateK8sResData(ip, name, kind, namespace, service, podname, hostIp string) {
	kri.mutex.Lock()
	defer kri.mutex.Unlock()

	_, ok := kri.ResInfos[ip]
	if ok {
		return
	}

	var resData daemon.K8sResData
	resData.Name = name
	resData.Kind = kind
	resData.NodeIp = hostIp
	resData.Namespace = namespace
	resData.PodName = podname
	kri.ResInfos[ip] = &resData
}
