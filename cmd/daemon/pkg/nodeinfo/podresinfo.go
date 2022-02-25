package nodeinfo

import (
	"context"
	"sync"
)

type PodResInfo struct {
	data *sync.Map // {namespace}/{podName} -> Resource
}

func NewPodResInfo() *PodResInfo {
	return &PodResInfo{
		data: new(sync.Map),
	}
}

func (pr *PodResInfo) GetPod(namespace, name string) (*Resource, bool) {
	obj, exist := pr.data.Load(getKey(namespace, name))
	if !exist || obj == nil {
		return nil, false
	}
	return obj.(*Resource), true
}

func (pr *PodResInfo) OnAdd(newPod *PodEvent) {
	pr.data.Store(getKey(newPod.Pod.Namespace, newPod.Pod.Name), newPod.FinalOwnerResource(context.Background()))
}
func (pr *PodResInfo) OnDelete(oldPod *PodEvent) {
	pr.data.Delete(getKey(oldPod.Pod.Namespace, oldPod.Pod.Name))
}
func (pr *PodResInfo) OnUpdate(oldPod, newPod *PodEvent) {}

func (pr *PodResInfo) Name() string {
	return "pod_res_info_watcher"
}
