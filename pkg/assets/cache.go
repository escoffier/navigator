package assets

import (
	"errors"
	"sync"
	"sync/atomic"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	sourceTypeEndpoints  = "endpoints"
	sourceTypeController = "controller"
)

var defaultInfo = ServiceInfo{}

type ServiceInfo struct {
	sync.RWMutex
	svcList   map[string]struct{}
	Namespace string
	source    string
}

func newServiceInfo(namespace string, src string) *ServiceInfo {
	return &ServiceInfo{
		svcList:   make(map[string]struct{}, 1),
		Namespace: namespace,
		source:    src,
	}
}
func (s *ServiceInfo) Services() []string {
	s.RLock()
	defer s.RUnlock()
	l := make([]string, len(s.svcList))
	i := 0
	for svc := range s.svcList {
		l[i] = svc
		i++
	}
	return l
}
func (s *ServiceInfo) appendService(svcName string) {
	s.Lock()
	defer s.Unlock()

	s.svcList[svcName] = struct{}{}
}
func (s *ServiceInfo) removeService(svcName string) int {
	s.RLock()
	if len(s.svcList) == 0 {
		s.RUnlock()
		return 0
	}
	s.RUnlock()

	s.Lock()
	defer s.Unlock()
	delete(s.svcList, svcName)
	return len(s.svcList)
}

type PodServiceCache struct {
	size int32
	sync.RWMutex
	data map[string]*sync.Map // cluster -> podName -> ServiceInfo{}
}

func NewPodServiceCache() *PodServiceCache {
	return &PodServiceCache{
		data: make(map[string]*sync.Map, 1),
	}
}
func (c *PodServiceCache) getData(cluster string) (m *sync.Map, exist bool) {
	c.RLock()
	defer c.RUnlock()
	m, exist = c.data[cluster]
	return
}

func (c *PodServiceCache) getOrCreateData(cluster string) *sync.Map {
	m, exist := c.getData(cluster)
	if exist {
		return m
	}
	c.Lock()
	defer c.Unlock()
	m, exist = c.data[cluster]
	if exist {
		return m
	}
	m = new(sync.Map)
	c.data[cluster] = m

	return m
}

func (c *PodServiceCache) GetServiceInfoBy(cluster, podName string) (*ServiceInfo, bool) {
	m, exist := c.getData(cluster)
	if !exist {
		return nil, false
	}
	val, exist := m.Load(podName)
	if !exist {
		return nil, false
	}
	sinfo := val.(*ServiceInfo)
	logging.GetLogger().Info().Msgf("assets service cache GetServiceInfoBy %s and %s: %+v", cluster, podName, sinfo)
	return sinfo, true
}

func (c *PodServiceCache) Size() int32 {
	return atomic.LoadInt32(&c.size)
}

func (c *PodServiceCache) OnPodForServiceEvent(kubeCluster string, newPod, oldPod *corev1.Pod, action AssetsAction) error {
	data := c.getOrCreateData(kubeCluster)
	if action == ActionDelete {
		if oldPod == nil {
			return errors.New("no old endpoints given")
		}
		data.Delete(oldPod.Name)
	}
	if action == ActionAdd || action == ActionUpdate {
		if newPod == nil {
			return errors.New("no new pods given")
		}
		if newPod.UID == "" {
			return nil
		}
		_, exist := data.Load(newPod.Name)
		if exist {
			return nil
		}

		owner := metav1.GetControllerOf(newPod)
		svcName := newPod.Name
		if owner != nil {
			svcName = owner.Name
		}
		sinfo := newServiceInfo(newPod.Namespace, sourceTypeController)
		sinfo.appendService(svcName)
		data.LoadOrStore(newPod.Name, sinfo)
	}
	return nil
}
func (c *PodServiceCache) OnEndpointsEvent(kubeCluster string, newEpt, oldEpt *corev1.Endpoints, action AssetsAction) error {
	data := c.getOrCreateData(kubeCluster)
	if action == ActionDelete {
		if oldEpt == nil {
			return errors.New("no old endpoints given")
		}

		for _, v := range oldEpt.Subsets {
			for _, address := range v.Addresses {
				podName := ""
				if address.TargetRef != nil {
					podName = address.TargetRef.Name
				}
				if len(podName) == 0 {
					continue
				}
				o, exist := data.Load(podName)
				if exist {
					atomic.AddInt32(&c.size, -1)
					svcInfo := o.(*ServiceInfo)
					logging.GetLogger().Info().Msgf("remove service %s in podname %s", oldEpt.Name, podName)
					size := svcInfo.removeService(oldEpt.Name)
					if size == 0 {
						data.Delete(podName)
					}
				}
			}
		}
	}
	if action == ActionUpdate || action == ActionAdd {
		if newEpt == nil {
			return errors.New("no new endpoints given")
		}
		svcInfo := newServiceInfo(newEpt.Namespace, sourceTypeEndpoints)
		svcInfo.appendService(newEpt.Name)
		for _, v := range newEpt.Subsets {
			for _, address := range v.Addresses {
				podName := ""
				if address.TargetRef != nil {
					podName = address.TargetRef.Name
				}
				if len(podName) == 0 {
					continue
				}
				atomic.AddInt32(&c.size, 1)
				logging.GetLogger().Info().Msgf("add service %s in podname %s", newEpt.Name, podName)
				o, _ := data.LoadOrStore(podName, svcInfo)
				sinfo := o.(*ServiceInfo)
				if sinfo.source != sourceTypeEndpoints { // endpoints data is first priority to set, just to replace existing serviceinfo
					data.Store(podName, svcInfo)
				} else {
					sinfo.appendService(newEpt.Name)
				}
			}
		}
	}

	return nil
}
