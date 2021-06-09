package netInfo

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type K8sResClient struct {
	k8sClient *kubernetes.Clientset
	K8sPods   *K8sResInfos
}

func NewK8sResourceSyncer() (*K8sResClient, error) {
	var k8sPods K8sResInfos
	k8sPods.ResInfos = make(map[string]*K8sResData)

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize k8s config: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize k8s clientset: %w", err)
	}

	rs := K8sResClient{
		k8sClient: k8sClient,
		K8sPods:   &k8sPods,
	}

	return &rs, nil
}

func (rs K8sResClient) GetPodControllerFromSvc(ns, svc string, dport int32) ([]*OwnerRef, int32) {
	var targetPort int32
	var tPortName string
	owners := []*OwnerRef{}
	tmp := map[string]*OwnerRef{}

	services, err := rs.k8sClient.CoreV1().Services(ns).Get(svc, metav1.GetOptions{})
	if err != nil {
		return owners, targetPort
	}

	ports := services.Spec.Ports
	for _, port := range ports {
		if port.Port != dport {
			continue
		}

		target := port.TargetPort
		if target.Type == 0 {
			targetPort = target.IntVal
		} else {
			tPortName = target.StrVal
		}
		break
	}

	map2string := func(m map[string]string) string {
		s := []string{}
		for k, v := range m {
			s = append(s, fmt.Sprintf("%s=%s", k, v))
		}

		return strings.Join(s, ",")
	}

	list, err := rs.k8sClient.CoreV1().Pods(ns).List(metav1.ListOptions{LabelSelector: map2string(services.Spec.Selector)})
	if err != nil {
		return owners, targetPort
	}

	for _, pod := range list.Items {
		ownername, ownerkind := rs.GetOwnerReferences(&pod)
		if _, ok := tmp[strings.Join([]string{ownername, ownerkind}, "_")]; !ok {
			var ref OwnerRef
			ref.Name = ownername
			ref.Kind = ownerkind
			tmp[strings.Join([]string{ownername, ownerkind}, "_")] = &ref
		}

		if targetPort == 0 && len(tPortName) > 0 {
			containers := pod.Spec.Containers
			for _, container := range containers {
				cports := container.Ports
				for _, cport := range cports {
					if cport.Name != tPortName {
						continue
					}
					targetPort = cport.ContainerPort
				}
			}
		}
	}

	for _, v := range tmp {
		owners = append(owners, v)
	}

	return owners, targetPort
}

func (rs K8sResClient) GetOwnerReferences(pod *corev1.Pod) (string, string) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil {
		return pod.GetName(), pod.Kind
	}

	ownername := owner.Name
	ownerkind := owner.Kind
	if ownerkind == "ReplicaSet" {
		namespace := pod.GetNamespace()
		rps, err := rs.k8sClient.AppsV1().ReplicaSets(namespace).Get(ownername, metav1.GetOptions{})
		if err != nil {
			//log.Errorf("pod name : %s, ns : %s, err : %v.", pod.GetName(), namespace, err)
			return ownername, ownerkind
		}

		owners := rps.GetOwnerReferences()
		for _, owner := range owners {
			//log.Infof("pod name : %s, ns : %s, Controller : %v, kind : %v, name : %v.", pod.GetName(), namespace, *owner.Controller, owner.Kind, owner.Name)
			if *owner.Controller != true {
				continue
			}

			return owner.Name, owner.Kind
		}
	}

	return ownername, ownerkind
}

func (rs K8sResClient) ListenServiceEvent(factory *informers.SharedInformerFactory) {
	informer := (*factory).Core().V1().Services().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}

			clusterIp := svc.Spec.ClusterIP
			//log.Infof("[service addfunc] clusterIp : %v, service : %v", clusterIp, svc.Namespace)
			if len(clusterIp) == 0 || clusterIp == "None" {
				return
			}

			name := svc.Name
			kind := "Service"
			namespace := svc.Namespace

			rs.K8sPods.SaveK8sResData(clusterIp, name, kind, namespace, "")
		},

		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}

			clusterIp := svc.Spec.ClusterIP
			//log.Infof("[service deletefunc] clusterIp : %v, service : %v", clusterIp, svc.Namespace)
			if len(clusterIp) == 0 || clusterIp == "None" {
				return
			}

			rs.K8sPods.DeleteK8sResData(clusterIp)
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
		},
	})
}

func (rs K8sResClient) procEndpointEvent(event string, obj interface{}) {
	ep, ok := obj.(*corev1.Endpoints)
	if !ok {
		return
	}
	subsets := ep.Subsets

	var ips, ns []string
	for _, subset := range subsets {
		addrs := subset.Addresses
		if len(addrs) == 0 {
			return
		}

		for _, addr := range addrs {
			if addr.IP == "" || addr.IP == "None" {
				continue
			}

			ips = append(ips, addr.IP)
			tr := addr.TargetRef
			if tr == nil {
				continue
			}
			ns = append(ns, tr.Namespace)
			//kind = append(kind, tr.Kind)
		}
	}

	if len(ns) == 0 {
		//log.Warnf("ip : %v, ns len : %v, service name : %v.", ips, ns, ep.Name)
		return
	}

	for i, ip := range ips {
		name := ep.Name
		namespace := ns[i]
		k := "endpoint"
		//print log
		//log.Infof("[%s addfunc] ip : %v, namespace : %v, name : %v", event, ip, namespace, name)
		rs.K8sPods.UpdateK8sResDataWithEndpoints(ip, name, k, namespace, name)
	}
}

func (rs K8sResClient) ListenEndpointEvent(factory *informers.SharedInformerFactory) {
	informer := (*factory).Core().V1().Endpoints().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rs.procEndpointEvent("add", obj)
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			rs.procEndpointEvent("update", newObj)
		},

		DeleteFunc: func(obj interface{}) {
		},
	})
}

func (rs K8sResClient) ListenPodsEvent(factory *informers.SharedInformerFactory) {
	informer := (*factory).Core().V1().Pods().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}

			podIp := pod.Status.PodIP
			if podIp == "" || podIp == "None" {
				return
			}

			name, kind := rs.GetOwnerReferences(pod)
			namespace := pod.GetNamespace()
			//log.Infof("[pods add] ip : %v, name : %v, kind : %v, namespace : %v", podIp, name, kind, namespace)
			rs.K8sPods.SaveK8sResData(podIp, name, kind, namespace, "")
		},

		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}

			podIp := pod.Status.PodIP
			if podIp == "" || podIp == "None" {
				return
			}

			//log.Infof("[pods delete] ip : %v, namespace : %v", podIp, pod.GetNamespace())
			rs.K8sPods.DeleteK8sResData(podIp)
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}

			podIp := pod.Status.PodIP
			if podIp == "" || podIp == "None" {
				return
			}

			_, err := rs.K8sPods.GetK8sResData(podIp)
			if err == nil {
				return
			}

			name, kind := rs.GetOwnerReferences(pod)
			namespace := pod.GetNamespace()
			//log.Infof("[pods update] ip : %v, name : %v, kind : %v, namespace : %v", podIp, name, kind, namespace)
			rs.K8sPods.UpdateK8sResData(podIp, name, kind, namespace, "")
		},
	})
}

func (rs *K8sResClient) ListenNodesEvent(factory *informers.SharedInformerFactory) {
	informer := (*factory).Core().V1().Nodes().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}

			nas := node.Status.Addresses
			if len(nas) == 0 {
				return
			}

			for _, na := range nas {
				if na.Type != "InternalIP" {
					continue
				}
				//log.Infof("AddFunc    node -> type:%v, ip: %v\n", na.Type, na.Address)
			}
		},

		DeleteFunc: func(obj interface{}) {
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
		},
	})
}

func (rs *K8sResClient) StartK8sServiceSyncer() error {
	factory := informers.NewSharedInformerFactory(rs.k8sClient, 0)

	//list k8s pods event
	rs.ListenPodsEvent(&factory)

	//list k8s service event
	rs.ListenServiceEvent(&factory)

	//list k8s endpoint event
	//rs.ListenEndpointEvent(&factory)

	factoryStopChan := make(chan struct{}, 1)
	factory.Start(factoryStopChan)

	log.Infof("Waiting for cache sync")
	syncedStatus := factory.WaitForCacheSync(factoryStopChan)
	log.Infof("Wait finished")

	var podType *corev1.Pod
	podSynced := syncedStatus[reflect.TypeOf(podType)]
	if !podSynced {
		return fmt.Errorf("Pod informer failed to sync initial cache")
	}

	var serviceType *corev1.Service
	serviceSynced := syncedStatus[reflect.TypeOf(serviceType)]
	if !serviceSynced {
		return fmt.Errorf("Service informer failed to sync initial cache")
	}

	// var endpointType *corev1.Endpoints
	// endpointSynced := syncedStatus[reflect.TypeOf(endpointType)]
	// if !endpointSynced {
	// 	return fmt.Errorf("endpoint informer failed to sync initial cache")
	// }

	//wait syns pod data
	time.Sleep(30 * time.Second)

	return nil
}
