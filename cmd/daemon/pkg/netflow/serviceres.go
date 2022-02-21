package netflow

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	NoneValue = "None"
)

type K8sResClient struct {
	k8sClient   *kubernetes.Clientset
	dockerCli   *client.Client
	nodeResInfo *NodeResourceInfo
	hostIP      string
	hostName    string
}

func NewK8sResourceSyncer(hostName, hostIP string, nodeResInfo *NodeResourceInfo) (*K8sResClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize k8s config: %w", err)
	}
	//k8s client
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize k8s clientset: %w", err)
	}
	//docker client
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, errors.Errorf("docker new client failed, %v", err)
	}

	rs := K8sResClient{
		k8sClient:   k8sClient,
		dockerCli:   dockerCli,
		nodeResInfo: nodeResInfo,
		hostIP:      hostIP,
		hostName:    hostName,
	}

	return &rs, nil
}

func (rs K8sResClient) GetContainerPid(containerID string) (int, error) {
	if containerID == "" {
		return 0, fmt.Errorf("container ID is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	container, err := rs.dockerCli.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0, fmt.Errorf("container inspace failed, %v", err)
	}

	if container.State.Pid <= 0 {
		return 0, fmt.Errorf("get container's pid failed, pid : %v", container.State.Pid)
	}

	return container.State.Pid, nil
}

func (rs K8sResClient) GetPodOwnerReferences(ctx context.Context, ns, podname string) (string, string) {
	pod, err := rs.k8sClient.CoreV1().Pods(ns).Get(ctx, podname, metav1.GetOptions{})
	if err != nil {
		logging.Get().Error().Msgf("get pod failed, namespace : %v, pod name : %v.", ns, podname)
		return "", ""
	}

	return rs.GetOwnerReferences(pod)
}

func (rs K8sResClient) GetOwnerReferences(pod *corev1.Pod) (string, string) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil {
		kind := pod.Kind
		if len(kind) == 0 || kind == "" {
			kind = "Pod"
		}
		return pod.GetName(), kind
	}
	//set timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	//owner information
	ownername := owner.Name
	ownerkind := owner.Kind
	//debug log
	//logging.Get().Info().Msgf("ownername : %v, ownerkind : %v", ownername, ownerkind)
	//get owner reference
	switch ownerkind {
	case "ReplicaSet":
		namespace := pod.GetNamespace()
		rset, err := rs.k8sClient.AppsV1().ReplicaSets(namespace).Get(ctx, ownername, metav1.GetOptions{})
		if err != nil {
			//logging.Get().Error().Msgf("pod name : %s, ns : %s, err : %v.", pod.GetName(), namespace, err)
			return ownername, ownerkind
		}

		owners := rset.GetOwnerReferences()
		for _, o := range owners {
			//logging.Get().Info().Msgf("pod name : %s, ns : %s, Controller : %v, kind : %v, name : %v.", pod.GetName(), namespace, *owner.Controller, owner.Kind, owner.Name)
			if !(*o.Controller) {
				continue
			}

			return o.Name, o.Kind
		}
	case "Job":
		namespace := pod.GetNamespace()
		job, err := rs.k8sClient.BatchV1().Jobs(namespace).Get(ctx, ownername, metav1.GetOptions{})
		if err != nil {
			return ownername, ownerkind
		}
		owners := job.GetOwnerReferences()
		for _, o := range owners {
			if !(*o.Controller) {
				continue
			}

			return o.Name, o.Kind
		}
	}

	return ownername, ownerkind
}

func (rs K8sResClient) GetContainerData(pod *corev1.Pod) map[string]*daemon.ContainerData {
	containerData := make(map[string]*daemon.ContainerData, len(pod.Status.ContainerStatuses))

	for _, container := range pod.Status.ContainerStatuses {
		if len(pod.Status.ContainerStatuses) != 1 {
			running := container.State.Running
			if running == nil {
				continue
			}
		}

		cname := container.Name
		id := strings.TrimPrefix(container.ContainerID, "docker://")
		cPid, err := rs.GetContainerPid(id)
		if len(cname) == 0 || err != nil {
			logging.Get().Warn().Msgf("get container info failed, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
			continue
		}
		//save container information
		containerData[id] = &daemon.ContainerData{
			ContainerName: cname,
			ContainerPid:  cPid,
		}
	}

	if len(containerData) == 0 {
		logging.Get().Warn().Msgf("get container id failed, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
	}

	return containerData
}

func (rs K8sResClient) ListenLocalNodePods(stopChan chan struct{}) {
	watchlist := cache.NewFilteredListWatchFromClient(
		rs.k8sClient.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		corev1.NamespaceAll,
		func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%v", rs.hostName)
		})

	_, controller := cache.NewInformer(
		watchlist,
		&corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					return
				}

				network := pod.Spec.HostNetwork
				podIP := pod.Status.PodIP
				if network || podIP == "" || podIP == NoneValue {
					return
				}
				//get owner reference
				ownerName, kind := rs.GetOwnerReferences(pod)
				ownerNamespace := pod.GetNamespace()
				//logging.Get().Info().Msgf("[pods add] ip : %v, name : %v, kind : %v, namespace : %v", podIp, pod.GetName(), kind, ownerNamespace)
				//save k8s resource data
				rs.nodeResInfo.SaveK8sResData(podIP, ownerName, kind, ownerNamespace, pod.GetName(), rs.GetContainerData(pod))
			},

			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					return
				}

				network := pod.Spec.HostNetwork
				podIP := pod.Status.PodIP
				if network || podIP == "" || podIP == NoneValue {
					return
				}
				//delete k8s resource
				rs.nodeResInfo.DeleteK8sResData(podIP)
				//logging.Get().Info().Msgf("[pods delete] ip : %v, name : %v, kind : %v, namespace : %v", podIp, pod.GetName(), pod.Kind, pod.GetNamespace())
			},

			UpdateFunc: func(oldObj, newObj interface{}) {
				pod, ok := newObj.(*corev1.Pod)
				if !ok {
					return
				}

				network := pod.Spec.HostNetwork
				podIP := pod.Status.PodIP
				if network || podIP == "" || podIP == NoneValue {
					return
				}

				_, err := rs.nodeResInfo.GetK8sResData(podIP)
				if err == nil {
					return
				}
				//get owner reference
				ownername, kind := rs.GetOwnerReferences(pod)
				namespace := pod.GetNamespace()
				//logging.Get().Info().Msgf("[pods update] ip : %v, name : %v, kind : %v, namespace : %v", podIp, pod.GetName(), pod.Kind, pod.GetNamespace())
				//update k8s resource data
				rs.nodeResInfo.UpdateK8sResData(podIP, ownername, kind, namespace, pod.GetName(), rs.GetContainerData(pod))
			}})
	//controller run
	controller.Run(stopChan)
}

func (rs *K8sResClient) DockerEvents() {
	filter := filters.NewArgs(
		filters.Arg("event", "create"),
		filters.Arg("type", "container"),
	)

	msg, errs := rs.dockerCli.Events(context.Background(), types.EventsOptions{
		Filters: filter,
	})

	for {
		select {
		case m := <-msg:
			rs.nodeResInfo.SaveContainerData(m.ID, m.Time)
		case err := <-errs:
			if err != nil {
				logging.Get().Err(err).Msgf("err returned for docker events. try to restart")
				// try to restart listening to container streams
				msg, errs = rs.dockerCli.Events(context.Background(), types.EventsOptions{
					Filters: filter,
				})
			}
		}
	}
}

func (rs *K8sResClient) StartK8sServiceSyncer() error {
	//docker events
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//docker events
		rs.DockerEvents()
	}()

	//get pods information
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//stop channel
		stopChan := make(chan struct{})
		//listen local node pods
		rs.ListenLocalNodePods(stopChan)
	}()
	//wait syns pod data
	time.Sleep(10 * time.Second)

	return nil
}
