package nodeinfo

import (
	"fmt"
	"hash/fnv"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	maxRetries = 5
)

type Controller struct {
	podInformer          cache.SharedIndexInformer
	podLister            listerv1.PodLister
	queue                workqueue.RateLimitingInterface
	podSynced            cache.InformerSynced
	containerInfoManager ContainerInfoManager
	policyCli            microseg.PolicyClient
}

func NewPodController(podLister listerv1.PodLister, podInformer cache.SharedIndexInformer, containerInfoManager ContainerInfoManager, policyCli microseg.PolicyClient) *Controller {
	controller := &Controller{
		podInformer:          podInformer,
		podLister:            podLister,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pod-queue"),
		podSynced:            podInformer.HasSynced,
		containerInfoManager: containerInfoManager,
		policyCli:            policyCli,
	}
	controller.policyCli.AddReConnectionCallback(controller.ResynAllPods)

	controller.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addPod,
		UpdateFunc: controller.updatePod,
		DeleteFunc: controller.deletePod,
	})
	return controller
}

func (n *Controller) addPod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	logging.Get().Debug().Msgf("add pod %s/%s", pod.Namespace, pod.Name)
	if pod.Spec.HostNetwork {
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		logging.Get().Err(err).Msgf("pod %s/%s", pod.Namespace, pod.Name)
		return
	}
	n.queue.Add(key)
}

func (n *Controller) updatePod(old, cur interface{}) {
	n.addPod(cur)
}

func (n *Controller) deletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		logging.Get().Err(err).Msgf("pod %s/%s", pod.Namespace, pod.Name)
		return
	}
	logging.Get().Info().Msgf("delete pod %s", key)
	n.queue.Add(key)
}

func (n *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		n.queue.Forget(key)
		return
	}
	if n.queue.NumRequeues(key) < maxRetries {
		log.Err(err).Msgf("Error syncing pod, retrying %s", key)
		n.queue.AddRateLimited(key)
		return
	}

	log.Warn().Msgf("Dropping pod %q out of the queue: %v", key, err)
	n.queue.Forget(key)
}

func (n *Controller) getPodContainerPid(pod *corev1.Pod) []int {
	var pids []int
	for _, container := range pod.Status.ContainerStatuses {
		if container.State.Running == nil {
			continue
		}
		if container.ContainerID == "" {
			continue
		}
		pid, _, err := n.containerInfoManager.GetContainerPid(container.ContainerID)
		if err != nil {
			logging.Get().Err(err).Msgf("get contianer pid of pod %s/%s", pod.Namespace, pod.Name)
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

func (n *Controller) syncPod(key string) error {
	logging.Get().Info().Msgf("sync pod %s", key)
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	pod, err := n.podLister.Pods(ns).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			err = n.policyCli.DeleteContaier(10, podID1(ns, name))
			if err != nil {
				return err
			}
			return nil
		} else {
			return err
		}
	}

	pids := n.getPodContainerPid(pod)
	for _, pid := range pids {
		logging.Get().Info().Msgf("sync pod : %s", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
		err = n.policyCli.AddContainer(pid, podID2(pod))
		if err != nil {
			logging.Get().Error().Str("module", "heavy-agent").Msgf("sync pod (pid : %+v, %s/%s) failed, err : %+v", pid, ns, name, err)
			return err
		}
	}

	return nil
}

func (n *Controller) processNextItem() bool {
	key, quit := n.queue.Get()
	if quit {
		logging.Get().Info().Msg("queue quit")
		return false
	}
	defer n.queue.Done(key)

	podKey := key.(string)
	err := n.syncPod(podKey)
	n.handleErr(err, key)

	return true
}

func (n *Controller) worker() {
	logging.Get().Info().Msg("start worker")
	for n.processNextItem() {
	}
}

func (n *Controller) Run(stopChan <-chan struct{}) {
	if !cache.WaitForCacheSync(stopChan, n.podSynced, n.containerInfoManager.Synced) {
		return
	}
	wait.Until(n.worker, time.Second, stopChan)
}

func (n *Controller) ResynAllPods() error {
	logging.Get().Info().Msg("resync all pods")
	pods, err := n.podLister.List(labels.Everything())
	if err != nil {
		logging.Get().Err(err).Msg("resync pods")
		return err
	}

	for _, pod := range pods {
		pids := n.getPodContainerPid(pod)
		if err != nil {
			logging.Get().Err(err).Msg("resync pods, get container")
			return err
		}

		for _, pid := range pids {
			err = n.policyCli.AddContainer(pid, podID2(pod))
			if err != nil {
				logging.Get().Warn().Str("module", "heavy-agent").Msgf("container (pid: %d, %+v/%+v) to agent, err: %v", pid, pod.Namespace, pod.Name, err)
				return err
			}
		}
	}
	return nil
}

func podID1(namespace, name string) uint64 {
	str := fmt.Sprintf("%s/%s", namespace, name)
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}

func podID(pod *corev1.Pod) uint32 {
	str := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	h := fnv.New32a()
	h.Write([]byte(str))
	return h.Sum32()
}

func podID2(pod *corev1.Pod) uint64 {
	str := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}
