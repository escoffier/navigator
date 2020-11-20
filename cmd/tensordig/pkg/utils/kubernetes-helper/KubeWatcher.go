package kuberneteshelper

import (
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	gocache "github.com/patrickmn/go-cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/client-go/tools/cache"
)

type KubeSelectedInfo struct {
	Namespace     string
	PodName       string
	PodUID        string
	PodLabels     map[string]string
	ContainerID   string
	ContainerName string
}

func InitKubernetesWatcher(clusterCache *gocache.Cache) error {
	logging.GetLogger().Info().Msg("Using incluster config")
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		corev1.NamespaceAll,
		fields.Everything(),
	)
	_, controller := cache.NewInformer(
		watchlist,
		&corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range pod.Status.ContainerStatuses {
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:     pod.ObjectMeta.Namespace,
						PodName:       pod.ObjectMeta.Name,
						PodUID:        string(pod.ObjectMeta.UID),
						PodLabels:     pod.ObjectMeta.Labels,
						ContainerID:   status.ContainerID,
						ContainerName: status.Name,
					}
					clusterCache.Set(status.ContainerID, newKubeSelectedInfo, gocache.NoExpiration)
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range pod.Status.ContainerStatuses {
					clusterCache.Delete(status.ContainerID)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod, ok := oldObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range oldPod.Status.ContainerStatuses {
					clusterCache.Delete(status.ContainerID)
				}
				newPod, ok := newObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range newPod.Status.ContainerStatuses {
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:     newPod.ObjectMeta.Namespace,
						PodName:       newPod.ObjectMeta.Name,
						PodUID:        string(newPod.ObjectMeta.UID),
						PodLabels:     newPod.ObjectMeta.Labels,
						ContainerID:   status.ContainerID,
						ContainerName: status.Name,
					}
					clusterCache.Set(status.ContainerID, newKubeSelectedInfo, gocache.NoExpiration)
				}
			},
		},
	)
	stop := make(chan struct{})
	go controller.Run(stop)
	logging.GetLogger().Info().Msg("Kubernetes watcher initialized")
	return nil
}
