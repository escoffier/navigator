package kuberneteshelper

import (
	"fmt"
	"strings"
	"sync"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/client-go/tools/cache"
)

type KubeSelectedInfo struct {
	Namespace            string
	PodName              string
	PodUID               string
	PodLabels            map[string]string
	ContainerID          string
	ImageID              string
	ContainerName        string
	SeccompProfileName   string
	SeccompProfileMode   string
	HostVolumeMountPaths []string
}

func InitKubernetesWatcher(clusterCache *gocache.Cache, podSyscallMapPrevent *sync.Map, podSyscallMapDetect *sync.Map, namespace string) (chan struct{}, error) {
	var config *rest.Config
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
	}

	logging.GetLogger().Info().Msg("Using incluster config")

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fmt.Sprintf("status.phase=Running")
	}

	watchlist := cache.NewFilteredListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		corev1.NamespaceAll,
		optionsModifier,
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
				hostVolumes := make([]corev1.Volume, 0)
				for _, volume := range pod.Spec.Volumes {
					if volume.VolumeSource.HostPath != nil {
						hostVolumes = append(hostVolumes, volume)
					}
				}
				for _, status := range pod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", obj)).Msg("Failed to get containerID")
						return
					}
					hostVolumeMountedPaths := make([]string, 0)
					for _, containerSpec := range pod.Spec.Containers {
						if containerSpec.Image != status.Image {
							continue
						}
						for _, volumeMount := range containerSpec.VolumeMounts {
							for _, hostVolume := range hostVolumes {
								if volumeMount.Name == hostVolume.Name {
									hostVolumeMountedPaths = append(hostVolumeMountedPaths, volumeMount.MountPath)
								}
							}
						}
					}
					containerID := containerIDSplit[1]
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:            pod.ObjectMeta.Namespace,
						PodName:              pod.ObjectMeta.Name,
						PodUID:               string(pod.ObjectMeta.UID),
						PodLabels:            pod.ObjectMeta.Labels,
						ContainerID:          containerID,
						ImageID:              strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1],
						ContainerName:        status.Name,
						HostVolumeMountPaths: hostVolumeMountedPaths,
					}
					clusterCache.Set(containerID, newKubeSelectedInfo, gocache.NoExpiration)

					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(pod.ObjectMeta.UID)).
						Str("pod-name", string(pod.ObjectMeta.Name)).
						Str("pod-namespace", string(pod.ObjectMeta.Namespace)).
						Msg("Added new container")
				}
				for _, status := range pod.Status.InitContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", obj)).Msg("Failed to get containerID")
						return
					}
					hostVolumeMountedPaths := make([]string, 0)
					for _, containerSpec := range pod.Spec.Containers {
						if containerSpec.Image != status.Image {
							continue
						}
						for _, volumeMount := range containerSpec.VolumeMounts {
							for _, hostVolume := range hostVolumes {
								if volumeMount.Name == hostVolume.Name {
									hostVolumeMountedPaths = append(hostVolumeMountedPaths, volumeMount.MountPath)
								}
							}
						}
					}
					containerID := containerIDSplit[1]
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:            pod.ObjectMeta.Namespace,
						PodName:              pod.ObjectMeta.Name,
						PodUID:               string(pod.ObjectMeta.UID),
						PodLabels:            pod.ObjectMeta.Labels,
						ContainerID:          containerID,
						ImageID:              strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1],
						ContainerName:        status.Name,
						HostVolumeMountPaths: hostVolumeMountedPaths,
					}
					clusterCache.Set(containerID, newKubeSelectedInfo, gocache.NoExpiration)
					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(pod.ObjectMeta.UID)).
						Str("pod-name", string(pod.ObjectMeta.Name)).
						Str("pod-namespace", string(pod.ObjectMeta.Namespace)).
						Msg("Added new container")
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range pod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", obj)).Msg("Failed to get containerID")
						return
					}
					containerID := containerIDSplit[1]
					x, found := clusterCache.Get(containerID)
					if found {
						clusterCache.Set(containerID, x, time.Second*30)
					}
					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(pod.ObjectMeta.UID)).
						Str("pod-name", string(pod.ObjectMeta.Name)).
						Str("pod-namespace", string(pod.ObjectMeta.Namespace)).
						Msg("Removed container with timeout")
				}
				for _, status := range pod.Status.InitContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", obj)).Msg("Failed to get containerID")
						return
					}
					containerID := containerIDSplit[1]
					x, found := clusterCache.Get(containerID)
					if found {
						clusterCache.Set(containerID, x, time.Second*30)
					}
					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(pod.ObjectMeta.UID)).
						Str("pod-name", string(pod.ObjectMeta.Name)).
						Str("pod-namespace", string(pod.ObjectMeta.Namespace)).
						Msg("Removed container with timeout")
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				containerPodMap := make(map[string]bool)
				oldPod, ok := oldObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", oldObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for _, status := range oldPod.Status.ContainerStatuses {
					containerPodMap[status.ContainerID] = true
				}
				newPod, ok := newObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				hostVolumes := make([]*corev1.Volume, 0)
				for _, volume := range newPod.Spec.Volumes {
					if volume.VolumeSource.HostPath != nil {
						hostVolumes = append(hostVolumes, &volume)
					}
				}
				for _, status := range newPod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", newPod)).Msg("Failed to get containerID")
						return
					}
					containerID := containerIDSplit[1]
					if _, ok := containerPodMap[status.ContainerID]; ok {
						containerPodMap[status.ContainerID] = false
					}
					hostVolumeMountedPaths := make([]string, 0)
					for _, containerSpec := range newPod.Spec.Containers {
						if containerSpec.Image != status.Image {
							continue
						}
						for _, volumeMount := range containerSpec.VolumeMounts {
							for _, hostVolume := range hostVolumes {
								if volumeMount.Name == hostVolume.Name {
									hostVolumeMountedPaths = append(hostVolumeMountedPaths, volumeMount.MountPath)
								}
							}
						}
					}
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:            newPod.ObjectMeta.Namespace,
						PodName:              newPod.ObjectMeta.Name,
						PodUID:               string(newPod.ObjectMeta.UID),
						PodLabels:            newPod.ObjectMeta.Labels,
						ContainerID:          containerID,
						ImageID:              strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1],
						ContainerName:        status.Name,
						HostVolumeMountPaths: hostVolumeMountedPaths,
					}
					clusterCache.Set(containerID, newKubeSelectedInfo, gocache.NoExpiration)
					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(newPod.ObjectMeta.UID)).
						Str("pod-name", string(newPod.ObjectMeta.Name)).
						Str("pod-namespace", string(newPod.ObjectMeta.Namespace)).
						Msg("Added new container")
				}
				for _, status := range newPod.Status.InitContainerStatuses {
					containerIDSplit := strings.Split(status.ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("obj", fmt.Sprintf("%+v", newPod)).Msg("Failed to get containerID")
						return
					}
					containerID := containerIDSplit[1]
					if _, ok := containerPodMap[status.ContainerID]; ok {
						containerPodMap[status.ContainerID] = false
					}
					hostVolumeMountedPaths := make([]string, 0)
					for _, containerSpec := range newPod.Spec.Containers {
						if containerSpec.Image != status.Image {
							continue
						}
						for _, volumeMount := range containerSpec.VolumeMounts {
							for _, hostVolume := range hostVolumes {
								if volumeMount.Name == hostVolume.Name {
									hostVolumeMountedPaths = append(hostVolumeMountedPaths, volumeMount.MountPath)
								}
							}
						}
					}
					newKubeSelectedInfo := &KubeSelectedInfo{
						Namespace:            newPod.ObjectMeta.Namespace,
						PodName:              newPod.ObjectMeta.Name,
						PodUID:               string(newPod.ObjectMeta.UID),
						PodLabels:            newPod.ObjectMeta.Labels,
						ContainerID:          containerID,
						ImageID:              strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1],
						ContainerName:        status.Name,
						HostVolumeMountPaths: hostVolumeMountedPaths,
					}
					clusterCache.Set(containerID, newKubeSelectedInfo, gocache.NoExpiration)
					logging.GetLogger().
						Info().
						Str("container-id", containerID).
						Str("image-id", strings.Split(status.ImageID, ":")[len(strings.Split(status.ImageID, ":"))-1]).
						Str("pod-uid", string(newPod.ObjectMeta.UID)).
						Str("pod-name", string(newPod.ObjectMeta.Name)).
						Str("pod-namespace", string(newPod.ObjectMeta.Namespace)).
						Msg("Added new container")
				}
				for containerID, oldExistsButNewDoesnt := range containerPodMap {
					if oldExistsButNewDoesnt {
						x, found := clusterCache.Get(containerID)
						if found {
							clusterCache.Set(containerID, x, time.Second*30)
						}
						logging.GetLogger().
							Info().
							Str("container-id", containerID).
							Msg("Removed container with timeout")
					}
				}
			},
		},
	)
	stop := make(chan struct{})
	go controller.Run(stop)
	logging.GetLogger().Info().Msg("Kubernetes watcher initialized")
	return stop, nil
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}
