package immune

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/nats-io/stan.go"
	dp "github.com/novln/docker-parser"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	redisClient  *redis.Client
	stanConn     stan.Conn
	k8sClientset *kubernetes.Clientset
)

func Init(redisCli *redis.Client, stanC stan.Conn) error {
	redisClient = redisCli
	stanConn = stanC

	return nil
}

func sendMessage(subject string, msg []byte) error {
	err := stanConn.Publish(subject, msg)
	return err
}

// TODO refactor
func Watch() error {
	var err error
	var config *rest.Config
	config, err = rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		return err
	}
	k8sClientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get k8s client")
		return err
	}
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fmt.Sprintf("status.phase=Running")
	}

	mainCtx := context.Background()

	watchlist := cache.NewFilteredListWatchFromClient(
		k8sClientset.CoreV1().RESTClient(),
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
					logging.GetLogger().Error().Str("pod", fmt.Sprintf("%+v\n", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for i := range pod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(pod.Status.ContainerStatuses[i].ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("pod", pod.Name).Msg("Failed to get container status")
						continue
					}
					containerID := containerIDSplit[1][0:12]
					containerName := pod.Status.ContainerStatuses[i].Name
					image := pod.Status.ContainerStatuses[i].Image
					reference, err := dp.Parse(image)
					if err != nil {
						logging.GetLogger().Error().Str("pod", pod.Name).Msg("Failed to parse image")
						continue
					}
					logging.GetLogger().Info().Str("containerID", containerID).Str("containreName", containerName).Str("image", image).Msg("Persisting container info")
					containerInfo := model.ContainerInfo{
						ContainerName: containerName,
						ImageRegistry: reference.Registry(),
						ImageName:     reference.ShortName(),
						ImageTag:      reference.Tag(),
					}
					containerInfoRaw, err := json.Marshal(containerInfo)
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to marshal container info")
						return
					}
					podContainerKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, containerID)
					redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 5*time.Second)
					defer redisCtxCancel()

					err = redisClient.Set(redisCtx, podContainerKey, containerInfoRaw, redis.KeepTTL).Err()
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to cache resource")
						return
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("pod", fmt.Sprintf("%+v\n", obj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for i := range pod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(pod.Status.ContainerStatuses[i].ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("pod", pod.Name).Msg("Failed to get container status")
						continue
					}
					containerID := containerIDSplit[1][0:12]
					logging.GetLogger().Info().Str("containerID", containerID).Msg("Removing container info")
					podContainerKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, containerID)
					redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 5*time.Second)
					defer redisCtxCancel()
					err = redisClient.Del(redisCtx, podContainerKey).Err()
					if err != nil {
						logging.GetLogger().Error().Err(err).Str("podContainerKey", podContainerKey).Msg("Failed to remove resource key from cache")
						return
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldpod, ok := oldObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("pod", fmt.Sprintf("%+v\n", oldObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for i := range oldpod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(oldpod.Status.ContainerStatuses[i].ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("pod", oldpod.Name).Msg("Failed to get container status")
						continue
					}
					containerID := containerIDSplit[1][0:12]
					logging.GetLogger().Info().Str("containerID", containerID).Msg("Removing container info")
					podContainerKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, containerID)
					redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 5*time.Second)
					defer redisCtxCancel()
					err = redisClient.Del(redisCtx, podContainerKey).Err()
					if err != nil {
						logging.GetLogger().Error().Err(err).Str("podContainerKey", podContainerKey).Msg("Failed to remove resource key from cache")
						return
					}
				}
				newpod, ok := newObj.(*corev1.Pod)
				if !ok {
					logging.GetLogger().Error().Str("pod", fmt.Sprintf("%+v\n", newObj)).Msg("Failed to cast to *corev1.Pod")
					return
				}
				for i := range newpod.Status.ContainerStatuses {
					containerIDSplit := strings.Split(newpod.Status.ContainerStatuses[i].ContainerID, "://")
					if len(containerIDSplit) == 1 {
						logging.GetLogger().Error().Str("pod", newpod.Name).Msg("Failed to get container status")
						continue
					}
					containerID := containerIDSplit[1][0:12]
					containerName := newpod.Status.ContainerStatuses[i].Name
					image := newpod.Status.ContainerStatuses[i].Image
					reference, err := dp.Parse(image)
					if err != nil {
						logging.GetLogger().Error().Err(err).Str("pod", newpod.Name).Msg("Failed to parse image")
						continue
					}
					logging.GetLogger().Info().Str("containerID", containerID).Str("containreName", containerName).Str("image", image).Msg("Persisting container info")
					containerInfo := model.ContainerInfo{
						ContainerName: containerName,
						ImageRegistry: reference.Registry(),
						ImageName:     reference.ShortName(),
						ImageTag:      reference.Tag(),
					}
					containerInfoRaw, err := json.Marshal(containerInfo)
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to marshal container info")
						return
					}
					podContainerKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, containerID)
					redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 5*time.Second)
					defer redisCtxCancel()

					err = redisClient.Set(redisCtx, podContainerKey, containerInfoRaw, redis.KeepTTL).Err()
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to cache resource")
						return
					}
				}
			},
		})
	stop := make(chan struct{})
	go controller.Run(stop)

	return nil
}
