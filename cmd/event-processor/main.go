package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"

	"gitlab.com/piccolo_su/vegeta/cmd/event-processor/pkg/config"
	"gitlab.com/piccolo_su/vegeta/cmd/event-processor/pkg/utils/alert"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"

	"github.com/go-redis/redis/v8"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	dp "github.com/novln/docker-parser"
	eventcenter_helper "gitlab.com/piccolo_su/vegeta/cmd/event-processor/pkg/utils/eventcenter-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Reporter struct {
	uuidGenerator *uuid.Generator
	cli           pb.EventsCenterCollectionServiceClient
}

type HolmesAlert struct {
	OutputFields map[string]interface{} `json:"output_fields"`
	Output       string                 `json:"output"`
	Rule         string                 `json:"rule"`
}

func getResource(ctx context.Context, clientset *kubernetes.Clientset, pod *corev1.Pod, containerInfo model.ContainerInfo) (model.SecurityPolicyResource, error) {
	namespace := pod.Namespace
	owner := metav1.GetControllerOf(pod)
	name := pod.Name
	kind := string(model.KubernetesResourcePod)
	if owner != nil {
		name = strings.ToLower(owner.Name)
		kind = strings.ToLower(owner.Kind)
		if kind == string(model.KubernetesResourceReplicaSet) {
			replicaset, err := clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return model.SecurityPolicyResource{}, err
			}
			owner = metav1.GetControllerOf(replicaset)
			if owner != nil {
				name = strings.ToLower(owner.Name)
				kind = strings.ToLower(owner.Kind)
			}
		}
	}
	r := model.SecurityPolicyResource{
		Cluster:       "default",
		Kind:          model.KubernetesResource(kind),
		Name:          name,
		Namespace:     namespace,
		ContainerName: containerInfo.ContainerName,
		ImageRegistry: containerInfo.ImageRegistry,
		ImageName:     containerInfo.ImageName,
		ImageTag:      containerInfo.ImageTag,
	}
	return r, nil
}

func sendMessage(conn stan.Conn, subject string, msg []byte) error {
	fmt.Printf("Sending a message to STAN: %s\n", string(msg))
	err := conn.Publish(subject, msg)
	return err
}

func dealHolmesAlert(m *stan.Msg, r Reporter) {

	var f HolmesAlert
	err := json.Unmarshal(m.Data, &f)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to unmarshal message")
		return
	}
	podName := "unknown"
	if val, ok := f.OutputFields["k8s.pod.name"]; ok {
		if val != nil {
			podName = val.(string)
		}
	}

	podNamespace := "unknown"
	if val, ok := f.OutputFields["k8s.ns.name"]; ok {
		if val != nil {
			podNamespace = val.(string)
		}
	}
	podID := "unknown"
	if val, ok := f.OutputFields["k8s.pod.id"]; ok {
		if val != nil {
			podID = val.(string)
		}
	}

	containerID := "unknown"
	if val, ok := f.OutputFields["container.id"]; ok {
		if val != nil {
			containerID = val.(string)
		}
	}

	ruleName := f.Rule
	output := f.Output

	go alert.NotifyEventWithRetry(r.cli, alert.GenerateEvent(r.uuidGenerator, &alert.EventArg{
		Cluster:     "default",
		Namespace:   podNamespace,
		PodName:     podName,
		PodUID:      podID,
		RuleNmae:    ruleName,
		ContainerID: containerID,
		Output:      output,
	}, "ATT&CK"))

}

type lateversionResp struct {
	Data struct {
		Item struct {
			Data                 string `json:"data"`
			LatestDataVersion    int    `json:"latestDataVersion"`
			LatestSettingVersion int    `json:"latestSettingVersion"`
			DataChanged          bool   `json:"dataChanged"`
			SettingChanged       bool   `json:"settingChanged"`
		} `json:"item"`
	} `json:"data"`
}

func updateLatestChannels(sc stan.Conn, channels []string, r Reporter, addr string) {
	const (
		interval = time.Second * 30
	)
	channelsMap := make(map[string]bool)
	for _, v := range channels {
		channelsMap[v] = true

	}

	currentVersion, currentSetVersion := -1, -1
	tmpUrl := "http://" + addr + "/api/openapi/ATTCK/latestData"
	client := &http.Client{}
	token := "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	for {
		timer := time.NewTimer(interval)
		<-timer.C
		url := fmt.Sprintf("%s?curDataVersion=%d&curSettingVersion=%d", tmpUrl, currentVersion, currentSetVersion)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Tensorsec-cicd-key", token)
		resp, err := client.Do(req)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("request fail")
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		respStrut := lateversionResp{}
		err = json.Unmarshal(body, &respStrut)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("body is null")
			continue
		}
		currentVersion = respStrut.Data.Item.LatestDataVersion
		currentSetVersion = respStrut.Data.Item.LatestSettingVersion
		if !respStrut.Data.Item.DataChanged {
			continue
		}

		ruleBytes, err := base64.StdEncoding.DecodeString(respStrut.Data.Item.Data)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("base64 decode fail")
			continue
		}
		_, rulesContext, _, err := cryption.ReadRulesData(ruleBytes)
		if err != nil {
			logging.GetLogger().Error().Err(err)
			continue
		}
		newChannels, err := config.ParseYamlDiffSet(rulesContext, channelsMap)
		if err != nil {
			logging.GetLogger().Error().Err(err)
			continue
		}
		for _, channel := range newChannels {
			_, err = sc.Subscribe(channel, func(m *stan.Msg) {
				dealHolmesAlert(m, r)
			})
			if err != nil {
				logging.GetLogger().Fatal().Err(err).Str("channel", channel).Msg("Failed to subscribe to falco alert topic")
			}
			channelsMap[channel] = true
			logging.GetLogger().Info().Str("new channel: ", channel).Msg("success")
		}

	}
}

func updateProfile(ctx context.Context, redisClient *redis.Client, clientset *kubernetes.Clientset, m *stan.Msg, kind model.SecurityKind) {
	redisCtx, redisCtxCancel := context.WithTimeout(ctx, 10*time.Second)
	defer redisCtxCancel()
	var f HolmesAlert
	err := json.Unmarshal(m.Data, &f)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to unmarshal message")
		return
	}
	var resource model.SecurityPolicyResource
	podName := f.OutputFields["k8s.pod.name"].(string)
	podNamespace := f.OutputFields["k8s.ns.name"].(string)
	podNameKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, podName)
	x, err := redisClient.Get(redisCtx, podNameKey).Result()
	if err == redis.Nil {
		pod, err := clientset.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get pod")
			return
		}
		containerID := f.OutputFields["container.id"].(string)
		containerKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, containerID)
		containerInfoRaw, err := redisClient.Get(redisCtx, containerKey).Result()
		if err == redis.Nil {
			logging.GetLogger().Error().Err(err).Str("containerID", containerID).Str("pod", podName).Msg("Container name not found")
			return
		} else if err != nil {
			logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get container name from cache")
			return
		}
		var containerInfo model.ContainerInfo
		err = json.Unmarshal([]byte(containerInfoRaw), &containerInfo)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("containerID", containerID).Str("pod", podName).Msg("Failed to unmarshal container info")
			return
		}
		resource, err = getResource(ctx, clientset, pod, containerInfo)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("containerID", containerID).Str("pod", podName).Msg("Failed to get resource")
			return
		}
		resourceRaw, err := json.Marshal(resource)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("containerID", containerID).Str("pod", podName).Msg("Failed to marshal resource")
			return
		}
		err = redisClient.Set(redisCtx, podNameKey, resourceRaw, time.Minute*5).Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("containerID", containerID).Str("pod", podName).Msg("Failed to cache resource")
			return
		}
		return
	} else if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get resource from cache")
		return
	} else {
		err = json.Unmarshal([]byte(x), &resource)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to unmarshal resource")
			return
		}
	}
	resourceKey, err := json.Marshal(resource)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to marshal resource key")
		return
	}
	policyIDRaw, err := redisClient.Get(redisCtx, string(resourceKey)).Result()
	if err == redis.Nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Training not enabled")
		return
	} else if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get cached training status")
		return
	}

	policyID, err := strconv.Atoi(policyIDRaw)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to parse policy ID")
		return
	}
	profileRaw, err := redisClient.Get(redisCtx, model.SecProfileRedisKey+string(kind)+fmt.Sprintf("%d", policyID)).Result()
	var profile model.SecProfileIntermediate
	if err == redis.Nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get cached profile")
		return
	} else if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get cached profile")
		return
	} else {
		err = json.Unmarshal([]byte(profileRaw), &profile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to unmarshal profile")
			return
		}
	}
	if profile.Paused {
		logging.GetLogger().Error().Str("pod", podName).Msg("Profile training is paused")
		return
	}
	if kind == model.SecurityKindApparmor {
		if profile.SecProfileEnvelope.ApparmorProfileData == nil {
			files := make([]model.ApparmorProfileData, 0)
			profile.SecProfileEnvelope.ApparmorProfileData = files
		}
		var mode string
		if f.OutputFields["evt.is_open_write"].(bool) {
			mode = "w"
		} else {
			mode = "r"
		}
		fileIndex := -1
		for i, val := range profile.SecProfileEnvelope.ApparmorProfileData {
			if val.File == f.OutputFields["fd.name"].(string) {
				fileIndex = i
			}
		}
		if fileIndex != -1 {
			if !strings.Contains(profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access, mode) {
				if mode == "r" {
					profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access = "r" + profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access
				} else if mode == "w" {
					profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access = profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access + "w"
				} else {
					logging.GetLogger().Error().Err(err).Str("mode", mode).Str("pod", f.OutputFields["k8s.pod.name"].(string)).Msg("Unknown mode")
					return
				}
				logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"].(string), mode)).Msg("New event added to the profile")
			} else {
				logging.GetLogger().Info().Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"].(string), mode)).Msg("Event already registered in the profile")
				return
			}
		} else {
			if profile.SecProfileEnvelope.ApparmorProfileData == nil {
				profile.SecProfileEnvelope.ApparmorProfileData = make([]model.ApparmorProfileData, 0)
			}
			profile.SecProfileEnvelope.ApparmorProfileData = append(profile.SecProfileEnvelope.ApparmorProfileData, model.ApparmorProfileData{
				File:   f.OutputFields["fd.name"].(string),
				Access: mode,
			})
			profile.NewEventsInTimeFrame = profile.NewEventsInTimeFrame + 1
			logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"].(string), mode)).Msg("New event added to the profile")
		}
	} else if kind == model.SecurityKindCommandWhitelist {
		if profile.SecProfileEnvelope.CommandWhitelistProfileData == nil {
			profile.SecProfileEnvelope.CommandWhitelistProfileData = make([]model.CommandWhitelistProfileData, 0)
		}

		var command string
		cwd := f.OutputFields["proc.cwd"].(string)
		if f.OutputFields["proc.exepath"] == "/bin/bash" {
			args := f.OutputFields["evt.args"].(string)
			argsSplit := strings.Split(args, " ")
			for _, val := range argsSplit {
				if strings.Contains(val, "exe=") {
					command = command + " " + strings.Split(val, "exe=")[1]
				} else if strings.Contains(val, "args=") {
					command = command + " " + strings.Split(val, "args=")[1]
				} else if strings.Contains(val, "filename=") {
					command = strings.Split(val, "filename=")[1]
				}
			}
		} else {
			exeline := f.OutputFields["proc.exeline"].(string)
			exelineSplit := strings.Split(exeline, " ")
			command = f.OutputFields["proc.exepath"].(string)
			command = command + " " + strings.Join(exelineSplit[1:], " ")
		}
		command = strings.TrimSpace(command)
		if strings.LastIndex(command, "(") != -1 && strings.LastIndex(command, ")") == len(command)-1 {
			command = command[(strings.LastIndex(command, "(") + 1):strings.LastIndex(command, ")")]
		}
		command = strings.ReplaceAll(command, "//", "/")
		cwd = strings.TrimSpace(cwd)
		if profile.SecProfileEnvelope.CommandWhitelistProfileData == nil {
			profile.SecProfileEnvelope.CommandWhitelistProfileData = make([]model.CommandWhitelistProfileData, 0)
		}
		alreadyExists := false
		for _, val := range profile.SecProfileEnvelope.CommandWhitelistProfileData {
			if val.Command == command && val.WorkingDirectory == cwd {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			profile.SecProfileEnvelope.CommandWhitelistProfileData = append(profile.SecProfileEnvelope.CommandWhitelistProfileData, model.CommandWhitelistProfileData{
				Command:          command,
				WorkingDirectory: cwd,
			})
			profile.NewEventsInTimeFrame = profile.NewEventsInTimeFrame + 1
			logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", fmt.Sprintf("%s %s", command, cwd)).Msg("New event added to the profile")
		} else {
			logging.GetLogger().Info().Str("event", fmt.Sprintf("%s %s", command, cwd)).Msg("Event already registered in the profile")
			return
		}
	} else if kind == model.SecurityKindSeccomp {
		if profile.SecProfileEnvelope.SeccompProfileData == nil {
			profile.SecProfileEnvelope.SeccompProfileData = make([]model.SeccompProfileData, 0)
		}
		alreadyExists := false
		for _, val := range profile.SecProfileEnvelope.SeccompProfileData {
			if val.Syscall == f.OutputFields["syscall.type"].(string) {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			profile.SecProfileEnvelope.SeccompProfileData = append(profile.SecProfileEnvelope.SeccompProfileData, model.SeccompProfileData{
				Syscall: f.OutputFields["syscall.type"].(string),
			})
			profile.NewEventsInTimeFrame = profile.NewEventsInTimeFrame + 1
			logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", f.OutputFields["syscall.type"].(string)).Msg("New event added to the profile")
		} else {
			logging.GetLogger().Info().Str("event", f.OutputFields["syscall.type"].(string)).Msg("Event already registered in the profile")
			return
		}
	} else {
		logging.GetLogger().Error().Str("kind", string(kind)).Msg("Unknown security profile kind")
		return
	}
	profileMarshalled, err := json.Marshal(profile)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to marshal profile")
		return
	}
	err = redisClient.Set(redisCtx, model.SecProfileRedisKey+string(kind)+fmt.Sprintf("%d", policyID), profileMarshalled, redis.KeepTTL).Err()
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to cache resource")
		return
	}
}

func main() {
	rulesFilename := flag.String("rule",
		"holmes_rules.yaml",
		"Rule file list holmes rules to work")

	flag.Parse()
	var holmesChannels, err = config.ParseYaml(rulesFilename)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to read falco channels")
	}

	redisEndpoint := os.Getenv("REDIS_ENDPOINT")
	if redisEndpoint == "" {
		panic("REDIS_ENDPOINT env variable not set")
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	if redisPassword == "" {
		panic("REDIS_PASSWORD env variable not set")
	}

	// Redis DB client
	sa := strings.Split(redisEndpoint, ",")
	redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: sa,
		Password:      redisPassword,
		DB:            0,
	})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get redis client")
		return
	}

	var config *rest.Config
	config, err = rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get k8s client")
		return
	}
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fmt.Sprintf("status.phase=Running")
	}

	mainCtx := context.Background()

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

	stanURL := os.Getenv("STAN_URL")
	if stanURL == "" {
		panic("STAN_URL env variable not set")
	}
	clusterID := os.Getenv("CLUSTER_ID")
	if clusterID == "" {
		panic("CLUSTER_ID env variable not set")
	}
	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		panic("CLIENT_ID env variable not set")
	}
	myPodName := os.Getenv("MY_POD_NAME")
	if myPodName == "" {
		panic("MY_POD_NAME env variable not set")
	}
	consoleAddr := os.Getenv("CONSOLE_HTTP_ADDR")
	if consoleAddr == "" {
		consoleAddr = "tensorsec-console:8889"
	}

	nc, err := nats.Connect(fmt.Sprintf("nats://%s", stanURL), nats.MaxReconnects(-1), nats.ReconnectBufSize(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		panic("Failed to connect to NATS")
	}
	sc, err := stan.Connect(clusterID, clientID, stan.NatsConn(nc))
	if err != nil {
		panic("Failed to connect to STAN")
	}

	defer sc.Close()

	_, err = sc.Subscribe("command", func(m *stan.Msg) {
		var c model.SecurityProfileCommand
		var profileMarshalled []byte
		var err error
		err = json.Unmarshal(m.Data, &c)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to unmarshal message")
			return
		}
		logging.GetLogger().Info().Str("message", fmt.Sprintf("%+v", c)).Msg("Received message")
		redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 10*time.Second)
		defer redisCtxCancel()
		invalidState := false
		if c.Command == model.SecProfileCommandTrainStart {
			profileIntermediate := model.SecProfileIntermediate{
				SecProfileEnvelope: &model.SecProfileEnvelope{
					Kind: c.Kind,
					Name: fmt.Sprintf("%d", c.PolicyID),
				},
				Whitelist:            c.Whitelist,
				Timeout:              c.Timeout,
				TimeFrame:            c.TimeFrame,
				EventPerTimeFrame:    c.EventPerTimeFrame,
				StartTime:            time.Now(),
				NewEventsInTimeFrame: 0,
				ElapsedTime:          0,
				Paused:               false,
				PolicyID:             c.PolicyID,
			}
			for _, resource := range c.Resources {
				resource.SecurityPolicyID = nil
				resource.ID = 0
				resourceKey, err := json.Marshal(resource)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to marshal resource key")
					invalidState = true
					goto sendMessageInvalidState
				}
				_, err = redisClient.Get(redisCtx, string(resourceKey)).Result()
				if err == redis.Nil {
					// pass
				} else if err != nil {
					logging.GetLogger().Warn().Str("profileKind", string(c.Kind)).Str("resource", fmt.Sprintf("%v", resource)).Msg("Failed to check cache")
					invalidState = true
					goto sendMessageInvalidState
				} else if err == nil {
					logging.GetLogger().Warn().Str("profileKind", string(c.Kind)).Str("resource", fmt.Sprintf("%v", resource)).Msg("Training already enabled")
					invalidState = true
					goto sendMessageInvalidState
				}
				err = redisClient.Set(redisCtx, string(resourceKey), fmt.Sprintf("%d", c.PolicyID), redis.KeepTTL).Err()
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to cache resource")
					invalidState = true
					goto sendMessageInvalidState
				}
			}
			var profileMarshalled []byte
			if c.Kind == model.SecurityKindApparmor {
				newApparmorProfile := make([]model.ApparmorProfileData, 0)
				if c.Whitelist != nil {
					for _, whitelistItem := range c.Whitelist {
						whitelistItemSplit := strings.Split(whitelistItem, " ")
						filename := whitelistItemSplit[0]
						mode := whitelistItemSplit[1]
						newApparmorProfile = append(newApparmorProfile, model.ApparmorProfileData{
							File:   filename,
							Access: mode,
						})
					}
				}
				profileIntermediate.SecProfileEnvelope.ApparmorProfileData = newApparmorProfile
			} else if c.Kind == model.SecurityKindCommandWhitelist {
				newCommandWhitelistProfile := make([]model.CommandWhitelistProfileData, 0)
				if c.Whitelist != nil {
					for _, whitelistItem := range c.Whitelist {
						whitelistItemSplit := strings.Split(whitelistItem, " ")
						executable := strings.Join(whitelistItemSplit[:len(whitelistItemSplit)-1], " ")
						cwd := whitelistItemSplit[len(whitelistItemSplit)-1]
						newCommandWhitelistProfile = append(newCommandWhitelistProfile, model.CommandWhitelistProfileData{
							Command:          executable,
							WorkingDirectory: cwd,
						})
					}
				}
				profileIntermediate.SecProfileEnvelope.CommandWhitelistProfileData = newCommandWhitelistProfile
			} else if c.Kind == model.SecurityKindSeccomp {
				newSeccompProfile := make([]model.SeccompProfileData, 0)
				if c.Whitelist != nil {
					for _, syscall := range c.Whitelist {
						newSeccompProfile = append(newSeccompProfile, model.SeccompProfileData{Syscall: syscall})
					}
				}
				profileIntermediate.SecProfileEnvelope.SeccompProfileData = newSeccompProfile
			} else {
				logging.GetLogger().Error().Str("kind", string(c.Kind)).Msg("Unknown security profile kind")
				invalidState = true
				goto sendMessageInvalidState
			}
			profileMarshalled, err = json.Marshal(profileIntermediate)
			if err != nil {
				logging.GetLogger().Warn().Int("policyID", c.PolicyID).Msg("Failed to marshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			err = redisClient.Set(redisCtx, model.SecProfileRedisKey+string(c.Kind)+fmt.Sprintf("%d", c.PolicyID), profileMarshalled, redis.KeepTTL).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to cache profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			newCommand := model.SecurityProfileCommand{
				Command:           model.SecProfileCommandTrainStarted,
				Resources:         c.Resources,
				PolicyID:          c.PolicyID,
				Kind:              c.Kind,
				Whitelist:         c.Whitelist,
				Timeout:           c.Timeout,
				TimeFrame:         c.TimeFrame,
				EventPerTimeFrame: c.EventPerTimeFrame,
				UpdatedBy:         c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(newCommand)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully started")
		} else if c.Command == model.SecProfileCommandTrainResume {
			redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 10*time.Second)
			defer redisCtxCancel()

			profileRaw, err := redisClient.Get(redisCtx, model.SecProfileRedisKey+string(c.Kind)+fmt.Sprintf("%d", c.PolicyID)).Result()
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to get raw profile")
				invalidState = true
				goto sendMessageInvalidState
			}

			var profile model.SecProfileIntermediate
			err = json.Unmarshal([]byte(profileRaw), &profile)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to unmarshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			profile.Paused = false
			profile.StartTime = time.Now()
			profile.NewEventsInTimeFrame = 0

			profileMarshalled, err = json.Marshal(profile)
			if err != nil {
				logging.GetLogger().Warn().Int("policyID", c.PolicyID).Msg("Failed to marshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			err = redisClient.Set(redisCtx, model.SecProfileRedisKey+string(c.Kind)+fmt.Sprintf("%d", c.PolicyID), profileMarshalled, redis.KeepTTL).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to cache profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			newCommand := model.SecurityProfileCommand{
				Command:           model.SecProfileCommandTrainResumed,
				Resources:         c.Resources,
				PolicyID:          c.PolicyID,
				Kind:              c.Kind,
				Whitelist:         c.Whitelist,
				Timeout:           c.Timeout,
				TimeFrame:         c.TimeFrame,
				EventPerTimeFrame: c.EventPerTimeFrame,
				UpdatedBy:         c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(newCommand)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully resumed")
		} else if c.Command == model.SecProfileCommandTrainSuspend {
			redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 10*time.Second)
			defer redisCtxCancel()
			profileRaw, err := redisClient.Get(redisCtx, model.SecProfileRedisKey+string(c.Kind)+fmt.Sprintf("%d", c.PolicyID)).Result()
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to get raw profile")
				invalidState = true
				goto sendMessageInvalidState
			}

			var profile model.SecProfileIntermediate
			err = json.Unmarshal([]byte(profileRaw), &profile)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to unmarshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			profile.Paused = true
			profile.ElapsedTime = profile.ElapsedTime + int(time.Now().Sub(profile.StartTime).Seconds())

			profileMarshalled, err := json.Marshal(profile)
			if err != nil {
				logging.GetLogger().Warn().Int("policyID", c.PolicyID).Msg("Failed to marshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			err = redisClient.Set(redisCtx, model.SecProfileRedisKey+string(c.Kind)+fmt.Sprintf("%d", c.PolicyID), profileMarshalled, redis.KeepTTL).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to cache profile")
				invalidState = true
				goto sendMessageInvalidState
			}
			newCommand := model.SecurityProfileCommand{
				Command:           model.SecProfileCommandTrainSuspended,
				Resources:         c.Resources,
				PolicyID:          c.PolicyID,
				Kind:              c.Kind,
				Whitelist:         c.Whitelist,
				Timeout:           c.Timeout,
				TimeFrame:         c.TimeFrame,
				EventPerTimeFrame: c.EventPerTimeFrame,
				UpdatedBy:         c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(newCommand)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully paused")
		} else if c.Command == model.SecProfileCommandTrainStop {
			for _, resource := range c.Resources {
				resource.ID = 0
				resource.SecurityPolicyID = nil
				resourceKey, err := json.Marshal(resource)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to marshal resource key")
					invalidState = true
					goto sendMessageInvalidState
				}
				_, err = redisClient.Get(redisCtx, string(resourceKey)).Result()
				if err == redis.Nil {
					logging.GetLogger().Warn().Str("profileKind", string(c.Kind)).Str("resource", fmt.Sprintf("%v", resource)).Msg("Training already stopped")
					invalidState = true
					goto sendMessageInvalidState
				} else if err != nil {
					logging.GetLogger().Warn().Str("profileKind", string(c.Kind)).Str("resource", fmt.Sprintf("%v", resource)).Msg("Failed to check cache")
					invalidState = true
					goto sendMessageInvalidState
				}
				err = redisClient.Del(redisCtx, string(resourceKey)).Err()
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to cache resource")
					invalidState = true
					goto sendMessageInvalidState
				}
			}
			message := model.SecurityProfileCommand{
				Command:   model.SecProfileCommandTrainStopped,
				PolicyID:  c.PolicyID,
				Kind:      c.Kind,
				Resources: c.Resources,
				UpdatedBy: c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(message)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully stopped")
		} else if c.Command == model.SecProfileCommandTrainAbort {
			redisCtx, redisCtxCancel := context.WithTimeout(mainCtx, 10*time.Second)
			defer redisCtxCancel()

			profileRaw, err := redisClient.Get(redisCtx, model.SecProfileRedisKey+string(c.Kind)+string(fmt.Sprintf("%d", c.PolicyID))).Result()
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to get raw profile")
				invalidState = true
				goto sendMessageInvalidState
			}

			var profile model.SecProfileIntermediate
			err = json.Unmarshal([]byte(profileRaw), &profile)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Failed to unmarshal profile")
				invalidState = true
				goto sendMessageInvalidState
			}

			if profile.SecProfileEnvelope.Kind == model.SecurityKindApparmor {
				previousProfile := make([]model.ApparmorProfileData, 0)
				if profile.Whitelist != nil {
					for _, whitelistItem := range profile.Whitelist {
						whitelistItemSplit := strings.Split(whitelistItem, " ")
						filename := whitelistItemSplit[0]
						mode := whitelistItemSplit[1]
						previousProfile = append(previousProfile, model.ApparmorProfileData{
							File:   filename,
							Access: mode,
						})
					}
				}
				profile.SecProfileEnvelope.ApparmorProfileData = previousProfile
			} else if profile.SecProfileEnvelope.Kind == model.SecurityKindCommandWhitelist {
				previousProfile := make([]model.CommandWhitelistProfileData, 0)
				if profile.Whitelist != nil {
					for _, whitelistItem := range profile.Whitelist {
						whitelistItemSplit := strings.Split(whitelistItem, " ")
						executable := whitelistItemSplit[0]
						cwd := whitelistItemSplit[1]
						previousProfile = append(previousProfile, model.CommandWhitelistProfileData{
							Command:          executable,
							WorkingDirectory: cwd,
						})
					}
				}
				profile.SecProfileEnvelope.CommandWhitelistProfileData = previousProfile
			} else if profile.SecProfileEnvelope.Kind == model.SecurityKindSeccomp {
				previousProfile := make([]model.SeccompProfileData, 0)
				if profile.Whitelist != nil {
					for _, syscall := range profile.Whitelist {
						previousProfile = append(previousProfile, model.SeccompProfileData{Syscall: syscall})
					}
				}
				profile.SecProfileEnvelope.SeccompProfileData = previousProfile
			} else {
				logging.GetLogger().Error().Err(err).Int("policyID", c.PolicyID).Msg("Unsupported profile kind")
				invalidState = true
				goto sendMessageInvalidState
			}

			for _, resource := range c.Resources {
				resource.ID = 0
				resource.SecurityPolicyID = nil
				resourceKey, err := json.Marshal(resource)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to marshal resource key")
					invalidState = true
					goto sendMessageInvalidState
				}
				err = redisClient.Del(redisCtx, string(resourceKey)).Err()
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("resourceKey", string(resourceKey)).Msg("Failed to remove resource key from cache")
					invalidState = true
					goto sendMessageInvalidState
				}
			}

			message := model.SecurityProfileCommand{
				Command:   model.SecProfileCommandTrainAborted,
				PolicyID:  c.PolicyID,
				Kind:      c.Kind,
				Resources: c.Resources,
				UpdatedBy: c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(message)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully aborted")
		}
	sendMessageInvalidState:
		if invalidState {
			message := model.SecurityProfileCommand{
				Command:   model.SecProfileCommandInvalidState,
				PolicyID:  c.PolicyID,
				Kind:      c.Kind,
				Resources: c.Resources,
				UpdatedBy: c.UpdatedBy,
			}
			messageRaw, err := json.Marshal(message)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to unmarshal message")
				return
			}
			err = sendMessage(sc, "commandResult", messageRaw)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
				return
			}
			logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Message about invalid state sent")
		}
	})
	if err != nil {
		logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to management topic")
	}

	rp := Reporter{}
	rp.uuidGenerator, err = uuid.NewGenerator()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("uuid.NewGenerator fail")
	}

	rp.cli, err = eventcenter_helper.NewClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("eventcenter_helper.NewClientFromEnv fail")
	}

	for _, channel := range holmesChannels {
		_, err = sc.Subscribe(channel, func(m *stan.Msg) {
			dealHolmesAlert(m, rp)
		})
		if err != nil {
			logging.GetLogger().Fatal().Err(err).Str("channel", fmt.Sprintf("%s", channel)).Msg("Failed to subscribe to falco alert topic")
		}
	}

	_, err = sc.Subscribe("falco.warning.file_integrity_management", func(m *stan.Msg) {
		logging.GetLogger().Info().Msg("Received new apparmor message")
		updateProfile(mainCtx, redisClient, clientset, m, model.SecurityKindApparmor)
	})
	if err != nil {
		logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to apparmor topic")
	}

	_, err = sc.Subscribe("falco.warning.command_whitelist", func(m *stan.Msg) {
		logging.GetLogger().Info().Msg("Received new command whitelist message")
		updateProfile(mainCtx, redisClient, clientset, m, model.SecurityKindCommandWhitelist)
	})
	if err != nil {
		logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to command whitelist topic")
	}

	_, err = sc.Subscribe("falco.warning.seccomp", func(m *stan.Msg) {
		logging.GetLogger().Info().Msg("Received new seccomp message")
		updateProfile(mainCtx, redisClient, clientset, m, model.SecurityKindSeccomp)
	})
	if err != nil {
		logging.GetLogger().Fatal().Err(err).Msg("Failed to subscribe to seccomp topic")
	}
	go updateLatestChannels(sc, holmesChannels, rp, consoleAddr)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	<-sigChan
	stop <- struct{}{}
}

func appendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}
