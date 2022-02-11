package immune

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/go-redis/redis/v8"
	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	FileRWSubject  = "falco.warning.file_integrity_management"
	CmdSubject     = "falco.warning.command_whitelist"
	SyscallSubject = "falco.warning.seccomp"
)

func getResource(ctx context.Context, pod *corev1.Pod, containerInfo model.ContainerInfo) (model.SecurityPolicyResource, error) {
	namespace := pod.Namespace
	owner := metav1.GetControllerOf(pod)
	name := pod.Name
	kind := string(model.KubernetesResourcePod)
	if owner != nil {
		name = strings.ToLower(owner.Name)
		kind = strings.ToLower(owner.Kind)
		if kind == string(model.KubernetesResourceReplicaSet) {
			replicaset, err := k8sClientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, name, metav1.GetOptions{})
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

func UpdateProfile(ctx context.Context, m *stan.Msg, kind model.SecurityKind) {
	redisCtx, redisCtxCancel := context.WithTimeout(ctx, 10*time.Second)
	defer redisCtxCancel()
	var f outputs.Response
	err := proto.Unmarshal(m.Data, &f)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to unmarshal message")
		return
	}
	var resource model.SecurityPolicyResource
	podName := f.OutputFields["k8s.pod.name"]
	podNamespace := f.OutputFields["k8s.ns.name"]
	podNameKey := fmt.Sprintf("%s-%s", model.EventProcessorRedisKey, podName)
	x, err := redisClient.Get(redisCtx, podNameKey).Result()
	if err == redis.Nil {
		pod, err := k8sClientset.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("pod", podName).Msg("Failed to get pod")
			return
		}
		containerID := f.OutputFields["container.id"]
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
		resource, err = getResource(ctx, pod, containerInfo)
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
		if f.OutputFields["evt.is_open_write"] == "true" {
			mode = "w"
		} else {
			mode = "r"
		}
		fileIndex := -1
		for i, val := range profile.SecProfileEnvelope.ApparmorProfileData {
			if val.File == f.OutputFields["fd.name"] {
				fileIndex = i
			}
		}
		if fileIndex != -1 {
			if !strings.Contains(profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access, mode) {
				if mode == "r" {
					profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access = "r" + profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access
				} else if mode == "w" {
					profile.SecProfileEnvelope.ApparmorProfileData[fileIndex].Access += "w"
				} else {
					logging.GetLogger().Error().Err(err).Str("mode", mode).Str("pod", f.OutputFields["k8s.pod.name"]).Msg("Unknown mode")
					return
				}
				logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"], mode)).Msg("New event added to the profile")
			} else {
				logging.GetLogger().Info().Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"], mode)).Msg("Event already registered in the profile")
				return
			}
		} else {
			if profile.SecProfileEnvelope.ApparmorProfileData == nil {
				profile.SecProfileEnvelope.ApparmorProfileData = make([]model.ApparmorProfileData, 0)
			}
			profile.SecProfileEnvelope.ApparmorProfileData = append(profile.SecProfileEnvelope.ApparmorProfileData, model.ApparmorProfileData{
				File:   f.OutputFields["fd.name"],
				Access: mode,
			})
			profile.NewEventsInTimeFrame++
			logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", fmt.Sprintf("%s %s", f.OutputFields["fd.name"], mode)).Msg("New event added to the profile")
		}
	} else if kind == model.SecurityKindCommandWhitelist {
		if profile.SecProfileEnvelope.CommandWhitelistProfileData == nil {
			profile.SecProfileEnvelope.CommandWhitelistProfileData = make([]model.CommandWhitelistProfileData, 0)
		}

		var command string
		cwd := f.OutputFields["proc.cwd"]
		if f.OutputFields["proc.exepath"] == "/bin/bash" {
			args := f.OutputFields["evt.args"]
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
			exeline := f.OutputFields["proc.exeline"]
			exelineSplit := strings.Split(exeline, " ")
			command = f.OutputFields["proc.exepath"]
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
			profile.NewEventsInTimeFrame++
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
			if val.Syscall == f.OutputFields["syscall.type"] {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			profile.SecProfileEnvelope.SeccompProfileData = append(profile.SecProfileEnvelope.SeccompProfileData, model.SeccompProfileData{
				Syscall: f.OutputFields["syscall.type"],
			})
			profile.NewEventsInTimeFrame++
			logging.GetLogger().Info().Int("current_event_count", profile.NewEventsInTimeFrame).Str("event", f.OutputFields["syscall.type"]).Msg("New event added to the profile")
		} else {
			logging.GetLogger().Info().Str("event", f.OutputFields["syscall.type"]).Msg("Event already registered in the profile")
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
