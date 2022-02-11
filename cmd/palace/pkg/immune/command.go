package immune

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	CommandSubject       = "command"
	CommandResultSubject = "commandResult"
)

func CommandHandler(m *stan.Msg) {
	mainCtx := context.Background()

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
	if len(c.Resources) == 0 {
		logging.GetLogger().Error().Msg("Resources is nil")
		invalidState = true
		goto sendMessageInvalidState
	}
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
		logging.GetLogger().Debug().Msgf("%#v", c.Kind)
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
		err = sendMessage(CommandResultSubject, messageRaw)
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
		err = sendMessage(CommandResultSubject, messageRaw)
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
		profile.ElapsedTime += int(time.Since(profile.StartTime).Seconds())

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
		err = sendMessage(CommandResultSubject, messageRaw)
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
		err = sendMessage(CommandResultSubject, messageRaw)
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
		err = sendMessage(CommandResultSubject, messageRaw)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
			return
		}
		logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Training successfully aborted")
	}
sendMessageInvalidState:
	if invalidState {
		logging.GetLogger().Error().Msgf("%+v", c)
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
		err = sendMessage(CommandResultSubject, messageRaw)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Failed to send message")
			return
		}
		logging.GetLogger().Info().Str("profileKind", string(c.Kind)).Str("policy", fmt.Sprintf("%d", c.PolicyID)).Msg("Message about invalid state sent")
	}
}
