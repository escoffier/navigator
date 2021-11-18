package queue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/go-redis/redis/v8"
	stan "github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/falco"
	profileService "gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/profile"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"k8s.io/client-go/kubernetes"
)

type QueueService struct {
	conn      *stan.Conn
	mutex     sync.Mutex
	k8sClient *kubernetes.Clientset
	db        *rdbtools.GormWrapper
	tickerMap map[string]*time.Ticker
}

var (
	instance *QueueService
	once     sync.Once
)

type trainingStopChannels struct {
	stop  chan struct{}
	abort chan struct{}
}

func Init(
	ctx context.Context,
	conn *stan.Conn,
	k8sClient *kubernetes.Clientset,
	redisClient *redis.Client,
	db *rdbtools.GormWrapper,

) error {
	once.Do(func() {
		instance = &QueueService{
			conn:      conn,
			mutex:     sync.Mutex{},
			k8sClient: k8sClient,
			db:        db,
		}

		go instance.init(ctx, redisClient)
	})

	return nil
}

func Get() (*QueueService, bool) {
	return instance, instance != nil
}

func updateFalcoRules(ctx context.Context, redisClient *redis.Client) error {
	redisLoopCtx, redisLoopCtxCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer redisLoopCtxCancel()
	iter := redisClient.Scan(redisLoopCtx, 0, model.SecProfileRedisKey+"*", 0).Iterator()
	if err := iter.Err(); err != nil {
		logging.GetLogger().Error().Err(err).Str("key", model.SecProfileRedisKey+"*").Msg("Failed to iterate over cache entries")
		return err
	}
	intermediateProfiles := make([]model.SecProfileIntermediate, 0)
	for iter.Next(redisLoopCtx) {
		profileKey := iter.Val()
		redisCtx, redisCtxCancel := context.WithTimeout(redisLoopCtx, 5*time.Second)
		defer redisCtxCancel()
		profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
		if err == redis.Nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("No cached profile found")
			continue
		} else if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to check cache")
			continue
		}
		var profile model.SecProfileIntermediate
		err = json.Unmarshal([]byte(profileRaw), &profile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to unmarshal cache entry")
			continue
		}
		intermediateProfiles = append(intermediateProfiles, profile)
	}
	falcoService, exists := falco.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get falco service")
		return fmt.Errorf("Failed to get falco service")
	}
	falcoCtx, falcoCtxCancel := context.WithTimeout(ctx, 1*time.Minute)
	defer falcoCtxCancel()
	err := falcoService.AddContentFilterToFalcoRulesConfigMap(falcoCtx, intermediateProfiles)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to refine falco rules with intermediate profiles")
		return err
	}
	err = falcoService.RestartFalco(falcoCtx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to restart falco")
		return err
	}
	logging.GetLogger().Info().Msg("Successfully updated falco with current training whitelist")
	return nil
}

func (s *QueueService) profileController(ctx context.Context, updatedBy string, redisClient *redis.Client, profileKey string, timer <-chan time.Time, ticker *time.Ticker, suspend <-chan struct{}) {
	for {
		select {
		case <-ticker.C:
			s.mutex.Lock()
			logging.GetLogger().Info().Msg("Start periodic profiles update")

			redisCtx, redisCtxCancel := context.WithTimeout(ctx, 30*time.Second)
			defer redisCtxCancel()
			profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
			if err == redis.Nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("No profile found")
				s.mutex.Unlock()
				return
			} else if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to get profile")
				s.mutex.Unlock()
				return
			}

			var profile model.SecProfileIntermediate
			err = json.Unmarshal([]byte(profileRaw), &profile)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to unmarshal profile data")
				s.mutex.Unlock()
				return
			}

			dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
			defer dbcancel()
			var p model.SecurityPolicy

			result := s.db.Get().WithContext(dbctx).Preload(clause.Associations).First(&p, profile.PolicyID)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					logging.GetLogger().Error().Err(result.Error).Msg("Policy with given ID doesn't exist in database")
					return
				}
				logging.GetLogger().Error().Err(result.Error).Msg("Error getting policy from db database")
				return
			}

			if profile.NewEventsInTimeFrame < profile.EventPerTimeFrame {
				logging.GetLogger().Info().
					Int("timeFrame", profile.TimeFrame).
					Int("requestedEventsInTimeFrame", profile.EventPerTimeFrame).
					Int("newEventsInTimeFrame", profile.NewEventsInTimeFrame).
					Str("profileKey", profileKey).
					Msg("Too little new events in a requested timeframe. Requesting training to stop")

				command := model.SecurityProfileCommand{
					Command:   model.SecProfileCommandTrainStop,
					PolicyID:  profile.PolicyID,
					Kind:      profile.SecProfileEnvelope.Kind,
					Resources: p.Resources,
					UpdatedBy: "system",
				}
				b, err := json.Marshal(command)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to marshal training stop command")
					s.mutex.Unlock()
					return
				}
				err = s.SendMessage(b)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("Failed to send training stop message to queue")
					s.mutex.Unlock()
					return
				}
				logging.GetLogger().Info().Str("profileKey", profileKey).Msg("Stop message successfully sent")
			} else {
				logging.GetLogger().Info().
					Int("timeFrame", profile.TimeFrame).
					Int("requestedEventsInTimeFrame", profile.EventPerTimeFrame).
					Int("newEventsInTimeFrame", profile.NewEventsInTimeFrame).
					Str("profileKey", profileKey).
					Msg("Received more events than requested. Continue training")
				profile.NewEventsInTimeFrame = 0
				updatedRawProfile, err := json.Marshal(profile)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to marshal intermediate profile")
					s.mutex.Unlock()
					return
				}
				redisCtx, redisCtxCancel := context.WithTimeout(ctx, 5*time.Second)
				defer redisCtxCancel()

				err = redisClient.Set(redisCtx, profileKey, updatedRawProfile, redis.KeepTTL).Err()
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to cache profile")
					s.mutex.Unlock()
					return
				}
				profileService, exists := profileService.Get()
				if !exists {
					logging.GetLogger().Error().Msg("Failed to get profile service")
					s.mutex.Unlock()
					return
				}

				err = profileService.ReplacePolicyProfile(ctx, profile.PolicyID, profile.SecProfileEnvelope.Kind, &model.ProfileData{
					ApparmorProfileData:         profile.SecProfileEnvelope.ApparmorProfileData,
					SeccompProfileData:          profile.SecProfileEnvelope.SeccompProfileData,
					CommandWhitelistProfileData: profile.SecProfileEnvelope.CommandWhitelistProfileData,
				}, "system")
				if err != nil {
					logging.GetLogger().Error().Err(err).Int("policyID", profile.PolicyID).Msg("Failed to update profile")
					s.mutex.Unlock()
					return
				}

				logging.GetLogger().Info().Int("policyID", profile.PolicyID).Msg("Profile successfully updated")
				logging.GetLogger().Info().Str("profileKey", profileKey).Int("newEventsInTimeFrame", profile.NewEventsInTimeFrame).Msg("Event counter resetted back to 0")
			}
			err = updateFalcoRules(ctx, redisClient)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to update falco rules with intermediate profiles")
			}
			s.mutex.Unlock()
		case <-timer:
			logging.GetLogger().Info().Str("profileKey", profileKey).Msg("Training timeout occured")

			redisCtx, redisCtxCancel := context.WithTimeout(ctx, 30*time.Second)
			defer redisCtxCancel()

			profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
			if err == redis.Nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("No profile found")
				s.mutex.Unlock()
				return
			} else if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to get profile")
				s.mutex.Unlock()
				return
			}

			var profile model.SecProfileIntermediate
			err = json.Unmarshal([]byte(profileRaw), &profile)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to unmarshal profile data")
				s.mutex.Unlock()
				return
			}

			dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
			defer dbcancel()
			var p model.SecurityPolicy

			result := s.db.Get().WithContext(dbctx).Preload(clause.Associations).First(&p, profile.PolicyID)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					logging.GetLogger().Error().Err(result.Error).Msg("Policy with given ID doesn't exist in database")
					return
				}
				logging.GetLogger().Error().Err(result.Error).Msg("Error getting policy from db database")
				return
			}

			command := model.SecurityProfileCommand{
				Command:   model.SecProfileCommandTrainStop,
				PolicyID:  profile.PolicyID,
				Kind:      profile.SecProfileEnvelope.Kind,
				Resources: p.Resources,
				UpdatedBy: "system",
			}
			b, err := json.Marshal(command)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to marshal training stop command")
				return
			}
			err = s.SendMessage(b)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to send training stop message to queue")
				return
			}
			logging.GetLogger().Info().Str("profileKey", profileKey).Msg("Stop message successfully sent")
		case <-suspend:
			logging.GetLogger().Info().Str("profileKey", profileKey).
				Msg("Suspend request received. Gracefully stopping the profile training goroutine without any action on the profile")
			return
		}
	}
}

func (s *QueueService) init(ctx context.Context, redisClient *redis.Client) error {
	falcoTicker := time.NewTicker(1 * time.Hour)
	falcoQuit := make(chan struct{})
	go func() {
		for {
			select {
			case <-falcoTicker.C:
				s.mutex.Lock()
				logging.GetLogger().Info().Msg("Start periodic rules update")
				// err := updateFalcoRules(ctx, redisClient)
				// if err != nil {
				// 	logging.GetLogger().Error().Err(err).Msg("Failed to update falco rules with intermediate profiles")
				// }
				s.mutex.Unlock()
			case <-falcoQuit:
				falcoTicker.Stop()
				logging.GetLogger().Info().Msg("Falco ticker stopped")
				return
			}
		}
	}()

	tickerMap := make(map[string]*time.Ticker)
	suspendMap := make(map[string]chan struct{})

	redisLoopCtx, redisLoopCtxCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer redisLoopCtxCancel()
	iter := redisClient.Scan(redisLoopCtx, 0, model.SecProfileRedisKey+"*", 0).Iterator()
	if err := iter.Err(); err != nil {
		logging.GetLogger().Error().Err(err).Str("key", model.SecProfileRedisKey+"*").Msg("Failed to iterate over cache entries")
		return fmt.Errorf("Failed to get redis iterator: %w", err)
	}
	for iter.Next(redisLoopCtx) {
		profileKey := iter.Val()

		redisCtx, redisCtxCancel := context.WithTimeout(redisLoopCtx, 5*time.Second)
		defer redisCtxCancel()
		profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
		if err == redis.Nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("No cached profile found")
			continue
		} else if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to check cache")
			continue
		}
		var profile model.SecProfileIntermediate
		err = json.Unmarshal([]byte(profileRaw), &profile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to unmarshal cache entry")
			continue
		}

		// TODO - get profile.TimeFrame when this feature is enabled again. Ensure it is set in redis
		ticker := time.NewTicker(time.Duration(profile.TimeFrame*2) * time.Second)
		suspend := make(chan struct{}, 1)

		tickerMap[profileKey] = ticker
		suspendMap[profileKey] = suspend

		timer := time.After((time.Duration(profile.Timeout-int(time.Now().Sub(profile.StartTime).Seconds())) - time.Duration(profile.ElapsedTime)) * time.Second)
		go s.profileController(ctx, "system", redisClient, string(profileKey), timer, ticker, suspend)
	}

	_, err := (*s.conn).Subscribe("commandResult", func(m *stan.Msg) {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		logging.GetLogger().Info().Str("msg", string(m.Data)).Msg("Received a message")
		var param model.SecurityProfileCommand
		err := json.Unmarshal(m.Data, &param)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to unmarshal message")
			return
		}

		if param.Command == model.SecProfileCommandInvalidState {
			logging.GetLogger().Error().
				Str("command", string(param.Command)).
				Int("policyID", param.PolicyID).
				Msg("Received information about invalid state. Contact administrator to analyse logs")
			return
		}

		profileKey := model.SecProfileRedisKey + string(param.Kind) + fmt.Sprintf("%d", param.PolicyID)

		redisCtx, redisCtxCancel := context.WithTimeout(ctx, 30*time.Second)
		defer redisCtxCancel()
		profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
		if err == redis.Nil {
			logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("No profile found")
			return
		} else if err != nil {
			logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to get profile")
			return
		}

		var profile model.SecProfileIntermediate
		err = json.Unmarshal([]byte(profileRaw), &profile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to unmarshal profile data")
			return
		}

		if param.Command == model.SecProfileCommandTrainAborted {
			profileService, exists := profileService.Get()
			if !exists {
				logging.GetLogger().Error().Msg("Failed to get profile service")
				return
			}

			err = profileService.ReplacePolicyProfile(ctx, param.PolicyID, profile.SecProfileEnvelope.Kind, &model.ProfileData{
				ApparmorProfileData:         profile.SecProfileEnvelope.ApparmorProfileData,
				SeccompProfileData:          profile.SecProfileEnvelope.SeccompProfileData,
				CommandWhitelistProfileData: profile.SecProfileEnvelope.CommandWhitelistProfileData,
			}, "system")
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile")
				return
			}

			err = s.setTrainingAbortedStatus(ctx, param.PolicyID, param.Kind)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile status in DB")
				return
			}

			err = redisClient.Del(redisCtx, profileKey).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to remove profile key from cache")
				return
			}
			val, ok := tickerMap[string(profileKey)]
			if !ok {
				logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Ticker for given profile not found")
				return
			}
			val.Stop()
			delete(tickerMap, string(profileKey))
			delete(suspendMap, string(profileKey))

			err = updateFalcoRules(ctx, redisClient)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to update rules in falco")
				return
			}

			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Training successfully aborted")
		} else if param.Command == model.SecProfileCommandTrainSuspended {
			err = s.setTrainingSuspendedStatus(ctx, param.PolicyID, param.Kind)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile status in DB")
				return
			}

			val, ok := suspendMap[string(profileKey)]
			if !ok {
				logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Ticker for given profile not found")
				return
			}
			val <- struct{}{}
			delete(tickerMap, string(profileKey))
			delete(suspendMap, string(profileKey))
			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Training successfully suspended")
		} else if param.Command == model.SecProfileCommandTrainResumed {
			err = s.setTrainingResumedStatus(ctx, param.PolicyID, param.Kind)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile status in DB")
				return
			}

			ticker := time.NewTicker(time.Duration(profile.TimeFrame) * time.Second)
			suspend := make(chan struct{}, 1)

			tickerMap[string(profileKey)] = ticker
			suspendMap[string(profileKey)] = suspend

			timer := time.After((time.Duration(profile.Timeout-int(time.Now().Sub(profile.StartTime).Seconds())) - time.Duration(profile.ElapsedTime)) * time.Second)
			go s.profileController(ctx, param.UpdatedBy, redisClient, profileKey, timer, ticker, suspend)
			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Training successfully resumed")
		} else if param.Command == model.SecProfileCommandTrainStopped {
			profileService, exists := profileService.Get()
			if !exists {
				logging.GetLogger().Error().Msg("Failed to get profile service")
				return
			}

			err = s.setTrainingStoppedStatus(ctx, param.PolicyID, param.Kind)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile status in DB")
				return
			}

			err = profileService.ReplacePolicyProfile(ctx, param.PolicyID, param.Kind, &model.ProfileData{
				ApparmorProfileData:         profile.SecProfileEnvelope.ApparmorProfileData,
				SeccompProfileData:          profile.SecProfileEnvelope.SeccompProfileData,
				CommandWhitelistProfileData: profile.SecProfileEnvelope.CommandWhitelistProfileData,
			}, "system")
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile")
				return
			}

			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Profile successfully updated")

			err = redisClient.Del(redisCtx, profileKey).Err()
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to remove profile key from cache")
				return
			}
			val, ok := tickerMap[string(profileKey)]
			if !ok {
				logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Ticker for given profile not found")
				return
			}
			val.Stop()
			delete(tickerMap, profileKey)
			delete(suspendMap, profileKey)

			err = updateFalcoRules(ctx, redisClient)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to update rules in falco")
				return
			}

			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Training successfully stopped")

			// TODO: Enable when fix falco to send events when pod restarts

			// if secProfileKind == model.SecProfileKindApparmor {
			// 	close(s.apparmorTimerMap[profileName])
			// 	delete(s.apparmorTimerMap, profileName)
			// } else if secProfileKind == model.SecProfileKindCommandWhitelist {
			// 	close(s.driftPreventionTimerMap[profileName])
			// 	delete(s.driftPreventionTimerMap, profileName)
			// } else if secProfileKind == model.SecProfileKindSeccomp {
			// 	close(s.seccompTimerMap[profileName])
			// 	delete(s.seccompTimerMap, profileName)
			// }
		} else if param.Command == model.SecProfileCommandTrainStarted {
			err = updateFalcoRules(ctx, redisClient)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to add profile rules from falco")
				return
			}
			logging.GetLogger().Info().Int("policyID", param.PolicyID).Msg("Training successfully started")

			err = s.setTrainingStartedStatus(ctx, param.PolicyID, param.Kind, profile.Timeout, profile.StartTime)
			if err != nil {
				logging.GetLogger().Error().Err(err).Int("policyID", param.PolicyID).Msg("Failed to update profile status in DB")
				return
			}

			ticker := time.NewTicker(time.Duration(profile.TimeFrame) * time.Second)
			suspend := make(chan struct{}, 1)

			tickerMap[string(profileKey)] = ticker
			suspendMap[string(profileKey)] = suspend

			timer := time.After((time.Duration(profile.Timeout-int(time.Now().Sub(profile.StartTime).Seconds())) - time.Duration(profile.ElapsedTime)) * time.Second)
			go s.profileController(ctx, param.UpdatedBy, redisClient, profileKey, timer, ticker, suspend)

			// TODO: Enable when fix falco to send events when pod restarts

			// ticker := time.NewTicker(6 * time.Minute)
			// quit := make(chan struct{})
			// if secProfileKind == model.SecProfileKindApparmor {
			// 	s.apparmorTimerMap[profileName] = quit
			// } else if secProfileKind == model.SecProfileKindCommandWhitelist {
			// 	s.driftPreventionTimerMap[profileName] = quit
			// } else if secProfileKind == model.SecProfileKindSeccomp {
			// 	s.seccompTimerMap[profileName] = quit
			// }
			// go func() {
			// 	for {
			// 		select {
			// 		case <-ticker.C:
			// 			pods, err := getPodsFromResource(context.Background(), param.ResourceForSecurityProfile.ResourceKind, s.k8sClient, param.ResourceForSecurityProfile.ResourceName, param.ResourceForSecurityProfile.ResourceNamespace)
			// 			if err != nil {
			// 				logging.GetLogger().Error().Err(err).Str("name", param.ResourceForSecurityProfile.ResourceName).Str("kind", string(param.ResourceForSecurityProfile.ResourceKind)).Str("namespace", param.ResourceForSecurityProfile.ResourceNamespace).Msg("Failed to get pods for resource")
			// 				return
			// 			}
			// 			randomIndex := rand.Intn(len(pods))
			// 			pod := pods[randomIndex]
			// 			err = s.k8sClient.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
			// 			if err != nil {
			// 				logging.GetLogger().Error().Err(err).Str("pod", pod.Name).Str("name", param.ResourceForSecurityProfile.ResourceName).Str("kind", string(param.ResourceForSecurityProfile.ResourceKind)).Str("namespace", param.ResourceForSecurityProfile.ResourceNamespace).Msg("Failed to restart pod for resource")
			// 				return
			// 			}
			// 		case <-quit:
			// 			ticker.Stop()
			// 			return
			// 		}
			// 	}
			// }()
		} else {
			logging.GetLogger().Error().Str("command", string(param.Command)).Msg("Unknown command")
		}
	})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to subscribe to 'commandResult' subject")
		return err
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	<-sigChan
	falcoQuit <- struct{}{}

	redisLoopCtx, redisLoopCtxCancel = context.WithTimeout(ctx, 5*time.Minute)
	defer redisLoopCtxCancel()
	iter = redisClient.Scan(redisLoopCtx, 0, model.SecProfileRedisKey+"*", 0).Iterator()
	if err := iter.Err(); err != nil {
		logging.GetLogger().Error().Err(err).Str("key", model.SecProfileRedisKey+"*").Msg("Failed to iterate over cache entries")
		return fmt.Errorf("Failed to get redis iterator: %w", err)
	}
	profileService, exists := profileService.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get profile service")
		return fmt.Errorf("Failed to get profile service")
	}
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	for iter.Next(redisLoopCtx) {
		profileKey := iter.Val()
		redisCtx, redisCtxCancel := context.WithTimeout(redisLoopCtx, 5*time.Second)
		defer redisCtxCancel()
		profileRaw, err := redisClient.Get(redisCtx, profileKey).Result()
		if err == redis.Nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("No cached profile found")
			continue
		} else if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to check cache")
			continue
		}
		var profile model.SecProfileIntermediate
		err = json.Unmarshal([]byte(profileRaw), &profile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to unmarshal cache entry")
			continue
		}

		err = profileService.ReplacePolicyProfile(ctx, profile.PolicyID, profile.SecProfileEnvelope.Kind, &model.ProfileData{
			ApparmorProfileData:         profile.SecProfileEnvelope.ApparmorProfileData,
			SeccompProfileData:          profile.SecProfileEnvelope.SeccompProfileData,
			CommandWhitelistProfileData: profile.SecProfileEnvelope.CommandWhitelistProfileData,
		}, "system")
		if err != nil {
			logging.GetLogger().Error().Err(err).Int("policyID", profile.PolicyID).Msg("Failed to update profile")
			continue
		}

		err = s.setTrainingAbortedStatus(ctx, profile.PolicyID, profile.SecProfileEnvelope.Kind)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int("policyID", profile.PolicyID).Msg("Failed to update profile status in DB")
			continue
		}

		err = redisClient.Del(redisCtx, profileKey).Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Int("policyID", profile.PolicyID).Msg("Failed to remove profile key from cache")
			continue
		}
		val, ok := tickerMap[string(profileKey)]
		if !ok {
			logging.GetLogger().Error().Int("policyID", profile.PolicyID).Msg("Ticker for given profile not found")
			continue
		}
		val.Stop()
		delete(tickerMap, string(profileKey))

		var p model.SecurityPolicy

		result := s.db.Get().WithContext(dbctx).Preload(clause.Associations).First(&p, profile.PolicyID)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				logging.GetLogger().Error().Err(result.Error).Msg("Policy with given ID doesn't exist in database")
				continue
			}
			logging.GetLogger().Error().Err(result.Error).Msg("Error getting policy from db database")
			continue
		}

		command := model.SecurityProfileCommand{
			Command:   model.SecProfileCommandTrainAbort,
			PolicyID:  profile.PolicyID,
			Kind:      profile.SecProfileEnvelope.Kind,
			Resources: p.Resources,
			UpdatedBy: "system",
		}
		b, err := json.Marshal(command)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("profileKey", profileKey).Msg("Failed to marshal training abort command")
			continue
		}
		err = s.SendMessage(b)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to send training abort message to queue")
			continue
		}
		logging.GetLogger().Info().Str("profileKey", profileKey).Msg("Abort message successfully sent")
	}

	err = updateFalcoRules(ctx, redisClient)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to update falco rules")
		return err
	}
	return nil
}

func (s *QueueService) SendMessage(msg []byte) error {
	logging.GetLogger().Info().Str("msg", string(msg)).Msg("Sending a message to STAN")
	err := (*s.conn).Publish("command", msg)
	return err
}

func (s *QueueService) setTrainingStartedStatus(ctx context.Context, policyID int, profileKind model.SecurityKind, timeout int, startTime time.Time) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change training status of an active policy"))
		}

		if profileKind == model.SecurityKindApparmor {
			p.ApparmorProfile.ElapsedTime = 0
			p.ApparmorProfile.StartTrainingTime = &startTime
			p.ApparmorProfile.TrainingStatus = model.TrainingStatusInProgress
			p.ApparmorProfile.TrainingTimeout = timeout
			p.ApparmorProfile.SecurityPolicyID = policyID
			p.ApparmorProfile.ResumeTrainingTime = nil
			p.ApparmorProfile.SuspendTrainingTime = nil
			p.ApparmorProfile.StopTrainingTime = nil
			p.ApparmorProfile.AbortTrainingTime = nil
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			p.CommandWhitelistProfile.ElapsedTime = 0
			p.CommandWhitelistProfile.StartTrainingTime = &startTime
			p.CommandWhitelistProfile.TrainingStatus = model.TrainingStatusInProgress
			p.CommandWhitelistProfile.TrainingTimeout = timeout
			p.CommandWhitelistProfile.SecurityPolicyID = policyID
			p.CommandWhitelistProfile.ResumeTrainingTime = nil
			p.CommandWhitelistProfile.SuspendTrainingTime = nil
			p.CommandWhitelistProfile.StopTrainingTime = nil
			p.CommandWhitelistProfile.AbortTrainingTime = nil
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			p.SeccompProfile.ElapsedTime = 0
			p.SeccompProfile.StartTrainingTime = &startTime
			p.SeccompProfile.TrainingStatus = model.TrainingStatusInProgress
			p.SeccompProfile.TrainingTimeout = timeout
			p.SeccompProfile.ResumeTrainingTime = nil
			p.SeccompProfile.SuspendTrainingTime = nil
			p.SeccompProfile.StopTrainingTime = nil
			p.SeccompProfile.SecurityPolicyID = policyID
			p.SeccompProfile.AbortTrainingTime = nil
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *QueueService) setTrainingStoppedStatus(ctx context.Context, policyID int, profileKind model.SecurityKind) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change training status of an active policy"))
		}

		endTime := time.Now()
		var resumeTime time.Time
		if profileKind == model.SecurityKindApparmor {
			if p.ApparmorProfile.ResumeTrainingTime != nil {
				resumeTime = *p.ApparmorProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.ApparmorProfile.StartTrainingTime
			}
			p.ApparmorProfile.ElapsedTime = p.ApparmorProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.ApparmorProfile.StopTrainingTime = &endTime
			p.ApparmorProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if p.CommandWhitelistProfile.ResumeTrainingTime != nil {
				resumeTime = *p.CommandWhitelistProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.CommandWhitelistProfile.StartTrainingTime
			}
			p.CommandWhitelistProfile.ElapsedTime = p.CommandWhitelistProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.CommandWhitelistProfile.StopTrainingTime = &endTime
			p.CommandWhitelistProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if p.SeccompProfile.ResumeTrainingTime != nil {
				resumeTime = *p.SeccompProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.SeccompProfile.StartTrainingTime
			}
			p.SeccompProfile.ElapsedTime = p.SeccompProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.SeccompProfile.StopTrainingTime = &endTime
			p.SeccompProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *QueueService) setTrainingAbortedStatus(ctx context.Context, policyID int, profileKind model.SecurityKind) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change training status of an active policy"))
		}

		endTime := time.Now()
		var resumeTime time.Time
		if profileKind == model.SecurityKindApparmor {
			if p.ApparmorProfile.ResumeTrainingTime != nil {
				resumeTime = *p.ApparmorProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.ApparmorProfile.StartTrainingTime
			}
			p.ApparmorProfile.ElapsedTime = p.ApparmorProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.ApparmorProfile.AbortTrainingTime = &endTime
			p.ApparmorProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if p.CommandWhitelistProfile.ResumeTrainingTime != nil {
				resumeTime = *p.CommandWhitelistProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.CommandWhitelistProfile.StartTrainingTime
			}
			p.CommandWhitelistProfile.ElapsedTime = p.CommandWhitelistProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.CommandWhitelistProfile.AbortTrainingTime = &endTime
			p.CommandWhitelistProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if p.SeccompProfile.ResumeTrainingTime != nil {
				resumeTime = *p.SeccompProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.SeccompProfile.StartTrainingTime
			}
			p.SeccompProfile.ElapsedTime = p.SeccompProfile.ElapsedTime + int(endTime.Sub(resumeTime).Seconds())
			p.SeccompProfile.AbortTrainingTime = &endTime
			p.SeccompProfile.TrainingStatus = model.TrainingStatusNotStarted
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *QueueService) setTrainingResumedStatus(ctx context.Context, policyID int, profileKind model.SecurityKind) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change training status of an active policy"))
		}

		resumeTime := time.Now()
		if profileKind == model.SecurityKindApparmor {
			p.ApparmorProfile.ResumeTrainingTime = &resumeTime
			p.ApparmorProfile.TrainingStatus = model.TrainingStatusInProgress
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			p.CommandWhitelistProfile.ResumeTrainingTime = &resumeTime
			p.CommandWhitelistProfile.TrainingStatus = model.TrainingStatusInProgress
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			p.SeccompProfile.ResumeTrainingTime = &resumeTime
			p.SeccompProfile.TrainingStatus = model.TrainingStatusInProgress
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *QueueService) setTrainingSuspendedStatus(ctx context.Context, policyID int, profileKind model.SecurityKind) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change training status of an active policy"))
		}

		suspendTime := time.Now()
		var resumeTime time.Time
		if profileKind == model.SecurityKindApparmor {
			if p.ApparmorProfile.ResumeTrainingTime != nil {
				resumeTime = *p.ApparmorProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.ApparmorProfile.StartTrainingTime
			}
			p.ApparmorProfile.ElapsedTime = p.ApparmorProfile.ElapsedTime + int(suspendTime.Sub(resumeTime).Seconds())
			p.ApparmorProfile.TrainingStatus = model.TrainingStatusPaused
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if p.CommandWhitelistProfile.ResumeTrainingTime != nil {
				resumeTime = *p.CommandWhitelistProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.CommandWhitelistProfile.StartTrainingTime
			}
			p.CommandWhitelistProfile.ElapsedTime = p.CommandWhitelistProfile.ElapsedTime + int(suspendTime.Sub(resumeTime).Seconds())
			p.CommandWhitelistProfile.TrainingStatus = model.TrainingStatusPaused
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if p.SeccompProfile.ResumeTrainingTime != nil {
				resumeTime = *p.SeccompProfile.ResumeTrainingTime
			} else {
				resumeTime = *p.SeccompProfile.StartTrainingTime
			}
			p.SeccompProfile.ElapsedTime = p.SeccompProfile.ElapsedTime + int(suspendTime.Sub(resumeTime).Seconds())
			p.SeccompProfile.TrainingStatus = model.TrainingStatusPaused
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}
