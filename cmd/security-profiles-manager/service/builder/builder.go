package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/queue"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type SecProfileBuilderService struct {
	db          *rdbtools.GormWrapper
	redisClient *redis.Client
	mutex       *sync.Mutex
	k8sClient   *kubernetes.Clientset
}

var (
	instance *SecProfileBuilderService
	once     sync.Once
)

func Init(
	ctx context.Context,
	db *rdbtools.GormWrapper,
	redisClient *redis.Client,
	k8sClient *kubernetes.Clientset,
) error {
	once.Do(func() {
		instance = &SecProfileBuilderService{
			db:          db,
			redisClient: redisClient,
			mutex:       &sync.Mutex{},
			k8sClient:   k8sClient,
		}
	})

	return nil
}

func Get() (*SecProfileBuilderService, bool) {
	return instance, instance != nil
}

func (s *SecProfileBuilderService) getPodsFromResource(ctx context.Context, kind model.KubernetesResource, k8sClient *kubernetes.Clientset, name, namespace string) ([]corev1.Pod, error) {
	var appName string
	var ok bool
	if kind == model.KubernetesResourceDaemonset {
		resource, err := k8sClient.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceReplicaSet {
		resource, err := k8sClient.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceDeployment {
		resource, err := k8sClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceStatefulset {
		resource, err := k8sClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceJob {
		resource, err := k8sClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceCronJob {
		resource, err := s.k8sClient.BatchV1beta1().CronJobs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else {
		return nil, NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown security profile kind: %s", kind))
	}

	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": appName,
		},
	}
	listOpts := metav1.ListOptions{LabelSelector: labels.Set(labelSelector.MatchLabels).String()}

	podList, err := k8sClient.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, err
	}
	return podList.Items, nil
}

func (s *SecProfileBuilderService) StartTraining(ctx context.Context, policyID int, profileKind model.SecurityKind, username string) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	var p model.SecurityPolicy
	intermediateQuery := s.db.Get().WithContext(dbctx)

	if profileKind == model.SecurityKindApparmor {
		intermediateQuery = intermediateQuery.Preload("ApparmorProfile.ApparmorProfileData")
	} else if profileKind == model.SecurityKindCommandWhitelist {
		intermediateQuery = intermediateQuery.Preload("CommandWhitelistProfile.CommandWhitelistProfileData")
	} else if profileKind == model.SecurityKindSeccomp {
		intermediateQuery = intermediateQuery.Preload("SeccompProfile.SeccompProfileData")
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}
	result := intermediateQuery.Preload(clause.Associations).First(&p, policyID)
	if result.Error != nil {
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
		}
		return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
	}

	if p.Active {
		return NewPolicyError(http.StatusBadRequest, fmt.Errorf("Cannot start training for active profile"))
	}

	if len(p.Resources) <= 0 {
		return NewCannotStartTrainingThatIsEmptyResourcesError(http.StatusBadRequest, fmt.Errorf("Cannot start training for policy's empty resources"))
	}
	var timeout int
	whitelist := make([]string, 0)
	if profileKind == model.SecurityKindApparmor {
		if p.ApparmorProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotStartTrainingThatIsInProgressError(http.StatusBadRequest, fmt.Errorf("Cannot start an in progress training"))
		}
		if p.ApparmorProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotStartAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot start a paused training"))
		}
		timeout = p.ApparmorProfile.TrainingTimeout
		if p.SeccompProfile.TrainingStartWhitelistOption == model.TrainingStartWhitelistOptionFromCurrentProfile {
			for _, entry := range p.ApparmorProfile.ApparmorProfileData {
				whitelist = append(whitelist, fmt.Sprintf("%s %s", entry.File, entry.Access))
			}
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		if p.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotStartTrainingThatIsInProgressError(http.StatusBadRequest, fmt.Errorf("Cannot start an in progress training"))
		}
		if p.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotStartAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot start a paused training"))
		}
		timeout = p.CommandWhitelistProfile.TrainingTimeout
		if p.SeccompProfile.TrainingStartWhitelistOption == model.TrainingStartWhitelistOptionFromCurrentProfile {
			for _, entry := range p.CommandWhitelistProfile.CommandWhitelistProfileData {
				whitelist = append(whitelist, fmt.Sprintf("%s %s", entry.Command, entry.WorkingDirectory))
			}
		}
	} else if profileKind == model.SecurityKindSeccomp {
		if p.SeccompProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotStartTrainingThatIsInProgressError(http.StatusBadRequest, fmt.Errorf("Cannot start an in progress training"))
		}
		if p.SeccompProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotStartAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot start a paused training"))
		}
		timeout = p.SeccompProfile.TrainingTimeout
		if p.SeccompProfile.TrainingStartWhitelistOption == model.TrainingStartWhitelistOptionFromCurrentProfile {
			for _, entry := range p.SeccompProfile.SeccompProfileData {
				whitelist = append(whitelist, entry.Syscall)
			}
		}
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}
	command := model.SecurityProfileCommand{
		Command:           model.SecProfileCommandTrainStart,
		Resources:         p.Resources,
		Whitelist:         whitelist,
		PolicyID:          p.ID,
		Kind:              profileKind,
		Timeout:           timeout,
		TimeFrame:         2 * timeout,
		EventPerTimeFrame: 0,
		UpdatedBy:         username,
	}
	b, err := json.Marshal(command)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare queue message: %w", err))
	}
	queueService, exists := queue.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get queue service")
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get queue service"))
	}

	err = queueService.SendMessage(b)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to send message to queue: %w", err))
	}
	logging.GetLogger().Info().Int("policy", p.ID).Str("profile", string(profileKind)).Msg("Profile train start request sent")

	return nil
}

func (s *SecProfileBuilderService) AbortTraining(ctx context.Context, policy *model.SecurityPolicy, profileKind model.SecurityKind, username string) error {
	if profileKind == model.SecurityKindApparmor {
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotAbortNonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot abort a non-started training"))
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotAbortNonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot abort a non-started training"))
		}
	} else if profileKind == model.SecurityKindSeccomp {
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotAbortNonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot abort a non-started training"))
		}
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}
	command := model.SecurityProfileCommand{
		Command:   model.SecProfileCommandTrainAbort,
		PolicyID:  policy.ID,
		Kind:      profileKind,
		Resources: policy.Resources,
		UpdatedBy: username,
	}
	b, err := json.Marshal(command)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare queue message: %w", err))
	}
	queueService, exists := queue.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get queue service")
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get queue service"))
	}
	err = queueService.SendMessage(b)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to send message to queue: %w", err))
	}
	logging.GetLogger().Info().Int("policy", policy.ID).Str("profile", string(profileKind)).Msg("Profile train abort request sent")

	return nil
}

func (s *SecProfileBuilderService) SuspendTraining(ctx context.Context, policy *model.SecurityPolicy, profileKind model.SecurityKind, username string) error {
	if profileKind == model.SecurityKindApparmor {
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotSuspendANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a non-started training"))
		}
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotSuspendAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a paused training"))
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotSuspendANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a non-started training"))
		}
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotSuspendAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a paused training"))
		}
	} else if profileKind == model.SecurityKindSeccomp {
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotSuspendANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a non-started training"))
		}
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusPaused {
			return NewCannotSuspendAPausedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot suspend a paused training"))
		}
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}

	command := model.SecurityProfileCommand{
		Command:   model.SecProfileCommandTrainSuspend,
		PolicyID:  policy.ID,
		Kind:      profileKind,
		Resources: policy.Resources,
		UpdatedBy: username,
	}
	b, err := json.Marshal(command)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare queue message: %w", err))
	}
	queueService, exists := queue.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get queue service")
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get queue service"))
	}
	err = queueService.SendMessage(b)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to send message to queue: %w", err))
	}
	logging.GetLogger().Info().Int("policy", policy.ID).Str("profile", string(profileKind)).Msg("Profile train suspend request sent")

	return nil
}

func (s *SecProfileBuilderService) ResumeTraining(ctx context.Context, policy *model.SecurityPolicy, profileKind model.SecurityKind, username string) error {
	if profileKind == model.SecurityKindApparmor {
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotResumeANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume a non-started training"))
		}
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotResumeAnInProgressTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume an in progress training"))
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotResumeANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume a non-started training"))
		}
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotResumeAnInProgressTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume an in progress training"))
		}
	} else if profileKind == model.SecurityKindSeccomp {
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotResumeANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume a non-started training"))
		}
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusInProgress {
			return NewCannotResumeAnInProgressTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot resume an in progress training"))
		}
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}

	command := model.SecurityProfileCommand{
		Command:   model.SecProfileCommandTrainResume,
		PolicyID:  policy.ID,
		Kind:      profileKind,
		Resources: policy.Resources,
		UpdatedBy: username,
	}
	b, err := json.Marshal(command)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare queue message: %w", err))
	}
	queueService, exists := queue.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get queue service")
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get queue service"))
	}
	err = queueService.SendMessage(b)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to send message to queue: %w", err))
	}
	logging.GetLogger().Info().Int("policy", policy.ID).Str("profile", string(profileKind)).Msg("Profile train resume request sent")

	return nil
}

func (s *SecProfileBuilderService) StopTraining(ctx context.Context, policy *model.SecurityPolicy, profileKind model.SecurityKind, username string) error {
	if profileKind == model.SecurityKindApparmor {
		if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotStopANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot stop a non-started training"))
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotStopANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot stop a non-started training"))
		}
	} else if profileKind == model.SecurityKindSeccomp {
		if policy.SeccompProfile.TrainingStatus == model.TrainingStatusNotStarted {
			return NewCannotStopANonStartedTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot stop a non-started training"))
		}
	} else {
		return NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}
	command := model.SecurityProfileCommand{
		Command:   model.SecProfileCommandTrainStop,
		PolicyID:  policy.ID,
		Kind:      profileKind,
		Resources: policy.Resources,
		UpdatedBy: username,
	}
	b, err := json.Marshal(command)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare queue message: %w", err))
	}
	queueService, exists := queue.Get()
	if !exists {
		logging.GetLogger().Error().Msg("Failed to get queue service")
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get queue service"))
	}
	err = queueService.SendMessage(b)
	if err != nil {
		return NewPolicyTrainingError(http.StatusInternalServerError, fmt.Errorf("Failed to send message to queue: %w", err))
	}
	logging.GetLogger().Info().Int("policy", policy.ID).Str("profile", string(profileKind)).Msg("Profile train stop request sent")

	return nil
}
