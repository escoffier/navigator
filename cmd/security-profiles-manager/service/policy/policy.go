package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/builder"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/falco"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	apparmorBaseProfile = `
	#include <tunables/global>

	profile %s flags=(attach_disconnected) {
	#include <abstractions/base>

	allow /** ix,
	network,
	ptrace,
	pivot_root,
	signal,
	dbus,
	unix,

	allow /tmp/dp.so rm,
	allow /var/log/drift-prevention.log rw,
	allow /etc/hosts r,
	allow /tmp/whitelist.txt r,
	allow /tmp/commands.txt r,
	deny /tmp/file-checker rwx,

`
	seccompProfileTemplate = `
	{
		"defaultAction": "%s",
		"architectures": [
			"SCMP_ARCH_X86_64",
			"SCMP_ARCH_X86",
			"SCMP_ARCH_X32"
		],
		"syscalls": [
			{
				"names": [
					"execveat",
					%s
				],
				"action": "SCMP_ACT_ALLOW"
			}
		]
	}
`
)

type profileToRemove struct {
	profile string
	kind    model.SecurityKind
}

type profileToAdd struct {
	profile              string
	kind                 model.SecurityKind
	mode                 model.SecurityMode
	apparmorData         []model.ApparmorProfileData
	seccompData          []model.SeccompProfileData
	commandWhitelistData []model.CommandWhitelistProfileData
}

type SecPolicyService struct {
	db                            *rdbtools.GormWrapper
	mutex                         sync.Mutex
	k8sClient                     *kubernetes.Clientset
	namespace                     string
	secProfilesContainerConfigMap string
}

var (
	instance *SecPolicyService
	once     sync.Once
)

func Init(
	db *rdbtools.GormWrapper,
	kubeClient *kubernetes.Clientset,
) error {
	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE environment variable not set")
	}
	secProfilesContainerConfigMap := os.Getenv("SEC_PROFILES_CONTAINER_CONFIGMAP")
	if secProfilesContainerConfigMap == "" {
		return fmt.Errorf("SEC_PROFILES_CONTAINER_CONFIGMAP environment variable not set")
	}
	once.Do(func() {
		instance = &SecPolicyService{
			db:                            db,
			mutex:                         sync.Mutex{},
			k8sClient:                     kubeClient,
			namespace:                     myNamespace,
			secProfilesContainerConfigMap: secProfilesContainerConfigMap,
		}
	})

	return nil
}

func Get() (*SecPolicyService, bool) {
	return instance, instance != nil
}

func (s *SecPolicyService) ListPolicies(ctx context.Context, offset int, limit int, search string, sortBy string, sortOrder string) ([]model.SecurityPolicy, int, error) {
	var policies []model.SecurityPolicy
	var totalCount int64

	dbctx, dbcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dbcancel()
	partialQuery := s.db.Get().WithContext(dbctx)

	if search != "" {
		sqlSearch := "%" + search + "%"
		partialQuery = partialQuery.Where("description LIKE ? OR name LIKE ? OR author LIKE ? OR updated_by LIKE ?",
			sqlSearch, sqlSearch, sqlSearch, sqlSearch)
	}
	var sort string
	if sortOrder == "asc" {
		sort = sortBy
	} else {
		sort = fmt.Sprintf("%s %s", sortBy, sortOrder)
	}

	result := partialQuery.Order(sort).Offset(offset).Limit(limit).Find(&policies).
		Offset(-1).Limit(-1).Count(&totalCount)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return policies, int(totalCount), nil
		}
		return policies, int(totalCount), PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when listing policies in database: %w", result.Error))
	}

	return policies, int(totalCount), nil
}

func (s *SecPolicyService) AddResoruceToPolicy(ctx context.Context, policyID, resourceID int) (*model.SecurityPolicy, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()
	var p model.SecurityPolicy

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}
		if p.Active {
			return NewCannotAddResourceToActivePolicyError(http.StatusInternalServerError, fmt.Errorf("Cannot add resource to active policy"))
		}
		if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
			return NewCannotAddResourceToPolicyInTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot add resource to policy - there are still profiles being trained"))
		}
		var r model.SecurityPolicyResource

		result = tx.WithContext(dbctx).Where("id = ?", resourceID).Preload(clause.Associations).First(&r)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewResourceNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}
		if r.SecurityPolicyID == nil {
			r.SecurityPolicyID = &policyID
			result := tx.WithContext(dbctx).Save(&r)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating security resource in db: %w", result.Error))
			}
		} else if *r.SecurityPolicyID == p.ID {
			return NewResourceAlreadyAttachedToPolicyError(http.StatusInternalServerError, fmt.Errorf("Resource already attached to requested policy: %w", result.Error))
		} else if *r.SecurityPolicyID > 0 {
			return NewResourceAttachedToDifferentPolicyError(http.StatusInternalServerError, fmt.Errorf("Resource already attached to another policy %d: %w", r.SecurityPolicyID, result.Error))
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	var err error
	policy, err := s.GetPolicy(ctx, s.db.Get(), policyID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) RemoveResourceFromPolicy(ctx context.Context, policyID, resourceID int) (*model.SecurityPolicy, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()
	var p model.SecurityPolicy

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewCannotRemoveResourceFromActivePolicyError(http.StatusInternalServerError, fmt.Errorf("Cannot remove resource from active policy"))
		}
		if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
			return NewCannotRemoveResourceFromPolicyInTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot remove resource from policy - there are still profiles being trained"))
		}

		resourceAttached := false
		for _, attachedResources := range p.Resources {
			if attachedResources.ID == resourceID {
				resourceAttached = true
				var r model.SecurityPolicyResource
				result = tx.WithContext(dbctx).Where("id = ?", resourceID).Preload(clause.Associations).First(&r)
				if result.Error != nil {
					if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
						return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
					}
					return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
				}
				r.SecurityPolicyID = nil
				// TODO: design choice - should profiles be removed from resource when detached from policy? Currently no
				result = tx.WithContext(dbctx).Save(&r)
				if result.Error != nil {
					return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating resource in database: %w", result.Error))
				}
			}
		}
		if !resourceAttached {
			return NewResourceNotAttachedToPolicyError(http.StatusInternalServerError, fmt.Errorf("Resource was not attached to policy"))
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	var err error
	policy, err := s.GetPolicy(ctx, s.db.Get(), policyID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) GetPolicy(ctx context.Context, db *gorm.DB, policyID int) (*model.SecurityPolicy, error) {
	if db == nil {
		db = s.db.Get()
	}
	var policy model.SecurityPolicy

	dbctx, dbcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dbcancel()

	result := db.WithContext(dbctx).
		Preload(clause.Associations).
		First(&policy, policyID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, NewPolicyNotFoundError(http.StatusNotFound, fmt.Errorf("Policy with given ID doesn't exist in database: %w", result.Error))
		}
		return nil, PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
	}
	if policy.ApparmorProfile.TrainingStatus == model.TrainingStatusInProgress {
		if policy.ApparmorProfile.StartTrainingTime == nil {
			return nil, NewMissingStartTrainingTimeInTrainedProfileError(http.StatusInternalServerError, fmt.Errorf("Missing 'startTrainingTime' in in training profile"))
		}
		currentTime := *policy.ApparmorProfile.StartTrainingTime
		if policy.ApparmorProfile.ResumeTrainingTime != nil {
			currentTime = *policy.ApparmorProfile.ResumeTrainingTime
		}
		policy.ApparmorProfile.ElapsedTime = policy.ApparmorProfile.ElapsedTime + int(time.Now().Sub(currentTime).Seconds())
	}
	if policy.CommandWhitelistProfile.TrainingStatus == model.TrainingStatusInProgress {
		if policy.CommandWhitelistProfile.StartTrainingTime == nil {
			return nil, NewMissingStartTrainingTimeInTrainedProfileError(http.StatusInternalServerError, fmt.Errorf("Missing 'startTrainingTime' in in training profile"))
		}
		currentTime := *policy.CommandWhitelistProfile.StartTrainingTime
		if policy.CommandWhitelistProfile.ResumeTrainingTime != nil {
			currentTime = *policy.CommandWhitelistProfile.ResumeTrainingTime
		}
		policy.CommandWhitelistProfile.ElapsedTime = policy.CommandWhitelistProfile.ElapsedTime + int(time.Now().Sub(currentTime).Seconds())
	}
	if policy.SeccompProfile.TrainingStatus == model.TrainingStatusInProgress {
		if policy.SeccompProfile.StartTrainingTime == nil {
			return nil, NewMissingStartTrainingTimeInTrainedProfileError(http.StatusInternalServerError, fmt.Errorf("Missing 'startTrainingTime' in in training profile"))
		}
		currentTime := *policy.SeccompProfile.StartTrainingTime
		if policy.SeccompProfile.ResumeTrainingTime != nil {
			currentTime = *policy.SeccompProfile.ResumeTrainingTime
		}
		policy.SeccompProfile.ElapsedTime = policy.SeccompProfile.ElapsedTime + int(time.Now().Sub(currentTime).Seconds())
	}
	return &policy, nil
}

func (s *SecPolicyService) SetSecurityMode(ctx context.Context, db *gorm.DB, policyID int, data model.SecurityPolicyModeChangeRequest, username string) (*model.SecurityPolicy, error) {
	if db == nil {
		db = s.db.Get()
	}
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	if data.Mode == nil {
		return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
	}

	txErr := db.Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).
			Preload("CommandWhitelistProfile.CommandWhitelistProfileData").
			Preload("SeccompProfile.SeccompProfileData").
			Preload("ApparmorProfile.ApparmorProfileData").
			Preload(clause.Associations).
			First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}

		oldStatus := p.Mode
		p.Mode = *data.Mode
		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		result = tx.WithContext(dbctx).
			Omit("CommandWhitelistProfile.CommandWhitelistProfileData").
			Omit("SeccompProfile.SeccompProfileData").
			Omit("ApparmorProfile.ApparmorProfileData").
			Omit(clause.Associations).Save(&p)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}

		if p.Active && oldStatus != *data.Mode {
			profilesToAdd := make([]profileToAdd, 0)
			if p.ApparmorProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:      fmt.Sprintf("%s-%d", model.SecurityKindApparmor, p.ID),
					kind:         model.SecurityKindApparmor,
					mode:         p.Mode,
					apparmorData: p.ApparmorProfile.ApparmorProfileData,
				})
			}
			if p.SeccompProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:     fmt.Sprintf("%s-%d", model.SecurityKindSeccomp, p.ID),
					kind:        model.SecurityKindSeccomp,
					mode:        p.Mode,
					seccompData: p.SeccompProfile.SeccompProfileData,
				})
			}
			if p.CommandWhitelistProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:              fmt.Sprintf("%s-%d", model.SecurityKindCommandWhitelist, p.ID),
					kind:                 model.SecurityKindCommandWhitelist,
					mode:                 p.Mode,
					commandWhitelistData: p.CommandWhitelistProfile.CommandWhitelistProfileData,
				})
			}

			err := s.updateProfiles(ctx, profilesToAdd)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profiles", fmt.Sprintf("%v", profilesToAdd)).Msg("Failed to build profiles. Contact admin")
				return NewProfileUpdateError(http.StatusInternalServerError, fmt.Errorf("Error when updating profiles: %w", err))
			}
			// TODO: fix race condition between when profile is distributed across nodes and pod restart
			time.Sleep(5 * time.Second)
			for _, r := range p.Resources {
				err = s.RestartPods(ctx, r.Kind, r.Namespace, r.Name)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("resource", fmt.Sprintf("%v", r)).Msg("Failed to restart resource. Contact admin")
				}
			}
		}

		return nil
	})
	logging.GetLogger().Info().Str("mode", fmt.Sprintf("%v", data)).Int("policy", policyID).Msg("Mode changed")
	if txErr != nil {
		return nil, txErr
	}
	policy, err := s.GetPolicy(ctx, db, policyID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) SetStatus(ctx context.Context, db *gorm.DB, policyID int, data model.SecurityPolicyStatusChangeRequest, username string) (*model.SecurityPolicy, error) {
	if db == nil {
		db = s.db.Get()
	}
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	if data.Enabled == nil {
		return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
	}

	txErr := db.Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy
		result := tx.WithContext(dbctx).
			Preload("CommandWhitelistProfile.CommandWhitelistProfileData").
			Preload("SeccompProfile.SeccompProfileData").
			Preload("ApparmorProfile.ApparmorProfileData").
			Preload(clause.Associations).
			First(&p, policyID)

		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}
		if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted ||
			p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
			return NewCannotChangePolicyStatusAreInTrainingError(http.StatusBadRequest, fmt.Errorf("Cannot change policy status - there are still profiles being trained"))
		}
		oldStatus := p.Active
		p.Active = *data.Enabled
		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		result = tx.WithContext(dbctx).
			Omit("CommandWhitelistProfile.CommandWhitelistProfileData").
			Omit("SeccompProfile.SeccompProfileData").
			Omit("ApparmorProfile.ApparmorProfileData").
			Omit(clause.Associations).Save(&p)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}

		if !oldStatus && *data.Enabled {
			profilesToAdd := make([]profileToAdd, 0)
			if p.ApparmorProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:      fmt.Sprintf("%s-%d", model.SecurityKindApparmor, p.ID),
					kind:         model.SecurityKindApparmor,
					mode:         p.Mode,
					apparmorData: p.ApparmorProfile.ApparmorProfileData,
				})
			}
			if p.SeccompProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:     fmt.Sprintf("%s-%d", model.SecurityKindSeccomp, p.ID),
					kind:        model.SecurityKindSeccomp,
					mode:        p.Mode,
					seccompData: p.SeccompProfile.SeccompProfileData,
				})
			}
			if p.CommandWhitelistProfile.Enabled {
				profilesToAdd = append(profilesToAdd, profileToAdd{
					profile:              fmt.Sprintf("%s-%d", model.SecurityKindCommandWhitelist, p.ID),
					kind:                 model.SecurityKindCommandWhitelist,
					mode:                 p.Mode,
					commandWhitelistData: p.CommandWhitelistProfile.CommandWhitelistProfileData,
				})
			}

			err := s.updateProfiles(ctx, profilesToAdd)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profiles", fmt.Sprintf("%v", profilesToAdd)).Msg("Failed to build profiles. Contact admin")
				return NewProfileUpdateError(http.StatusInternalServerError, fmt.Errorf("Error when updating profiles: %w", err))
			}
			// TODO: fix race condition between when profile is distributed across nodes and pod restart
			time.Sleep(5 * time.Second)
			for _, r := range p.Resources {
				err = s.RestartPods(ctx, r.Kind, r.Namespace, r.Name)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("resource", fmt.Sprintf("%v", r)).Msg("Failed to restart resource. Contact admin")
				}
			}
		} else if oldStatus && !(*data.Enabled) { // !p.Active
			profilesToRemove := make([]profileToRemove, 0)
			if p.ApparmorProfile.Enabled {
				profilesToRemove = append(profilesToRemove, profileToRemove{
					profile: fmt.Sprintf("%s-%d", model.SecurityKindApparmor, p.ID),
					kind:    model.SecurityKindApparmor,
				})
			}
			if p.SeccompProfile.Enabled {
				profilesToRemove = append(profilesToRemove, profileToRemove{
					profile: fmt.Sprintf("%s-%d", model.SecurityKindSeccomp, p.ID),
					kind:    model.SecurityKindSeccomp,
				})
			}
			if p.CommandWhitelistProfile.Enabled {
				profilesToRemove = append(profilesToRemove, profileToRemove{
					profile: fmt.Sprintf("%s-%d", model.SecurityKindCommandWhitelist, p.ID),
					kind:    model.SecurityKindCommandWhitelist,
				})
			}
			err := s.removeProfiles(ctx, profilesToRemove)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profiles", fmt.Sprintf("%+v", profilesToRemove)).Msg("Failed to remove profile. Contact admin")
				return NewProfileUpdateError(http.StatusInternalServerError, fmt.Errorf("Error when updating profiles: %w", err))
			}
			// TODO: fix race condition between when profile is distributed across nodes and pod restart
			time.Sleep(5 * time.Second)
			for _, r := range p.Resources {
				err = s.RestartPods(ctx, r.Kind, r.Namespace, r.Name)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("resource", fmt.Sprintf("%v", r)).Msg("Failed to restart resource. Contact admin")
				}
			}
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	logging.GetLogger().Info().Str("status", fmt.Sprintf("%v", data)).Int("policy", policyID).Msg("Status changed")
	policy, err := s.GetPolicy(ctx, db, policyID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) DeletePolicy(ctx context.Context, secPolicyID int, username string) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		p, err := s.GetPolicy(ctx, tx, secPolicyID)
		if err != nil {
			return err
		}
		if p.Active {
			return NewCannotDeleteActivePolicyError(http.StatusBadRequest, fmt.Errorf("Cannot delete active policy"))
		}

		builderService, exists := builder.Get()
		if !exists {
			logging.GetLogger().Error().Msg("Failed to get builder service")
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get falco service"))
		}

		if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted {
			err = builderService.AbortTraining(ctx, p, model.SecurityKindApparmor, username)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profile", string(model.SecurityKindApparmor)).Msg("Failed to abort training. Contact admin")
			}
		}
		if p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted {
			err = builderService.AbortTraining(ctx, p, model.SecurityKindSeccomp, username)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profile", string(model.SecurityKindSeccomp)).Msg("Failed to abort training. Contact admin")
			}
		}
		if p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
			err = builderService.AbortTraining(ctx, p, model.SecurityKindCommandWhitelist, username)
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("profile", string(model.SecurityKindCommandWhitelist)).Msg("Failed to abort training. Contact admin")
			}
		}
		result := tx.WithContext(dbctx).Delete(&model.SecurityPolicy{}, secPolicyID)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when deleting policy: %w", result.Error))
		}
		return nil
	})
	logging.GetLogger().Info().Int("policy", secPolicyID).Msg("Policy deleted")

	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *SecPolicyService) AddPolicy(ctx context.Context, data model.SecurityPolicyAddRequest, username string) (*model.SecurityPolicy, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	if data.Description == nil || data.Name == nil {
		return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
	}

	var p model.SecurityPolicy

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		p = model.SecurityPolicy{
			Name:                      *data.Name,
			Author:                    username,
			UpdatedBy:                 username,
			Description:               *data.Description,
			CreatedAt:                 time.Now(),
			UpdatedAt:                 time.Now(),
			Mode:                      model.SecurityModeDetection,
			Active:                    false,
			ResourceImageChangeAction: model.ResourceImageChangeActionChangeToAudit,
		}
		result := tx.WithContext(dbctx).Create(&p)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating policy in database: %w", result.Error))
		}

		apparmorProfile := model.ApparmorProfile{
			Enabled:                      false,
			SecurityPolicyID:             p.ID,
			TrainingTimeout:              86400,
			TrainingStartWhitelistOption: model.TrainingStartWhitelistOptionFromCurrentProfile,
			TrainingStatus:               model.TrainingStatusNotStarted,
			TimeFrame:                    999999999,
		}
		result = tx.WithContext(dbctx).Create(&apparmorProfile)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating apparmor profile in database: %w", result.Error))
		}

		seccompProfile := model.SeccompProfile{
			Enabled:                      false,
			SecurityPolicyID:             p.ID,
			TrainingTimeout:              86400,
			TrainingStartWhitelistOption: model.TrainingStartWhitelistOptionFromCurrentProfile,
			TrainingStatus:               model.TrainingStatusNotStarted,
			TimeFrame:                    999999999,
		}
		result = tx.WithContext(dbctx).Create(&seccompProfile)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating seccomp profile in database: %w", result.Error))
		}

		defaultSyscalls := make([]model.SeccompProfileData, 0)
		for _, syscall := range falco.DefaultSyscallWhitelist {
			defaultSyscalls = append(defaultSyscalls, model.SeccompProfileData{
				Syscall:          syscall,
				SeccompProfileID: seccompProfile.ID,
			})
		}
		seccompProfile.SeccompProfileData = defaultSyscalls

		result = tx.WithContext(dbctx).Create(&seccompProfile.SeccompProfileData)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
		}

		commandWhitelistProfile := model.CommandWhitelistProfile{
			Enabled:                      false,
			SecurityPolicyID:             p.ID,
			TrainingTimeout:              86400,
			TrainingStartWhitelistOption: model.TrainingStartWhitelistOptionFromCurrentProfile,
			TrainingStatus:               model.TrainingStatusNotStarted,
			TimeFrame:                    999999999,
		}
		result = tx.WithContext(dbctx).Create(&commandWhitelistProfile)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating command whitelist profile in database: %w", result.Error))
		}

		driftProfile := model.DriftProfile{
			Enabled:          false,
			SecurityPolicyID: &p.ID,
		}
		result = tx.WithContext(dbctx).Create(&driftProfile)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating drift profile in database: %w", result.Error))
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	logging.GetLogger().Info().Int("policy", p.ID).Msg("Policy created")

	policy, err := s.GetPolicy(ctx, s.db.Get(), p.ID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) UpdatePolicyProfile(ctx context.Context, policyID int, profileKind model.SecurityKind, data model.SecurityPolicyProfilePutRequest, username string) (*model.SecurityPolicy, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	var p model.SecurityPolicy

	if profileKind == model.SecurityKindDrift {
		if data.Enabled == nil {
			return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
		}
	} else {
		if data.Enabled == nil || data.Timeout == nil || data.TrainingStartWhitelistOption == nil {
			return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
		}
	}

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}

		if profileKind == model.SecurityKindApparmor {
			if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateConfigOfCurrentlyTrainedProfileError(http.StatusBadRequest, fmt.Errorf("Cannot update configuration of currently trained profile"))
			}
			previousEnabled := p.ApparmorProfile.Enabled
			if previousEnabled != *data.Enabled && p.Active {
				return NewCannotChangeProfileStatusWhenPolicyIsActiveError(http.StatusBadRequest, fmt.Errorf("Cannot change status of a given profile when policy is active"))
			}
			p.ApparmorProfile.Enabled = *data.Enabled
			p.ApparmorProfile.TrainingTimeout = *data.Timeout
			p.ApparmorProfile.TrainingStartWhitelistOption = *data.TrainingStartWhitelistOption
			result = tx.WithContext(dbctx).Save(&p.ApparmorProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateConfigOfCurrentlyTrainedProfileError(http.StatusBadRequest, fmt.Errorf("Cannot update configuration of currently trained profile"))
			}
			previousEnabled := p.CommandWhitelistProfile.Enabled
			if previousEnabled != *data.Enabled && p.Active {
				return NewCannotChangeProfileStatusWhenPolicyIsActiveError(http.StatusBadRequest, fmt.Errorf("Cannot enable a given profile when policy is active"))
			}
			p.CommandWhitelistProfile.Enabled = *data.Enabled
			p.CommandWhitelistProfile.TrainingTimeout = *data.Timeout
			p.CommandWhitelistProfile.TrainingStartWhitelistOption = *data.TrainingStartWhitelistOption
			result = tx.WithContext(dbctx).Save(&p.CommandWhitelistProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateConfigOfCurrentlyTrainedProfileError(http.StatusBadRequest, fmt.Errorf("Cannot update configuration of currently trained profile"))
			}
			previousEnabled := p.SeccompProfile.Enabled
			if previousEnabled != *data.Enabled && p.Active {
				return NewCannotChangeProfileStatusWhenPolicyIsActiveError(http.StatusBadRequest, fmt.Errorf("Cannot enable a given profile when policy is active"))
			}
			p.SeccompProfile.Enabled = *data.Enabled
			p.SeccompProfile.TrainingTimeout = *data.Timeout
			p.SeccompProfile.TrainingStartWhitelistOption = *data.TrainingStartWhitelistOption
			result = tx.WithContext(dbctx).Save(&p.SeccompProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		} else if profileKind == model.SecurityKindDrift {
			previousEnabled := p.SeccompProfile.Enabled
			if previousEnabled != *data.Enabled && p.Active {
				return NewCannotChangeProfileStatusWhenPolicyIsActiveError(http.StatusBadRequest, fmt.Errorf("Cannot enable a given profile when policy is active"))
			}
			p.DriftProfile.Enabled = *data.Enabled
			result = tx.WithContext(dbctx).Save(&p.DriftProfile)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
			}
		}

		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		result = tx.WithContext(dbctx).Save(&p)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}

		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	logging.GetLogger().Info().Int("policy", p.ID).Str("profile", string(profileKind)).Msg("Policy profile patched")

	policy, err := s.GetPolicy(ctx, s.db.Get(), p.ID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) UpdatePolicy(ctx context.Context, policyID int, data model.SecurityPolicyPutRequest, username string) (*model.SecurityPolicy, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	var p model.SecurityPolicy

	if data.Name == nil || data.Description == nil || data.ResourceImageChangeAction == nil {
		return nil, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("Missing required fields"))
	}

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		result := tx.WithContext(dbctx).First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}
		p.Description = *data.Description
		p.Name = *data.Name
		p.ResourceImageChangeAction = *data.ResourceImageChangeAction
		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		logging.GetLogger().Info().Int("policy", policyID).Msg("Policy updated. About to persist")
		result = tx.WithContext(dbctx).Save(&p)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	logging.GetLogger().Info().Int("policy", p.ID).Msg("Policy updated")

	policy, err := s.GetPolicy(ctx, s.db.Get(), p.ID)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *SecPolicyService) removeProfiles(ctx context.Context, profilesToRemove []profileToRemove) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	configMap, err := s.k8sClient.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.secProfilesContainerConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}

	for _, profileToRemove := range profilesToRemove {
		profileName := profileToRemove.profile
		if _, ok := configMap.Data[profileName]; !ok {
			logging.GetLogger().Warn().Str("profile", profileName).Msg("Profile does not exist")
		}
		delete(configMap.Data, profileName)
	}

	_, err = s.k8sClient.CoreV1().ConfigMaps(s.namespace).Update(ctx, configMap, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	logging.GetLogger().Info().Str("profiles", fmt.Sprintf("%+v", profilesToRemove)).Msg("Profiles are removed")
	return nil
}

func (s *SecPolicyService) updateProfiles(ctx context.Context, profilesToAdd []profileToAdd) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	configMap, err := s.k8sClient.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.secProfilesContainerConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, p := range profilesToAdd {
		profileContent := string(p.mode) + "\n"
		if p.kind == model.SecurityKindSeccomp {
			syscalls := make([]string, 0)
			for _, s := range p.seccompData {
				syscalls = append(syscalls, fmt.Sprintf("\"%s\"", s.Syscall))
			}
			syscallsStr := strings.Join(syscalls, ",\n")
			var seccompMode string
			if p.mode == model.SecurityModePrevention {
				seccompMode = "SCMP_ACT_KILL"
			} else if p.mode == model.SecurityModeDetection {
				seccompMode = "SCMP_ACT_LOG"
			}
			profileContent = profileContent + fmt.Sprintf(seccompProfileTemplate, seccompMode, syscallsStr)
			logging.GetLogger().Info().Str("profileName", p.profile).Msg("Seccomp profile is prepared")
		} else if p.kind == model.SecurityKindApparmor {
			// TODO: we can extend apparmor to do whitelisting of executables
			profileContent = profileContent + fmt.Sprintf(apparmorBaseProfile, p.profile)

			for _, file := range p.apparmorData {
				if file.File != "/tmp/dp.so" && file.File != "/var/log/drift-prevention.log" && file.File != "/etc/hosts" && file.File != "/etc/resolv.conf" {
					profileContent = fmt.Sprintf("%s\nallow %s %s,", profileContent, file.File, file.Access)
				}
			}

			profileContent = fmt.Sprintf("%s\n}", profileContent)
			logging.GetLogger().Info().Str("profileName", p.profile).Msg("Apparmor profile is prepared")
		} else if p.kind == model.SecurityKindCommandWhitelist {
			for _, cmd := range p.commandWhitelistData {
				profileContent = profileContent + fmt.Sprintf("%s %s\n", cmd.Command, cmd.WorkingDirectory)
			}
			logging.GetLogger().Info().Str("profileName", p.profile).Msg("CommandWhitelist profile is prepared")
		} else {
			logging.GetLogger().Error().Str("kind", string(p.kind)).Msg("Unsupported security profile kind")
			return fmt.Errorf("Unsupported profile kind %s", p.kind)
		}
		if configMap.Data == nil {
			configMap.Data = make(map[string]string)
		}
		if _, ok := configMap.Data[p.profile]; !ok {
			logging.GetLogger().Info().Str("profile", p.profile).Msg("Profile not found")
		}
		configMap.Data[p.profile] = profileContent
	}

	_, err = s.k8sClient.CoreV1().ConfigMaps(s.namespace).Update(ctx, configMap, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	logging.GetLogger().Info().Str("profiles", fmt.Sprintf("%+v", profilesToAdd)).Msg("Profiles are updated")
	return nil
}

func (s *SecPolicyService) RestartPods(ctx context.Context, kind model.KubernetesResource, namespace, name string) error {
	var appName string
	var ok bool
	if kind == model.KubernetesResourceDaemonset {
		resource, err := s.k8sClient.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceReplicaSet {
		resource, err := s.k8sClient.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceDeployment {
		resource, err := s.k8sClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceStatefulset {
		resource, err := s.k8sClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceJob {
		resource, err := s.k8sClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else if kind == model.KubernetesResourceCronJob {
		resource, err := s.k8sClient.BatchV1beta1().CronJobs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get resource: %w", err))
		}
		if resource.Labels == nil {
			resource.Labels = make(map[string]string)
		}
		appName, ok = resource.Labels["app"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("No \"app\" label in resource: %w", err))
		}
	} else {
		return NewKubernetesError(http.StatusBadRequest, fmt.Errorf("Unknown security profile kind: %s", kind))
	}

	options := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", appName),
	}

	podList, err := s.k8sClient.CoreV1().Pods(namespace).List(ctx, options)
	if err != nil {
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to get pods: %w", err))
	}
	for _, pod := range podList.Items {
		s.k8sClient.CoreV1().Pods(namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	}

	return nil
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func (s *SecPolicyService) AddResource(ctx context.Context, resource model.SecurityPolicyResource) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var secresource model.SecurityPolicyResource

		result := tx.WithContext(dbctx).
			Preload(clause.Associations).
			Where("cluster = ? and name = ? and namespace = ? and kind = ? and container_name = ?", resource.Cluster, resource.Name, resource.Namespace, resource.Kind, resource.ContainerName).First(&secresource)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				// Create new security resource for security profiles
				newResource := model.SecurityPolicyResource{
					Cluster:          "default",
					Name:             resource.Name,
					Kind:             resource.Kind,
					Namespace:        resource.Namespace,
					ContainerName:    resource.ContainerName,
					ImageRegistry:    resource.ImageRegistry,
					ImageName:        resource.ImageName,
					ImageTag:         resource.ImageTag,
					SecurityPolicyID: nil,
				}
				result := tx.WithContext(dbctx).Create(&newResource)
				if result.Error != nil {
					return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when creating new resource: %w", result.Error))
				}
			} else {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource: %w", result.Error))
			}
		} else { // err == nil
			secresource.ImageRegistry = resource.ImageRegistry
			secresource.ImageName = resource.ImageName
			secresource.ImageTag = resource.ImageTag
			result := tx.WithContext(dbctx).Save(&secresource)
			if result.Error != nil {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when updating resource: %w", result.Error))
			}
			if secresource.SecurityPolicyID != nil {
				var p model.SecurityPolicy
				result := tx.WithContext(dbctx).Preload(clause.Associations).First(&p, *secresource.SecurityPolicyID)
				if result.Error != nil {
					if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
						return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
					}
					return NewPolicyNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
				}
				if p.ResourceImageChangeAction == model.ResourceImageChangeActionChangeToAudit {
					newMode := model.SecurityModeDetection
					if p.Mode == model.SecurityModePrevention {
						_, err := s.SetSecurityMode(ctx, tx, p.ID, model.SecurityPolicyModeChangeRequest{
							Mode: &newMode,
						}, "system")
						if err != nil {
							return err
						}
					}
				} else if p.ResourceImageChangeAction == model.ResourceImageChangeActionPolicyDisable {
					if p.Active {
						enabled := false
						_, err := s.SetStatus(ctx, tx, p.ID, model.SecurityPolicyStatusChangeRequest{
							Enabled: &enabled,
						}, "system")
						if err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (s *SecPolicyService) RemoveResource(ctx context.Context, resource model.SecurityPolicyResource) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var secresource model.SecurityPolicyResource

		result := tx.WithContext(dbctx).
			Where("cluster = ? and name = ? and namespace = ? and kind = ? and container_name = ?", resource.Cluster, resource.Name, resource.Namespace, resource.Kind, resource.ContainerName).
			First(&secresource)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return PostgresError(http.StatusInternalServerError, fmt.Errorf("Error when getting resource in database: %w", result.Error))
			}
			return NewResourceNotFoundError(http.StatusBadRequest, fmt.Errorf("Resource does not exist in database: %w", result.Error))
		}
		// err == nil
		result = tx.WithContext(dbctx).Delete(&secresource)
		if result.Error != nil {
			return PostgresError(http.StatusInternalServerError, fmt.Errorf("Failed to inactivate security resource: %w", result.Error))
		}
		return nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}
