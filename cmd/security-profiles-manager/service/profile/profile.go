package profile

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/service/falco"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"k8s.io/client-go/kubernetes"
)

type SecProfileService struct {
	db                            *databases.RDBInstance
	mutex                         sync.Mutex
	k8sClient                     *kubernetes.Clientset
	namespace                     string
	secProfilesContainerConfigMap string
}

var (
	instance *SecProfileService
	once     sync.Once
)

func Init(
	db *databases.RDBInstance,
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
		instance = &SecProfileService{
			db:                            db,
			mutex:                         sync.Mutex{},
			k8sClient:                     kubeClient,
			namespace:                     myNamespace,
			secProfilesContainerConfigMap: secProfilesContainerConfigMap,
		}
	})

	return nil
}

func Get() (*SecProfileService, bool) {
	return instance, instance != nil
}

func (s *SecProfileService) ListProfileData(ctx context.Context, policyID int, profileKind model.SecurityKind) (*model.ProfileData, error) {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	profileData := &model.ProfileData{}
	var p model.SecurityPolicy

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		intermediateQuery := tx.WithContext(dbctx)

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
				return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	if profileKind == model.SecurityKindApparmor {
		profileData.ApparmorProfileData = make([]model.ApparmorProfileData, len(p.ApparmorProfile.ApparmorProfileData))
		for i, val := range p.ApparmorProfile.ApparmorProfileData {
			profileData.ApparmorProfileData[i] = val
		}
	} else if profileKind == model.SecurityKindCommandWhitelist {
		profileData.CommandWhitelistProfileData = make([]model.CommandWhitelistProfileData, len(p.CommandWhitelistProfile.CommandWhitelistProfileData))
		for i, val := range p.CommandWhitelistProfile.CommandWhitelistProfileData {
			profileData.CommandWhitelistProfileData[i] = val
		}
	} else if profileKind == model.SecurityKindSeccomp {
		profileData.SeccompProfileData = make([]model.SeccompProfileData, len(p.SeccompProfile.SeccompProfileData))
		for i, val := range p.SeccompProfile.SeccompProfileData {
			profileData.SeccompProfileData[i] = val
		}
	} else {
		return nil, NewUnknownSecurityProfileKindError(http.StatusBadRequest, fmt.Errorf("Unknown profile kind"))
	}

	return profileData, nil
}

func (s *SecProfileService) UpdatePolicyProfile(ctx context.Context, policyID int, profileKind model.SecurityKind, profileData *model.ProfileDataPost, username string) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).
			Preload("CommandWhitelistProfile.CommandWhitelistProfileData").
			Preload("SeccompProfile.SeccompProfileData").
			Preload("ApparmorProfile.ApparmorProfileData").
			Preload(clause.Associations).
			First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyError(http.StatusBadRequest, fmt.Errorf("Cannot update profile, because its policy is active"))
		}

		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		result = tx.WithContext(dbctx).Omit(clause.Associations).Save(&p)
		if result.Error != nil {
			return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}

		if profileKind == model.SecurityKindApparmor {
			if p.ApparmorProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateProfileThatIsTrained(http.StatusBadRequest, fmt.Errorf("Cannot update profile, because it is currently being trained"))
			}
			if len(profileData.ApparmorProfileDataAdd) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Adding apparmor entries")
				for i := range profileData.ApparmorProfileDataAdd {
					profileData.ApparmorProfileDataAdd[i].ApparmorProfileID = p.ApparmorProfile.ID
					if profileData.ApparmorProfileDataAdd[i].Access != "r" && profileData.ApparmorProfileDataAdd[i].Access != "rw" && profileData.ApparmorProfileDataAdd[i].Access != "w" {
						return NewInvalidAccessSentError(http.StatusBadRequest, fmt.Errorf("Invalid file access sent: %s", profileData.ApparmorProfileDataAdd[i].Access))
					}
					if profileData.ApparmorProfileDataAdd[i].File == "" {
						return NewMissingFileSentError(http.StatusBadRequest, fmt.Errorf("Missing filename sent: %s", profileData.ApparmorProfileDataAdd[i].File))
					}
					if string(profileData.ApparmorProfileDataAdd[i].File[0]) != "/" {
						return NewFileSentNotAbsoluteError(http.StatusBadRequest, fmt.Errorf("Sent filename not abolute: %s", profileData.ApparmorProfileDataAdd[i].File))
					}
					for _, existingEntry := range p.ApparmorProfile.ApparmorProfileData {
						if existingEntry.Access == profileData.ApparmorProfileDataAdd[i].Access && existingEntry.File == profileData.ApparmorProfileDataAdd[i].File {
							return NewDuplicateEntrySentError(http.StatusBadRequest, fmt.Errorf("Duplicate entry sent: %v", profileData.ApparmorProfileDataAdd[i]))
						}
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.ApparmorProfileDataAdd)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
			if len(profileData.ApparmorProfileDataRemove) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Removing apparmor entries")
				query := fmt.Sprintf("apparmor_profile_id = %d AND (", p.ApparmorProfile.ID)
				for i, v := range profileData.ApparmorProfileDataRemove {
					query = query + fmt.Sprintf("(file = '%s' AND access = '%s')", v.File, v.Access)
					if i != len(profileData.ApparmorProfileDataRemove)-1 {
						query = query + " OR "
					}
				}
				query = query + ")"
				result = tx.WithContext(dbctx).Where(query).Delete(&profileData.ApparmorProfileDataRemove)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
				}
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if p.CommandWhitelistProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateProfileThatIsTrained(http.StatusBadRequest, fmt.Errorf("Cannot update profile, because it is currently being trained"))
			}
			if len(profileData.CommandWhitelistProfileDataAdd) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Adding command whitelist entries")
				for i := range profileData.CommandWhitelistProfileDataAdd {
					profileData.CommandWhitelistProfileDataAdd[i].CommandWhitelistProfileID = p.CommandWhitelistProfile.ID
					if profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory == "" {
						return NewMissingWorkingDirSentError(http.StatusBadRequest, fmt.Errorf("Empty working dir sent: %s", profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory))
					}
					if string(profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory[0]) == "/" {
						return NewWorkingDirSentNotAbsoluteError(http.StatusBadRequest, fmt.Errorf("Sent working dir is not absolute: %s", profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory))
					}
					if profileData.CommandWhitelistProfileDataAdd[i].Command == "" {
						return NewMissingCommandSentError(http.StatusBadRequest, fmt.Errorf("Empty command sent: %s", profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory))
					}
					for _, existingEntry := range p.CommandWhitelistProfile.CommandWhitelistProfileData {
						if existingEntry.Command == profileData.CommandWhitelistProfileDataAdd[i].Command && existingEntry.WorkingDirectory == profileData.CommandWhitelistProfileDataAdd[i].WorkingDirectory {
							return NewDuplicateEntrySentError(http.StatusBadRequest, fmt.Errorf("Duplicate entry sent: %v", profileData.CommandWhitelistProfileDataAdd[i]))
						}
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.CommandWhitelistProfileDataAdd)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
			if len(profileData.CommandWhitelistProfileDataRemove) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Removing command whitelist entries")
				query := fmt.Sprintf("command_whitelist_profile_id = %d AND (", p.CommandWhitelistProfile.ID)
				for i, v := range profileData.CommandWhitelistProfileDataRemove {
					query = query + fmt.Sprintf("(command = '%s' AND working_directory = '%s')", v.Command, v.WorkingDirectory)
					if i != len(profileData.CommandWhitelistProfileDataRemove)-1 {
						query = query + " OR "
					}
				}
				query = query + ")"
				result = tx.WithContext(dbctx).Where(query).Delete(&profileData.CommandWhitelistProfileDataRemove)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
				}
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if p.SeccompProfile.TrainingStatus != model.TrainingStatusNotStarted {
				return NewCannotUpdateProfileThatIsTrained(http.StatusBadRequest, fmt.Errorf("Cannot update profile, because it is currently being trained"))
			}
			if len(profileData.SeccompProfileDataAdd) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Adding seccomp entries")
				for i := range profileData.SeccompProfileDataAdd {
					profileData.SeccompProfileDataAdd[i].SeccompProfileID = p.SeccompProfile.ID
					if profileData.SeccompProfileDataAdd[i].Syscall == "" {
						return NewMissingSyscallSentError(http.StatusBadRequest, fmt.Errorf("Empty syscall sent: %s", profileData.SeccompProfileDataAdd[i].Syscall))
					}
					if !util.ContainsString(falco.SeccompEventsToWatch, profileData.SeccompProfileDataAdd[i].Syscall) {
						return NewInvalidSyscallSentError(http.StatusBadRequest, fmt.Errorf("Invalid syscall sent: %s", profileData.SeccompProfileDataAdd[i].Syscall))
					}
					for _, existingEntry := range p.SeccompProfile.SeccompProfileData {
						if existingEntry.Syscall == profileData.SeccompProfileDataAdd[i].Syscall {
							return NewDuplicateEntrySentError(http.StatusBadRequest, fmt.Errorf("Duplicate entry sent: %v", profileData.SeccompProfileDataAdd[i]))
						}
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.SeccompProfileDataAdd)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
			if len(profileData.SeccompProfileDataRemove) > 0 {
				logging.GetLogger().Info().Int("policy", p.ID).Msg("Removing seccomp entries")
				query := fmt.Sprintf("seccomp_profile_id = %d AND (", p.SeccompProfile.ID)
				for i, v := range profileData.SeccompProfileDataRemove {
					query = query + fmt.Sprintf("(syscall = '%s')", v.Syscall)
					if i != len(profileData.SeccompProfileDataRemove)-1 {
						query = query + " OR "
					}
				}
				query = query + ")"
				result = tx.WithContext(dbctx).Where(query).Delete(&profileData.SeccompProfileDataRemove)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
				}
			}
		} else {
			logging.GetLogger().Error().Str("kind", string(profileKind)).Msg("Unsupported security profile kind")
			return NewPolicyError(http.StatusBadRequest, fmt.Errorf("Unsupported profile kind %s", profileKind))
		}
		logging.GetLogger().Info().Msg("Policy profile successfully updated")

		return nil
	})
	if txErr != nil {
		return txErr
	}

	return nil
}

func (s *SecProfileService) ReplacePolicyProfile(ctx context.Context, policyID int, profileKind model.SecurityKind, profileData *model.ProfileData, username string) error {
	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()

	txErr := s.db.Get().Transaction(func(tx *gorm.DB) error {
		var p model.SecurityPolicy

		result := tx.WithContext(dbctx).
			Preload("CommandWhitelistProfile.CommandWhitelistProfileData").
			Preload("SeccompProfile.SeccompProfileData").
			Preload("ApparmorProfile.ApparmorProfileData").
			Preload(clause.Associations).
			First(&p, policyID)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when getting policy in database: %w", result.Error))
			}
			return NewNotFoundError(http.StatusBadRequest, fmt.Errorf("Policy does not exist in database: %w", result.Error))
		}

		if p.Active {
			return NewPolicyError(http.StatusBadRequest, fmt.Errorf("Cannot update profile, because its policy is active"))
		}

		p.UpdatedAt = time.Now()
		p.UpdatedBy = username
		result = tx.WithContext(dbctx).Omit(clause.Associations).Save(&p)
		if result.Error != nil {
			return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when updating policy in database: %w", result.Error))
		}

		if profileKind == model.SecurityKindApparmor {
			if len(profileData.ApparmorProfileData) > 0 {
				for i := range profileData.ApparmorProfileData {
					profileData.ApparmorProfileData[i].ApparmorProfileID = p.ApparmorProfile.ID
				}
				if len(p.ApparmorProfile.ApparmorProfileData) > 0 {
					result = tx.WithContext(dbctx).Where("apparmor_profile_id = ?", p.ApparmorProfile.ID).Delete(&p.ApparmorProfile.ApparmorProfileData)
					if result.Error != nil {
						return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.ApparmorProfileData)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
		} else if profileKind == model.SecurityKindCommandWhitelist {
			if len(profileData.CommandWhitelistProfileData) > 0 {
				for i := range profileData.CommandWhitelistProfileData {
					profileData.CommandWhitelistProfileData[i].CommandWhitelistProfileID = p.CommandWhitelistProfile.ID
				}
				if len(p.CommandWhitelistProfile.CommandWhitelistProfileData) > 0 {
					result = tx.WithContext(dbctx).Where("command_whitelist_profile_id = ?", p.CommandWhitelistProfile.ID).Delete(&p.CommandWhitelistProfile.CommandWhitelistProfileData)
					if result.Error != nil {
						return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.CommandWhitelistProfileData)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
		} else if profileKind == model.SecurityKindSeccomp {
			if len(profileData.SeccompProfileData) > 0 {
				for i := range profileData.SeccompProfileData {
					profileData.SeccompProfileData[i].SeccompProfileID = p.SeccompProfile.ID
				}
				if len(p.SeccompProfile.SeccompProfileData) > 0 {
					result = tx.WithContext(dbctx).Where("seccomp_profile_id = ?", p.SeccompProfile.ID).Delete(&p.SeccompProfile.SeccompProfileData)
					if result.Error != nil {
						return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when removing profile entries from database: %w", result.Error))
					}
				}
				result = tx.WithContext(dbctx).Create(&profileData.SeccompProfileData)
				if result.Error != nil {
					return RDBError(http.StatusInternalServerError, fmt.Errorf("Error when adding profile entries to database: %w", result.Error))
				}
			}
		} else {
			logging.GetLogger().Error().Str("kind", string(profileKind)).Msg("Unsupported security profile kind")
			return NewPolicyError(http.StatusBadRequest, fmt.Errorf("Unsupported profile kind %s", profileKind))
		}
		logging.GetLogger().Info().Msg("Policy profile successfully updated")

		return nil
	})
	if txErr != nil {
		return txErr
	}

	return nil
}
