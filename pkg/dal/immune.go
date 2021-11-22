package dal

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	onDupUpdatedColsForImmuneProfiles = []string{
		"created_at",
		"status",
		"creator",
	}
)

type ImmunePoliciesQueryOption struct {
	whereEqCondition map[string]interface{}
	whereInCondition map[string]interface{}
}

func NewImmunePoliciesQuery() *ImmunePoliciesQueryOption {
	return &ImmunePoliciesQueryOption{
		whereEqCondition: make(map[string]interface{}, 2),
		whereInCondition: make(map[string]interface{}, 2),
	}
}
func (opt *ImmunePoliciesQueryOption) WithStatuses(statuses interface{}) *ImmunePoliciesQueryOption {
	opt.whereInCondition["status"] = statuses
	return opt
}
func (opt *ImmunePoliciesQueryOption) WithKinds(kinds interface{}) *ImmunePoliciesQueryOption {
	opt.whereInCondition["kind"] = kinds
	return opt
}
func (opt *ImmunePoliciesQueryOption) WithClusterKey(ckey string) *ImmunePoliciesQueryOption {
	opt.whereEqCondition["cluster_key"] = ckey
	return opt
}

func ListImmunePolicies(ctx context.Context, rdb *gorm.DB, opt *ImmunePoliciesQueryOption, offset, limit int) ([]*model.ImmunePolicy, error) {
	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	policies := make([]*model.ImmunePolicy, 0, limit)
	db := rdb.WithContext(tctx).Model(&model.ImmunePolicy{})
	if limit > 0 {
		db = db.Offset(offset).Limit(limit)
	}
	if opt.whereEqCondition != nil && len(opt.whereEqCondition) > 0 {
		db = db.Where(opt.whereEqCondition)
	}
	if len(opt.whereInCondition) > 0 {
		for column, val := range opt.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	err := db.Order("updated_at DESC").Find(&policies).Error
	return policies, err
}

func CountImmunePolicies(ctx context.Context, rdb *gorm.DB, opt *ImmunePoliciesQueryOption) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	var count int64
	db := rdb.WithContext(tctx).Model(&model.ImmunePolicy{})
	if opt.whereEqCondition != nil && len(opt.whereEqCondition) > 0 {
		db = db.Where(opt.whereEqCondition)
	}
	if len(opt.whereInCondition) > 0 {
		for column, val := range opt.whereInCondition {
			db = db.Where(fmt.Sprintf("%s in ?", column), val)
		}
	}
	err := db.Count(&count).Error
	return count, err
}

func GetPolicy(ctx context.Context, rdb *gorm.DB, policyID int64) (*model.ImmunePolicy, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var policy model.ImmunePolicy
	err := rdb.WithContext(tctx).Model(&model.ImmunePolicy{}).Where("id = ?", policyID).First(&policy).Error
	return &policy, err
}

func GetProfilesOfPolicy(ctx context.Context, rdb *gorm.DB, policyID int64, containerName string /*optional*/) ([]*model.ImmuneProfile, error) {
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	profiles := make([]*model.ImmuneProfile, 0, 20)
	db := rdb.WithContext(tctx).Model(&model.ImmuneProfile{}).Where("policy_id = ? AND status = ?", policyID, 0)
	if len(containerName) > 0 {
		db = db.Where("container_name = ?", containerName)
	}
	err := db.Find(&profiles).Error
	return profiles, err
}

func CreateImmunePolicy(ctx context.Context, rdb *gorm.DB, policy *model.ImmunePolicy) (*model.ImmunePolicy, error) {
	tctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Model(&model.ImmunePolicy{}).Create(policy).Error
	return policy, err
}

func UpdateImmunePolicy(ctx context.Context, rdb *gorm.DB, policyID int64, policy *model.ImmunePolicy) error {
	if policy == nil {
		return errors.New("nil input")
	}
	tctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Model(&model.ImmunePolicy{}).Where("id = ?", policyID).Updates(map[string]interface{}{
		"name":        policy.Name,
		"description": policy.Description,
		"decision":    policy.Decision,
		"updater":     policy.Updater,
		"updated_at":  policy.UpdatedAt,
	}).Error
	return err
}

func CreateImmuneProfile(ctx context.Context, rdb *gorm.DB, profile *model.ImmuneProfile) (int64, error) {
	uuid := util.GenerateUUID64Signed(strconv.FormatInt(profile.PolicyID, 10), profile.ContainerName, string(profile.Value))
	profile.UUID = uuid

	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Model(&model.ImmuneProfile{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForImmuneProfiles),
	}).Create(profile).Error
	return uuid, err
}

func DeleteImmuneProfile(ctx context.Context, rdb *gorm.DB, profile *model.ImmuneProfile) error {
	if profile.UUID == 0 {
		profile.UUID = util.GenerateUUID64Signed(strconv.FormatInt(profile.PolicyID, 10), profile.ContainerName, string(profile.Value))
	}

	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	err := rdb.WithContext(tctx).Model(&model.ImmuneProfile{}).Where("uuid = ?", profile.UUID).Updates(map[string]interface{}{
		"status":     1,
		"creator":    profile.Creator,
		"created_at": time.Now(),
	}).Error
	return err
}

func SetImmunePolicyStatus(ctx context.Context, rdb *gorm.DB, policyID int64, status model.PolicyStatus) error {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	return rdb.WithContext(tctx).Model(&model.ImmunePolicy{}).Where("id = ?", policyID).Update("status", status).Error
}
