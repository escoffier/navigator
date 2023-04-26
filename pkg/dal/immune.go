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
	columnQuery      colQuery
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
func (opt *ImmunePoliciesQueryOption) WithResourceUUID(resourceUUID uint32) *ImmunePoliciesQueryOption {
	opt.whereEqCondition["resource_uuid"] = resourceUUID
	return opt
}
func (opt *ImmunePoliciesQueryOption) WithQuery(query string) *ImmunePoliciesQueryOption {
	opt.columnQuery.column = "name"
	opt.columnQuery.query = query
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
	if len(opt.columnQuery.column) > 0 && len(opt.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", opt.columnQuery.column), GetLikeExpr(opt.columnQuery.query))
	}
	err := db.Where("status != ?", 1).Order("updated_at DESC").Find(&policies).Error
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
	if len(opt.columnQuery.column) > 0 && len(opt.columnQuery.query) > 0 {
		db = db.Where(fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", opt.columnQuery.column), GetLikeExpr(opt.columnQuery.query))
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
	err := db.Order("created_at asc").Find(&profiles).Error
	return profiles, err
}

func GetImmunePolicy(ctx context.Context, rdb *gorm.DB, id int64) (*model.ImmunePolicy, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	var p model.ImmunePolicy
	err := rdb.WithContext(tctx).Model(&model.ImmunePolicy{}).Where("id = ?", id).First(&p).Error
	if err == gorm.ErrRecordNotFound {
		return nil, err
	} else if err != nil {
		return nil, err
	}
	return &p, nil
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

func GetUUIDOfProfile(profile *model.ImmuneProfile) int64 {
	return util.GenerateUUID64Signed(strconv.FormatInt(profile.PolicyID, 10), profile.ContainerName, string(profile.Value))
}
func CreateImmuneProfile(ctx context.Context, rdb *gorm.DB, profile *model.ImmuneProfile) (int64, error) {
	if profile.UUID == 0 {
		profile.UUID = GetUUIDOfProfile(profile)
	}

	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Model(&model.ImmuneProfile{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForImmuneProfiles),
	}).Create(profile).Error
	return profile.UUID, err
}

func DeleteImmuneProfile(ctx context.Context, rdb *gorm.DB, profile *model.ImmuneProfile) error {
	if profile.UUID == 0 {
		profile.UUID = GetUUIDOfProfile(profile)
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

type ImmuneTasksQuery struct {
	whereEqCondition map[string]interface{}
}

func NewImmuneTasksQuery() *ImmuneTasksQuery {
	return &ImmuneTasksQuery{
		whereEqCondition: make(map[string]interface{}, 3),
	}
}
func (q *ImmuneTasksQuery) WithResourceUUID(uuid uint32) *ImmuneTasksQuery {
	q.whereEqCondition["resource_uuid"] = uuid
	return q
}
func (q *ImmuneTasksQuery) WithState(state model.TaskState) *ImmuneTasksQuery {
	q.whereEqCondition["state"] = state
	return q
}

func CountImmuneTasks(ctx context.Context, rdb *gorm.DB, queryOpt *ImmuneTasksQuery) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.ImmuneTask{}).Where("status = ?", 0)
	if queryOpt != nil && len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	var cnt int64
	err := db.Count(&cnt).Error
	return cnt, err
}

func SetImmuneTaskState(ctx context.Context, rdb *gorm.DB, id int64, state model.TaskState) error {
	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	return rdb.WithContext(tctx).Model(&model.ImmuneTask{}).Where("id = ?", id).Update("state", state).Error
}

func GetImmuneTasks(ctx context.Context, rdb *gorm.DB, queryOpt *ImmuneTasksQuery, offset, limit int) ([]*model.ImmuneTask, error) {
	tctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.ImmuneTask{}).Where("status = ?", 0)
	if limit > 0 {
		db = db.Limit(limit).Offset(offset)
	}
	if queryOpt != nil && len(queryOpt.whereEqCondition) > 0 {
		db = db.Where(queryOpt.whereEqCondition)
	}
	tasks := make([]*model.ImmuneTask, 0, limit)
	err := db.Order("id desc").Find(&tasks).Error
	return tasks, err
}

func CreateImmuneTask(ctx context.Context, rdb *gorm.DB, t *model.ImmuneTask) (int64, error) {
	if t == nil {
		return 0, errors.New("nil")
	}
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	err := rdb.WithContext(tctx).Model(t).Create(t).Error
	return t.ID, err
}
