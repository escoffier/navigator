package scap

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// PolicyCreate 创建一条合规扫描策略
func (s *Service) PolicyCreate(ctx context.Context, policy *model.ScapPolicy) (uint, error) {
	db := s.rdb.Get().WithContext(ctx).Create(policy)
	if err := db.Error; err != nil {
		logging.Get().Err(err).Msgf("创建合规策略失败, policy=%v", policy)

		// 策略名冲突
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return 0, fmt.Errorf("创建失败, 名称重复 <%s>", policy.Name)
		}

		return 0, errors.New("创建失败")
	}
	return policy.ID, nil
}

// PolicyDelete 删除一条合规扫描策略
func (s *Service) PolicyDelete(ctx context.Context, policyId uint, scapType uint8) error {
	// 先判断是否在使用，如果有使用，则不能删除
	var cron model.ScapCronRecord
	if err := s.rdb.Get().WithContext(ctx).
		Model(&cron).
		Select("id").
		Where("policy_id = ?", policyId).
		Where("type = ?", scapType).
		First(&cron).
		Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logging.Get().Err(err).Msgf("更新合规策略失败, 获取在使用的策略失败，id=%d", policyId)
		return errors.New("更新合规策略失败, 获取关联的任务失败")
	}
	if cron.ID != 0 {
		return errors.New("更新合规策略失败, 策略已在使用")
	}

	db := s.rdb.Get().
		WithContext(ctx).
		Where("type = ? AND id = ?", scapType, policyId).
		Where("is_default =?", false).
		Delete(&model.ScapPolicy{})

	if err := db.Error; err != nil {
		logging.Get().Err(err).Msgf("删除合规策略失败, id=%d", policyId)
		return fmt.Errorf("删除策略 <%d> 失败", policyId)
	}
	return nil
}

func (s *Service) PolicyBatch(ctx context.Context, scapType uint8, limit, offset int, name string) ([]model.ScapPolicy, int64, error) {
	var count int64

	db := s.rdb.Get().WithContext(ctx).Model(&model.ScapPolicy{}).Where("type = ?", scapType)
	// 当存在名字时候，使用模糊搜索查询
	if len(name) != 0 {
		db = db.Where("name LIKE ?", "%"+name+"%")
	}

	if err := db.Count(&count).Error; err != nil {
		logging.Get().Err(err).Msgf("获取策略列表失败, type=%d", scapType)
		return nil, 0, errors.New("获取策略总数失败")
	}

	if count == 0 {
		return nil, 0, nil
	}

	var result = make([]model.ScapPolicy, 0, limit)
	if err := db.
		Omit("rule_ids").
		Limit(limit).
		Offset(offset).
		Find(&result).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}, Desc: true}).
		Error; err != nil {
		logging.Get().Err(err).Msgf("获取策略列表失败, type=%d, limit=%d, offset = %d", scapType, limit, offset)
		return nil, 0, errors.New("获取策略列表失败")
	}

	return result, count, nil
}

func (s *Service) PolicyUpdate(ctx context.Context, policyId uint, policy *model.ScapPolicy) (uint, error) {
	var id uint
	err := s.rdb.Get().WithContext(ctx).Transaction(
		func(tx *gorm.DB) error {
			var err error

			// 先判断是否在使用，如果有使用，则不能删除
			var cron model.ScapCronRecord
			if err := tx.
				Model(&cron).
				Select("id").
				Where("policy_id = ?", policyId).
				First(&cron).
				Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				logging.Get().Err(err).Msgf("更新合规策略失败, 获取在使用的策略失败，id=%d", policyId)
				return errors.New("更新合规策略失败, 获取关联的任务失败")
			}
			if cron.ID != 0 {
				return errors.New("更新合规策略失败, 策略已在使用")
			}

			// 获取到最原始的创建时间
			var r model.ScapPolicy
			if err = tx.Unscoped().Select("created_at", "is_default").Where("id = ?", policy).First(&r).Error; err != nil {
				logging.Get().Err(err).Msgf("更新策略失败, 数据不存在, policyId=%d", policyId)
				return errors.New("更新策略失败")
			}

			if r.IsDefault {
				return errors.New("默认策略无法修改")
			}

			// 先把policyId的对应数据删除，因为删除是当前读，所以不用担心并发
			if err = tx.Where("deleted_at = ?", 0).Delete(&model.ScapPolicy{}, policyId).Error; err != nil {
				logging.Get().Err(err).Msgf("更新策略失败, 删除老数据失败, policyId=%d", policyId)
				return errors.New("更新策略失败")
			}

			if tx.RowsAffected == 0 {
				return errors.New("更新策略失败, 数据不存在")
			}

			policy.CreatedAt = r.CreatedAt

			// 然后新插入一条数据
			if err = tx.Create(policy).Error; err != nil {
				logging.Get().Err(err).Msgf("更新策略失败, 创建新数据失败, policyId=%d, policy=%v", policyId, policy)
				return errors.New("更新策略失败")
			}

			id = policy.ID

			return nil
		},
	)

	return id, err
}

// PolicyDetail 获取策略的详情
func (s *Service) PolicyDetail(ctx context.Context, policyId uint) (*model.ScapPolicy, []model.PolicyDetailInfo, error) {
	db := s.rdb.Get().WithContext(ctx)

	var policy model.ScapPolicy
	if err := db.Model(&policy).First(&policy, policyId).Error; err != nil {
		logging.Get().Err(err).Msgf("获取策略详情失败, policyId=%d", policyId)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errors.New("策略不存在")
		}
		return nil, nil, errors.New("获取策略详情失败")
	}

	var checkType string
	switch policy.Type {
	case 1:
		checkType = kube
	case 2:
		checkType = docker
	case 3:
		checkType = host
	}

	var checks []model.PolicyDetailInfo

	db = db.Model(&model.PolicyDetailInfo{}).Where("check_type = ?", checkType)
	if !policy.IsDefault {
		checks = make([]model.PolicyDetailInfo, 0, len(policy.RuleIds))
		db = db.Where("id IN ?", policy.RuleIds)
	}

	if err := db.Find(&checks).Error; err != nil {
		logging.Get().Err(err).Msgf("获取策略详情失败, 获取检测规则失败，policyId=%d", policyId)
		return nil, nil, errors.New("获取策略详情失败")
	}

	return &policy, checks, nil
}

// PolicyBrief 获取策略的简略信息
func (s *Service) PolicyBrief(ctx context.Context, policyId uint) (*model.ScapPolicy, error) {
	db := s.rdb.Get().WithContext(ctx)

	var policy model.ScapPolicy
	if err := db.Model(&policy).First(&policy, policyId).Error; err != nil {

		logging.Get().Err(err).Msgf("获取策略简略信息失败, policyId=%d", policyId)
		return nil, errors.New("获取策略信息失败")
	}

	return &policy, nil
}
