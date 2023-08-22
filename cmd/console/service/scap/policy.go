package scap

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// PolicyCreate 创建一条合规扫描策略
func (s *Service) PolicyCreate(ctx context.Context, policy *model.ScapPolicy) (uint64, error) {
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
func (s *Service) PolicyDelete(ctx context.Context, policyId uint, scapType string) error {
	// 先判断是否在使用，如果有使用，则不能删除
	var cron model.ScapCronRecord
	if err := s.rdb.Get().WithContext(ctx).Model(&cron).Select("id").
		Where("policy_id = ?", policyId).Where("type = ?", scapType).
		First(&cron).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logging.Get().Err(err).Msgf("更新合规策略失败, 获取在使用的策略失败，id=%d", policyId)
		return errors.New("更新合规策略失败, 获取关联的任务失败")
	}
	if cron.ID != 0 {
		return errors.New("更新合规策略失败, 策略已在使用")
	}

	db := s.rdb.Get().WithContext(ctx).
		Where("type = ? AND id = ?", scapType, policyId).
		Where("is_default =?", false).
		Delete(&model.ScapPolicy{})

	if err := db.Error; err != nil {
		logging.Get().Err(err).Msgf("删除合规策略失败, id=%d", policyId)
		return fmt.Errorf("删除策略 <%d> 失败", policyId)
	}
	return nil
}

func (s *Service) PolicyBatch(ctx context.Context, scapType string, limit, offset int, name string) ([]*model.ScapPolicy, int64, error) {
	db := s.rdb.Get().WithContext(ctx).Model(&model.ScapPolicy{}).
		Where("type = ?", scapType)

	if name != "" {
		db = db.Where("name LIKE ?", "%"+name+"%")
	}

	var total int64
	if err := db.Session(&gorm.Session{}).Count(&total).
		Error; err != nil {
		logging.Get().Err(err).Msgf("获取策略列表失败, type=%d", scapType)
		return nil, 0, errors.New("获取策略总数失败")
	}

	if total == 0 {
		return []*model.ScapPolicy{}, 0, nil
	}

	var result []*model.ScapPolicy
	if err := db.Omit("rule_ids").
		Order(clause.OrderByColumn{Column: clause.Column{Name: "is_default"}, Desc: true}).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "created_at"}, Desc: true}).
		Limit(limit).Offset(offset).
		Find(&result).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logging.Get().Err(err).Msgf("获取默认策略失败, type=%d, limit=%d, offset=%d", scapType, limit, offset)
		return nil, 0, errors.New("获取默认策略失败")
	}

	return result, total, nil
}

func (s *Service) PolicyUpdate(ctx context.Context, policyId uint64, policy *model.ScapPolicy) (uint64, error) {
	var id uint64
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

	var checks []model.PolicyDetailInfo

	db = db.Model(&model.PolicyDetailInfo{}).Where("check_type = ?", policy.Type)
	if !policy.IsDefault {
		checks = make([]model.PolicyDetailInfo, 0, len(policy.RuleIds))
		db = db.Where("id IN ?", policy.RuleIds)
	} else if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeHost {
		db = db.Where("id >= 1000")
	} else {
		if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeDocker {
			db = db.Where("policy_id NOT IN ?", []string{"0.1.1", "0.2.1", "1.1"})
		}

		if os.Getenv("SCAP_LJS_ENABLED") == "true" {
			// 陆金所默认策略只扫描这些合规项
			// 对陆金所的默认策略返回数据做过滤
			policyIds := make([]string, 0)
			if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeDocker {
				policyIds = []string{
					"1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.8", "1.2.9", "1.2.10", "1.2.11", "1.2.12",
					"2.3", "2.5", "2.6", "2.12", "2.13", "2.14",
					"3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20", "3.21", "3.22",
					"5.5", "5.6", "5.7", "5.10", "5.11", "5.12", "5.19", "5.29",
				}
			} else if model.ComplianceCheckType(policy.Type) == model.ComplianceCheckTargetTypeKube {
				policyIds = []string{
					"1.1.1", "1.1.2", "1.1.3", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9", "1.1.10", "1.1.11", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17", "1.1.18", "1.1.19", "1.1.20", "1.1.21",
					"1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9", "1.2.11", "1.2.17", "1.2.18", "1.2.19", "1.2.20", "1.2.22", "1.2.26", "1.2.27", "1.2.28", "1.2.29", "1.2.30", "1.2.31", "1.2.32",
					"1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.4.1",
					"2.1", "2.2", "2.4", "2.5", "2.6",
					"4.1.5", "4.1.7", "4.2.1", "4.2.2", "4.2.3", "4.2.5", "4.2.7", "4.2.9", "4.2.10",
				}
			}
			if len(policyIds) > 0 {
				db = db.Where("policy_id IN ?", policyIds)
			}
		}
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

func (s *Service) GetUserHelper(ctx context.Context, username string) *model.UserLite {
	ul, err := dal.GetUserLiteWithCache(ctx, s.rdb.GetReadDB(), s.redisClient, username)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("")
		return &model.UserLite{
			Username: username,
			Account:  username,
		}
	}

	return ul
}
