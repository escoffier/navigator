package imagesec

import (
	"context"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 安全策略
type SecurityPolicyService interface {
	CreatePolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) *i18.ErrI18
	UpdatePolicy(ctx context.Context, id int64, data *imagesecModel.SecurityPolicy) *i18.ErrI18
	SearchPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]*imagesecModel.SecurityPolicy, int64, *i18.ErrI18)
	DeletePolicy(ctx context.Context, id int64) *i18.ErrI18
}

type SecurityPolicySrv struct {
	policyDal          imagesecStore.DetectPolicyDal
	imageDetectTaskSrv detect.ImageDetectTaskService
	sensitiveRuleDal   imagesecStore.SensitiveRuleDal
}

func NewPolicySrv(
	policyDal imagesecStore.DetectPolicyDal,
	taskSrv detect.ImageDetectTaskService,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
) *SecurityPolicySrv {
	return &SecurityPolicySrv{
		policyDal:          policyDal,
		imageDetectTaskSrv: taskSrv,
		sensitiveRuleDal:   sensitiveRuleDal,
	}
}

func (s *SecurityPolicySrv) CreatePolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) *i18.ErrI18 {
	data.Serialize()
	if err := data.Check(); err != nil {
		return err
	}
	if err := s.policyDal.CreateDetectPolicy(ctx, data); err != nil {
		logging.Get().Err(err).Interface("data", data).Msg("CreateDetectPolicy")
		return scani18.CreatePolicy(err)
	}

	logging.Get().Info().Int64("policyID", data.ID).Msg("CreateDetectPolicy succeed")
	// 加检测任务
	go func() {
		imageSearchParam := imagesecModel.ImageListParam{ImageFromType: data.Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx, imageSearchParam, imagesecModel.SearchSecurityPolicyParam{},
			imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityPolicyChange}); err != nil {
			logging.Get().Err(err).Msg("CreateDetectPolicy CreateDetectTask")
			return
		}
		logging.Get().Info().Msg("CreateDetectPolicy CreateDetectTask succeed")
	}()

	return nil
}

func (s *SecurityPolicySrv) UpdatePolicy(ctx context.Context, id int64, data *imagesecModel.SecurityPolicy) *i18.ErrI18 {

	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}

	err := s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
		ID:      id,
		Updater: data.ToUpdater(),
	})
	if err != nil {
		logging.Get().Err(err).Interface("data", data).Int64("policyID", id).Msg("UpdateDetectPolicy")
		return scani18.UpdatePolicy(err)
	}

	// 加检测任务
	go func() {
		imageSearchParam := imagesecModel.ImageListParam{ImageFromType: data.Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx, imageSearchParam,
			imagesecModel.SearchSecurityPolicyParam{Ids: []int64{id}}, imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityPolicyChange},
		); err != nil {
			logging.Get().Err(err).Msg("UpdateDetectPolicy CreateDetectTask")
			return
		}
		logging.Get().Info().Msg("UpdateDetectPolicy CreateDetectTask succeed")
	}()

	return nil
}

// 数据库中对默认策略：name=default,产品要求搜索：『默认策略』也能搜索出结果
func (s *SecurityPolicySrv) SearchPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) (
	[]*imagesecModel.SecurityPolicy, int64, *i18.ErrI18) {

	keyword := param.Keyword

	if keyword != "" {
		param.Keyword = ""
		param.Filter = param.Filter.SetLimit(0).SetOffset(0)
	}

	policy, cnt, err := s.policyDal.SearchDetectPolicy(ctx, param)
	if err != nil {
		logging.Get().Err(err).Interface("param", param).Msg("SearchDetectPolicy")
		return nil, 0, scani18.SearchPolicy(err)
	}
	ans := make([]*imagesecModel.SecurityPolicy, 0)
	for i := range policy {
		add := false
		if keyword == "" {
			add = true
		}
		if keyword != "" && (strings.Contains(policy[i].Name, keyword) || strings.Contains(policy[i].Scope.ImageRegexp, keyword)) {
			add = true
		}
		for j := range policy[i].Scope.ClusterName {
			if strings.Contains(policy[i].Scope.ClusterName[j], keyword) {
				add = true
			}
		}
		if add {
			ans = append(ans, policy[i])
		}
	}

	for i := range ans {
		if (ans[i].Sensitive.AllBlack || ans[i].Sensitive.AllWhite) && ans[i].Sensitive.Enable {
			rule, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, nil)
			if err != nil {
				logging.Get().Err(err).Int64("policyID", ans[i].ID).Msg("SearchDetectPolicy SearchSensitiveRule")
				return nil, 0, i18.SearchErr(err)
			}
			sesRule := make([]string, 0)
			for j := range rule {
				sesRule = append(sesRule, rule[j].Value)
			}
			if ans[i].Sensitive.AllBlack {
				ans[i].Sensitive.Black = sesRule
			}
			if ans[i].Sensitive.AllWhite {
				ans[i].Sensitive.White = sesRule
			}
		}
	}

	return ans, cnt, nil
}

func (s *SecurityPolicySrv) DeletePolicy(ctx context.Context, id int64) *i18.ErrI18 {
	err := s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
		ID:      id,
		Updater: map[string]interface{}{"deleted_at": time.Now().UnixMilli()},
	})
	if err != nil {
		logging.Get().Err(err).Int64("policyID", id).Msg("DeleteDetectPolicy")
		return scani18.DeletePolicy(err)
	}
	return nil
}
