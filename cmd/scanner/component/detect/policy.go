package detect

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 安全策略
type SecurityPolicyService interface {
	CreatePolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) error
	UpdatePolicy(ctx context.Context, param imagesecModel.UpdatePolicyParam) error
	SearchPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) ([]*imagesecModel.SecurityPolicy, int64, error)
	DeletePolicy(ctx context.Context, id int64) error
	GetPolicySnapshot(ctx context.Context, uniqueID uint64) (imagesecModel.SecurityPolicy, error)
}

type SecurityPolicySrv struct {
	policyDal          imagesecStore.DetectPolicyDal
	imageDetectTaskSrv ImageDetectTaskService
	sensitiveRuleDal   imagesecStore.SensitiveRuleDal
	userDal            imagesecStore.UserDal
	Log                *scannerUtils.LogEvent
}

func NewPolicySrv(
	policyDal imagesecStore.DetectPolicyDal,
	taskSrv ImageDetectTaskService,
	sensitiveRuleDal imagesecStore.SensitiveRuleDal,
	userDal imagesecStore.UserDal,
) *SecurityPolicySrv {
	return &SecurityPolicySrv{
		userDal:            userDal,
		policyDal:          policyDal,
		imageDetectTaskSrv: taskSrv,
		sensitiveRuleDal:   sensitiveRuleDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("SecurityPolicy"),
			scannerUtils.WithModule(consts.ModuleDetect),
		),
	}
}

func (s *SecurityPolicySrv) CreatePolicy(ctx context.Context, data *imagesecModel.SecurityPolicy) error {
	allPolicy = nil

	data.Serialize()

	if data.Name == imagesecModel.DefaultPolicyNameZH || data.Name == imagesecModel.DefaultPolicyNameEN || data.IsDefault {
		return scani18.CreatePolicy(fmt.Errorf("%s", consts.DuplicateKey))
	}

	if err := data.Check(); err != nil {
		return err
	}
	if err := s.policyDal.CreateDetectPolicy(ctx, data); err != nil {
		s.Log.Err(err).Interface("data", data).Msg("CreateDetectPolicy")
		return scani18.CreatePolicy(err)
	}

	if err := s.policyDal.CreateDetectPolicySnapshot(ctx, data); err != nil {
		s.Log.Err(err).Interface("data", data).Msg("CreateDetectPolicyCreateDetectPolicySnapshot")
	}

	s.Log.Info().Int64("policyID", data.ID).Msg("CreateDetectPolicy succeed")
	// 加检测任务
	go func() {
		if data.PolicyType == imagesecModel.ConfigTypeDeploy {
			return
		}

		imageSearchParam := imagesecModel.ImageSearchApiParam{ImageFromType: data.Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx,
			imageSearchParam,
			imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityPolicyCreate},
			data,
		); err != nil {
			s.Log.Err(err).Msg("CreateDetectPolicy CreateDetectTask")
			return
		}
		s.Log.Info().Msg("CreateDetectPolicy CreateDetectTask succeed")
	}()

	return nil
}

func (s *SecurityPolicySrv) UpdatePolicy(ctx context.Context, param imagesecModel.UpdatePolicyParam) error {
	allPolicy = nil

	data := param.Policy
	if data.Updater == "" {
		return i18.CreateI18BadReqErr("未获取到更新人", "not get updater")
	}
	data.ID = param.ID
	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}

	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Ids: []int64{param.ID}})
	if err != nil {
		s.Log.Err(err).Interface("data", data).Int64("policyID", param.ID).Msg("SearchPolicy")
		return scani18.UpdatePolicy(err)
	}
	if len(policy) == 0 || policy[0].IsDefault {
		return nil
	}
	if len(policy) > 0 && data.Same(policy[0]) {
		s.Log.Err(err).Interface("data", data).Int64("policyID", param.ID).Msg("policy not changed")
		return nil
	}

	err = s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
		ID:      param.ID,
		Updater: data.ToUpdater(),
	})

	if err != nil {
		s.Log.Err(err).Interface("data", data).Int64("policyID", param.ID).Msg("UpdateDetectPolicy")
		return scani18.UpdatePolicy(err)
	}

	// 写快照
	if param.CreateSnapshot {
		data.Creator = policy[0].Creator
		data.CreatedAt = time.Now().UnixMilli()
		data.UpdatedAt = time.Now().UnixMilli()

		if err := s.policyDal.CreateDetectPolicySnapshot(ctx, &data); err != nil {
			s.Log.Err(err).Interface("data", data).Int64("policyID", param.ID).
				Msg("UpdateDetectPolicy CreateDetectPolicySnapshot")
		}
	}

	scopeChanged := !data.Scope.Same(policy[0].Scope)

	// 加检测任务
	go func() {
		if !param.CreateDetectTask {
			return
		}
		if data.PolicyType == imagesecModel.ConfigTypeDeploy {
			return
		}
		// 删除这个策略的子任务,对于扫描任务的检测任务已做特殊处理
		// FIXME 如何处理的?
		deleteParam := imagesecModel.SearchTaskParam{PolicyID: data.ID}

		if err := s.imageDetectTaskSrv.DeleteDetectData(ctx, deleteParam); err != nil {
			s.Log.Err(err).Msg("UpdateDetectPolicy delete not finished detect task and subtask")
		}

		imageSearchParam := imagesecModel.ImageSearchApiParam{ImageFromType: data.Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(
			ctx,
			imageSearchParam,
			imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityPolicyUpdate},
			&data,
		); err != nil {
			s.Log.Err(err).Msg("UpdateDetectPolicy CreateDetectTask")
			return
		}
		s.Log.Info().Msg("UpdateDetectPolicy CreateDetectTask succeed")
	}()

	// 再加一个默认策略的检测任务，只是优先级低些,防止策略范围变小
	// 默认策略是所有的镜像
	// 检测时是查询所有的策略一起检测的
	go func(scopeChanged bool) {
		if !param.CreateDetectTask {
			return
		}
		if !scopeChanged {
			return
		}

		defaultP, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
			PolicyType: policy[0].PolicyType,
			Default:    consts.TrueString,
		})
		if err != nil {
			s.Log.Err(err).Msg("UpdateDetectPolicy not find default detect task")
		}
		if len(defaultP) == 0 {
			return
		}

		imageSearchParam := imagesecModel.ImageSearchApiParam{ImageFromType: data.Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx, imageSearchParam,
			imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityDefaultPolicy},
			defaultP[0],
		); err != nil {
			s.Log.Err(err).Msg("UpdateDetectPolicy CreateDetectTask")
			return
		}
		s.Log.Info().Msg("UpdateDetectPolicy CreateDetectTask succeed")
	}(scopeChanged)

	return nil
}

// 数据库中对默认策略：name=default,产品要求搜索：『默认策略』也能搜索出结果
func (s *SecurityPolicySrv) SearchPolicy(ctx context.Context, param imagesecModel.SearchSecurityPolicyParam) (
	[]*imagesecModel.SecurityPolicy, int64, error) {

	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	keyword := param.Keyword

	if keyword != "" {
		param.Keyword = ""
		param.Filter = param.Filter.SetLimit(0).SetOffset(0)
	}

	policy, cnt, err := s.policyDal.SearchDetectPolicy(ctx, param)
	if err != nil {
		s.Log.Err(err).Interface("param", param).Msg("SearchDetectPolicy")
		return nil, 0, scani18.SearchPolicy(err)
	}
	ans := make([]*imagesecModel.SecurityPolicy, 0)
	for i := range policy {
		po := policy[i]
		add := false

		if strings.Contains(po.Name, keyword) {
			add = true
		}

		for _, re := range po.Scope.ImageRegexp {
			if strings.Contains(re, keyword) {
				add = true
			}
		}
		for j := range po.Scope.ClusterName {
			if strings.Contains(po.Scope.ClusterName[j], keyword) {
				add = true
			}
		}

		for j := range po.Scope.RegName {
			if strings.Contains(po.Scope.RegName[j], keyword) {
				add = true
			}
		}
		if keyword == "" {
			add = true
		}
		if add {
			ans = append(ans, policy[i])
		}
	}
	if keyword != "" {
		cnt = int64(len(ans))
	}
	user := make([]string, 0)
	for i := range ans {
		user = append(user, ans[i].Updater)
		user = append(user, ans[i].Creator)
		if (ans[i].Sensitive.AllBlack || ans[i].Sensitive.AllWhite) && ans[i].Sensitive.Enable {
			rule, _, err := s.sensitiveRuleDal.SearchSensitiveRule(ctx, imagesecModel.SearchSensitiveRuleParam{})
			if err != nil {
				s.Log.Err(err).Int64("policyID", ans[i].ID).Msg("SearchDetectPolicy SearchSensitiveRule")
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

	username, err := s.userDal.GetUsername(ctx, user)
	if err != nil {
		return nil, 0, scani18.SearchScanTask(err)
	}
	for i := range ans {
		if username[ans[i].Updater] != "" {
			ans[i].Updater = username[ans[i].Updater]
		}
		if username[ans[i].Creator] != "" {
			ans[i].Creator = username[ans[i].Creator]
		}
	}

	return ans, cnt, nil
}

func (s *SecurityPolicySrv) DeletePolicy(ctx context.Context, id int64) error {
	allPolicy = nil
	policy, _, err := s.policyDal.SearchDetectPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Ids: []int64{id}})
	if err != nil {
		return scani18.DeletePolicy(err)
	}
	if len(policy) == 0 {
		return nil
	}

	err = s.policyDal.UpdateDetectPolicy(ctx, imagesecModel.UpdateSecurityPolicyParam{
		ID:      id,
		Updater: map[string]interface{}{"deleted_at": time.Now().UnixMilli()},
	})
	if err != nil {
		s.Log.Err(err).Int64("policyID", id).Msg("DeleteDetectPolicy")
		return scani18.DeletePolicy(err)
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("DeletePolicy and delete detect task and subtask")
			}
		}()
		if policy[0].PolicyType == imagesecModel.ConfigTypeDeploy {
			return
		}
		// 删除这个策略未完成的任务
		deleteParam := imagesecModel.SearchTaskParam{PolicyID: id}
		if err := s.imageDetectTaskSrv.DeleteDetectData(ctx, deleteParam); err != nil {
			s.Log.Err(err).Msg("DeletePolicy delete not finished detect task and subtask")
		}

		// 然后触发所有的重新扫描
		imageSearchParam := imagesecModel.ImageSearchApiParam{ImageFromType: policy[0].Scope.ImageFromType}
		if err := s.imageDetectTaskSrv.CreateImageDetectTask(ctx,
			imageSearchParam,
			imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityPolicyDelete},
			nil,
		); err != nil {
			s.Log.Err(err).Msg("CreateDetectPolicy CreateDetectTask")
			return
		}
		s.Log.Info().Msg("DeletePolicy and CreateDetectTask succeed")
	}()

	return nil
}

func (s *SecurityPolicySrv) GetPolicySnapshot(ctx context.Context, uniqueID uint64) (
	imagesecModel.SecurityPolicy, error) {
	if uniqueID <= 0 {
		return imagesecModel.SecurityPolicy{}, scani18.NotGetID()
	}

	po, err := s.policyDal.SearchDetectPolicySnapshot(ctx, imagesecModel.SearchSecurityPolicyParam{UniqueID: uniqueID})
	if err != nil {
		s.Log.Err(err).Uint64("uniqueID", uniqueID).Msg("SearchDetectPolicySnapshot")
		return imagesecModel.SecurityPolicy{}, scani18.SearchPolicy(err)
	}
	if len(po) == 0 {
		return imagesecModel.SecurityPolicy{}, scani18.SearchPolicy(fmt.Errorf("not find"))
	}

	username, err := s.userDal.GetUsername(ctx, []string{po[0].Creator, po[0].Updater})
	if err != nil {
		return imagesecModel.SecurityPolicy{}, scani18.SearchScanTask(err)
	}

	for i := range po {
		if username[po[i].Updater] != "" {
			po[i].Updater = username[po[i].Updater]
		}
		if username[po[i].Creator] != "" {
			po[i].Creator = username[po[i].Creator]
		}
	}

	return po[0], nil
}
