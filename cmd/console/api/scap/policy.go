package scap

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/api/scap/internal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (a *ApiServer) PolicyCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	var req scap.Policy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			fmt.Errorf("invalid request parameters"),
		))

		response.RespError(w, http.StatusBadRequest)
		return
	}

	if err := internal.VerifyPolicy(&req); err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewErrorWithCode(http.StatusBadRequest, err),
		)
		return
	}

	username := model.GetUsernameFromContext(r.Context())
	value := &model.ScapPolicy{
		Name:     req.Name,
		Type:     scapType,
		Creator:  username,
		Operator: username,
		Comment:  req.Comment,
		RuleIds:  req.RuleIds,
	}

	id, err := a.service.PolicyCreate(ctx, value)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(http.StatusInternalServerError, err))
		return
	}

	response.Ok(w, response.WithItem(map[string]uint64{"id": id}),
		response.WithTarget(&response.TargetRef{
			Name: req.Name,
			ID:   "",
			Link: "",
		}))
}

func (a *ApiServer) PolicyBatch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	limit, err := param.QueryInt(r, "limit")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid limit parameter"),
		))
		return
	}

	offset, err := param.QueryInt(r, "offset")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid offset parameter"),
		))
		return
	}

	name, _ := param.QueryString(r, "name")

	result, count, err := a.service.PolicyBatch(ctx, scapType, limit, offset, name)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(http.StatusInternalServerError, err))
		return
	}

	var resp = make([]scap.PolicyBrief, len(result))
	language := lang.Language(ctx)
	for i, v := range result {
		if v.IsDefault && lang.LanguageEN == language {
			v.Name = strings.ReplaceAll(v.Name, "合规检测默认策略", "default policy")
		}

		resp[i] = scap.PolicyBrief{
			ID:        v.ID,
			Name:      v.Name,
			Operator:  v.Operator,
			CreatedAt: v.CreatedAt.UnixMilli(),
			UpdatedAt: v.UpdatedAt.UnixMilli(),
			IsDefault: v.IsDefault,
		}
	}

	response.Ok(w, response.WithItems(resp), response.WithTotalItems(count))
}

func (a *ApiServer) PolicyUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	policyId, err := param.Uint64(r, "id")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid policy id"),
		))
		return
	}

	var policy scap.Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			fmt.Errorf("invalid request parameters"),
		))
		return
	}

	if err := internal.VerifyPolicy(&policy); err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewErrorWithCode(http.StatusBadRequest, err),
		)
		return
	}

	value := &model.ScapPolicy{
		Name:     policy.Name,
		Type:     scapType,
		Operator: model.GetUsernameFromContext(r.Context()),
		Comment:  policy.Comment,
		RuleIds:  policy.RuleIds,
	}

	id, err := a.service.PolicyUpdate(ctx, policyId, value)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	response.Ok(w, response.WithItem(map[string]uint64{"id": id}))
}

func (a *ApiServer) PolicyDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	policyId, err := param.Uint(r, "id")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid policy id"),
		))
		return
	}

	var policyName string
	policyBrief, err := a.service.PolicyBrief(ctx, policyId)
	if err == nil {
		policyName = policyBrief.Name
	}
	err = a.service.PolicyDelete(ctx, policyId, scapType)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	response.Ok(w, response.WithTarget(&response.TargetRef{
		Name: policyName,
		ID:   strconv.Itoa(int(policyId)),
		Link: "",
	}))
}

func (a *ApiServer) PolicyDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	policyId, err := param.Uint(r, "id")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid policy id"),
		))
		return
	}

	policy, checks, err := a.service.PolicyDetail(ctx, policyId)
	if err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewErrorWithCode(http.StatusInternalServerError, err))
		return
	}

	if policy.IsDefault && lang.LanguageEN == lang.Language(ctx) {
		policy.Name = strings.ReplaceAll(policy.Name, "合规检测默认策略", "default policy")
		policy.Comment = strings.ReplaceAll(policy.Comment, "合规检测默认策略", "default policy")
	}

	var result = scap.PolicyDetail{
		PolicyBrief: scap.PolicyBrief{
			ID:        policy.ID,
			Name:      policy.Name,
			Operator:  policy.Operator,
			CreatedAt: policy.CreatedAt.UnixMilli(),
			UpdatedAt: policy.UpdatedAt.UnixMilli(),
			Comment:   policy.Comment,
			IsDefault: policy.IsDefault,
		},
		Creator: policy.Creator,
	}

	result.Rules = make([]scap.Rule, 0, len(checks))

	language := lang.Language(ctx)
	for i := range checks {
		tmp := scap.Rule{
			ID:             checks[i].Id,
			RawID:          checks[i].PolicyId,
			ExpectedResult: checks[i].ExpectedResult,
			Audit:          checks[i].Audit,
		}

		if language == lang.LanguageEN {
			tmp.Title = checks[i].TitleEn
			tmp.Detail = checks[i].DetailEn
			tmp.Remediation = checks[i].RemediationEn
			tmp.Classified = checks[i].ClassifiedEn
		} else {
			tmp.Title = checks[i].TitleZh
			tmp.Detail = checks[i].DetailZh
			tmp.Remediation = checks[i].RemediationZh
			tmp.Classified = checks[i].ClassifiedZh
		}

		result.Rules = append(result.Rules, tmp)
	}

	response.Ok(w, response.WithItem(result))
}
