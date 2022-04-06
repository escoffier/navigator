package scap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/console/api/scap/internal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (a *ApiServer) PolicyCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)
	var username = r.Context().Value(uName).(string)

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
		apperror.RespAndLog(
			w,
			ctx,
			apperror.NewErrorWithCode(
				http.StatusBadRequest,
				err,
			),
		)
		return
	}

	value := &model.ScapPolicy{
		Name:     req.Name,
		Type:     scapType,
		Operator: username,
		Comment:  req.Comment,
		RuleIds:  req.RuleIds,
	}

	id, err := a.service.PolicyCreate(ctx, value)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	response.Ok(w, response.WithItem(scap.CreatePolicyResp{ID: models.ID{ID: id}}))
}

func (a *ApiServer) PolicyBatch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)

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
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	var resp = make([]scap.PolicyBrief, 0, len(result))
	for i := range result {

		s := scap.PolicyBrief{
			ID:        result[i].ID,
			Name:      result[i].Name,
			Operator:  result[i].Operator,
			CreatedAt: result[i].CreatedAt.Unix(),
			IsDefault: result[i].IsDefault,
		}

		resp = append(resp, s)
	}

	response.Ok(w, response.WithItems(resp), response.WithTotalItems(count))
}

func (a *ApiServer) PolicyUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)
	var username = r.Context().Value(uName).(string)

	policyId, err := param.Uint(r, "id")
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
		apperror.RespAndLog(
			w,
			ctx,
			apperror.NewErrorWithCode(
				http.StatusBadRequest,
				err,
			),
		)
		return
	}

	value := &model.ScapPolicy{
		Name:     policy.Name,
		Type:     scapType,
		Operator: username,
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

	response.Ok(w, response.WithItem(scap.UpdatePolicyResp{ID: models.ID{ID: id}}))
}

func (a *ApiServer) PolicyDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)

	policyId, err := param.Uint(r, "id")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			errors.New("invalid policy id"),
		))
		return
	}

	err = a.service.PolicyDelete(ctx, policyId, scapType)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	response.Ok(w)
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
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	var result = scap.PolicyDetail{
		PolicyBrief: scap.PolicyBrief{
			Name:      policy.Name,
			Operator:  policy.Operator,
			CreatedAt: policy.CreatedAt.Unix(),
			Comment:   policy.Comment,
			IsDefault: policy.IsDefault,
		},
	}

	result.Rules = make([]scap.Rule, 0, len(checks))

	for i := range checks {
		result.Rules = append(result.Rules, scap.Rule{
			ID:             checks[i].Id,
			RawID:          checks[i].PolicyId,
			TitleEn:        checks[i].TitleEn,
			TitleZh:        checks[i].TitleZh,
			DetailEn:       checks[i].DetailEn,
			DetailZh:       checks[i].DetailZh,
			RemediationEn:  checks[i].RemediationEn,
			RemediationZh:  checks[i].RemediationZh,
			ExpectedResult: checks[i].ExpectedResult,
			Audit:          checks[i].Audit,
		})
	}

	response.Ok(w, response.WithItem(result))
}
