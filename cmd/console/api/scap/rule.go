package scap

import (
	"context"
	"errors"
	"net/http"
	"time"

	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (a *ApiServer) RuleBatch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)

	limit, err := param.QueryInt(r, "limit")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(
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

	list, count, err := a.service.RuleBatch(ctx, scapType, limit, offset)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	var rules = make([]scap.Rule, 0, len(list))
	for i := range list {

		rules = append(rules, scap.Rule{
			ID:             list[i].Id,
			RawID:          list[i].PolicyId,
			TitleEn:        list[i].TitleEn,
			TitleZh:        list[i].TitleZh,
			DetailEn:       list[i].DetailEn,
			DetailZh:       list[i].DetailZh,
			RemediationEn:  list[i].RemediationEn,
			RemediationZh:  list[i].RemediationZh,
			ExpectedResult: list[i].ExpectedResult,
			Audit:          list[i].Audit,
			ClassifiedZh:   list[i].ClassifiedZh,
			ClassifiedEn:   list[i].ClassifiedEn,
		})
	}

	response.Ok(w, response.WithItems(rules), response.WithTotalItems(count))
}

func (a *ApiServer) RuleDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	scapType := r.Context().Value(sType).(uint8)

	id, err := param.Int(r, "id")
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewInvalidArgError(
			http.StatusBadRequest,
			errors.New("invalid id parameter"),
		))
		return
	}

	rule, err := a.service.RuleDetail(ctx, scapType, id)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	resp := scap.Rule{
		ID:             rule.Id,
		RawID:          rule.PolicyId,
		TitleEn:        rule.TitleEn,
		TitleZh:        rule.TitleZh,
		DetailEn:       rule.DetailEn,
		DetailZh:       rule.DetailZh,
		RemediationEn:  rule.RemediationEn,
		RemediationZh:  rule.RemediationZh,
		ExpectedResult: rule.ExpectedResult,
		Audit:          rule.Audit,
		ClassifiedZh:   rule.ClassifiedZh,
		ClassifiedEn:   rule.ClassifiedEn,
	}

	if rule.PolicyDetailInfoExtraDetail != nil {
		resp.ExtraDetail = rule.PolicyDetailInfoExtraDetail
	}

	response.Ok(w, response.WithItem(resp))
}
