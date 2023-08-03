package scap

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (a *ApiServer) RuleBatch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

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

	keyword, _ := param.QueryString(r, "keyword")

	list, count, err := a.service.RuleBatch(ctx, scapType, keyword, limit, offset)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			err,
		))
		return
	}

	language := lang.Language(ctx)
	var rules = make([]scap.Rule, 0, len(list))
	for i := range list {
		tmp := scap.Rule{
			ID:    list[i].Id,
			RawID: list[i].PolicyId,
		}

		if model.ComplianceCheckType(scapType) == model.ComplianceCheckTargetTypeDocker {
			if strings.HasPrefix(list[i].PolicyId, "co") {
				tmp.Runtime = "cri-o"
			} else if strings.HasPrefix(list[i].PolicyId, "cd") {
				tmp.Runtime = "containerd"
			} else {
				tmp.Runtime = "docker"
			}
		}

		if language == lang.LanguageEN {
			tmp.Title = list[i].TitleEn
			tmp.Detail = list[i].DetailEn
			tmp.Remediation = list[i].RemediationEn
			tmp.Classified = list[i].ClassifiedEn
		} else {
			tmp.Title = list[i].TitleZh
			tmp.Detail = list[i].DetailZh
			tmp.Remediation = list[i].RemediationZh
			tmp.Classified = list[i].ClassifiedZh
		}

		rules = append(rules, tmp)
	}

	response.Ok(w, response.WithItems(rules), response.WithTotalItems(count))
}

func (a *ApiServer) RuleDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	scapType := r.Context().Value(sType).(string)

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
		ExpectedResult: rule.ExpectedResult,
		Audit:          rule.Audit,
	}

	if model.ComplianceCheckType(scapType) == model.ComplianceCheckTargetTypeDocker {
		if strings.HasPrefix(rule.PolicyId, "co") {
			resp.Runtime = "cri-o"
		} else if strings.HasPrefix(rule.PolicyId, "cd") {
			resp.Runtime = "containerd"
		} else {
			resp.Runtime = "docker"
		}
	}

	if lang.Language(ctx) == lang.LanguageEN {
		resp.Title = rule.TitleEn
		resp.Detail = rule.DetailEn
		resp.Remediation = rule.RemediationEn
		resp.Classified = rule.ClassifiedEn
	} else {
		resp.Title = rule.TitleZh
		resp.Detail = rule.DetailZh
		resp.Remediation = rule.RemediationZh
		resp.Classified = rule.ClassifiedZh
	}

	if rule.PolicyDetailInfoExtraDetail != nil {
		resp.ExtraDetail = &rule.PolicyDetailInfoExtraDetail.PolicyDetailInfoExtraDetail
	}

	response.Ok(w, response.WithItem(resp))
}
