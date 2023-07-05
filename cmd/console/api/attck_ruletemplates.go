package api

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/attck"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) getRuleTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		version1, err := param.QueryInt(r, "version1")
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		keyword, err := param.QueryString(r, "keyword")
		if err != nil {
			keyword = ""
		}

		ruleTemplates, err := service.GetRuleTemplates(ctx, version1, keyword, lang.Language(r.Context()))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w,
			response.WithItems(ruleTemplates),
			response.WithTotalItems(int64(len(ruleTemplates))),
			response.WithApiVersion(versionAPIVersion))
	}
}

func (api *api) createRuleTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var req struct {
			Version1    int    `json:"version1"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", err)))
			return
		}

		err = service.CreateRuleTemplates(ctx, req.Version1, req.Name, req.Description, model.GetUsernameFromContext(r.Context()), lang.Language(r.Context()))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{ID: "", Name: fmt.Sprintf("%d: %s", req.Version1, req.Name)}))
	}
}

func (api *api) applyRuleTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var req struct {
			Version1 int `json:"version1"`
			ID       int `json:"id"`
		}
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", err)))
			return
		}

		err = service.ApplyRuleTemplates(ctx, req.Version1, req.ID, lang.Language(r.Context()), model.GetUsernameFromContext(r.Context()))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", req.ID), Name: fmt.Sprintf("%d: %d", req.Version1, req.ID)}))
	}
}

func (api *api) deleteRuleTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var req struct {
			Version1 int `json:"version1"`
			ID       int `json:"id"`
		}
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", err)))
			return
		}

		err = service.DeleteRuleTemplates(ctx, req.Version1, req.ID, lang.Language(r.Context()))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w, response.WithTarget(&response.TargetRef{ID: fmt.Sprintf("%d", req.ID), Name: fmt.Sprintf("%d: %d", req.Version1, req.ID)}))
	}
}

func (api *api) getRuleTemplatesRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultConfigTimeout)
		defer cancel()
		service, ok := attck.GetServiceInstance()
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		var req struct {
			Version1 int       `json:"version1"`
			ID       int       `json:"id"`
			Keyword  *string   `json:"keyword"`
			RuleType *[]string `json:"rule_type"`
			Urgency  *[]bool   `json:"urgency"`
			Severity *[]int    `json:"severity"`
			Switch   *[]bool   `json:"switch"`
		}
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("parse body error %v", err)))
			return
		}

		templateRules, err := service.GetRuleTemplatesRules(ctx, req.Version1, req.ID, req.Keyword, req.RuleType, req.Urgency, req.Severity, req.Switch, lang.Language(r.Context()))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
			return
		}

		response.Ok(w,
			response.WithItems(templateRules),
			response.WithTotalItems(int64(len(templateRules))),
			response.WithApiVersion(versionAPIVersion))
	}
}
