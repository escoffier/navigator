package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/platformreport"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	platformReportDefaultTimeout = time.Second * 5
	platformReportAPIVersion     = "2.0"
)

func (api *api) platformReport() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", api.getReportTemplates())
		r.Get("/template", api.getSpecificTemplate())
		r.Post("/template", api.addReportTemplate())
		r.Put("/template", api.updateReportTemplate())
		r.Delete("/template", api.deleteReportTemplate())
		r.Post("/record", api.generateReportRecord())
		r.Get("/record", api.getReportRecords())
		r.Get("/recordDetail", api.getReportRecordDetail())
	}
}

func (api *api) addReportTemplate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		var template model.ReportTaskTemplate
		err := util.DecodeJSONBody(w, r, &template)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.AddReportTaskTemplate(ctx, &template)
		if err != nil {
			if err == platformreport.ErrInvalidTemplate {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "参数非法", "invalid arg"))
				return
			}

			if err == def.ErrTaskTemplateNameDuplicate {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "名称重复", "duplicate name"))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion), response.WithItem(template))
	}
}

func (api *api) updateReportTemplate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		var template model.ReportTaskTemplate
		err := util.DecodeJSONBody(w, r, &template)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		curTemplate, err := service.GetTemplateTask(ctx, template.ID)
		if err != nil {
			if err == def.ErrTaskTemplateNotExist {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"模版不存在", "template not exist"))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		if curTemplate.Type == model.ReportTaskTypeOneTime {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, errors.New("invalid op"),
					"不支持修改自定义类型报告", "not support updating one-time template"))
			return
		}

		if curTemplate.Type != template.Type {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, errors.New("invalid op"),
					"不支持修改报告类型", "not support updating template type"))
			return
		}

		err = service.UpdateReportTaskTemplate(ctx, &template)
		if err != nil {
			if err == platformreport.ErrInvalidTemplate {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "参数非法", "invalid arg"))
				return
			}

			if err == def.ErrTaskTemplateNameDuplicate {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "名称重复", "duplicate name"))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		latestTemplate, err := service.GetTemplateTask(ctx, template.ID)
		if err != nil {
			if err == def.ErrTaskTemplateNotExist {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"模版不存在", "template not exist"))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion), response.WithItem(*latestTemplate))
	}
}

func (api *api) deleteReportTemplate() http.HandlerFunc {
	type req struct {
		ID int32 `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		var cliReq req
		var err = util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.DeleteReportTaskTemplate(ctx, cliReq.ID)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion))
	}
}

const (
	maxTemplateLimit = 50
)

func (api *api) getReportTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = maxTemplateLimit
		}

		if limit > maxTemplateLimit {
			limit = maxTemplateLimit
		}

		query, err := param.QueryString(r, "query")
		if err != nil {
			query = ""
		}

		typeFilter, err := param.QueryString(r, "type")
		if err != nil {
			typeFilter = ""
		}

		var types []string
		if typeFilter != "" {
			types = strings.Split(typeFilter, ",")
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		templates, count, err := service.GetReportTaskTemplates(ctx, types, query, offset, limit)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion),
			response.WithTotalItems(count), response.WithItems(templates))
	}
}

func (api *api) getSpecificTemplate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		id, err := param.QueryInt32(r, "id")
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, errors.New("not specify id"),
					"未指定模版id", "not specify id"))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		template, err := service.GetTemplateTask(ctx, id)
		if err != nil {
			if err == def.ErrTaskTemplateNotExist {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, errors.New("template not exist"),
						"模版不存在", "template not exist"))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion), response.WithItem(*template))
	}
}

func (api *api) generateReportRecord() http.HandlerFunc {
	type req struct {
		TemplateID int32 `json:"templateID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.TriggerTask(ctx, cliReq.TemplateID)
		if err != nil {
			if err == def.ErrTaskTemplateNotExist {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"模版不存在", "template not exist"))
				return
			}

			if err == platformreport.ErrInvalidOp {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"非法操作", "invalid op"))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w)
	}
}

const (
	maxRecordLimit = 20
)

func (api *api) getReportRecords() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		offset, err := param.QueryUint(r, "offset")
		if err != nil {
			offset = 0
		}

		limit, err := param.QueryUint(r, "limit")
		if err != nil {
			limit = maxRecordLimit
		}

		if limit > maxRecordLimit {
			limit = maxRecordLimit
		}

		templateID, err := param.QueryInt32(r, "templateID")
		if err != nil || templateID <= 0 {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, errors.New("no id"),
					"请指定模版id", "not specify template id"))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		records, count, err := service.GetTemplateReports(ctx, templateID, offset, limit)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion),
			response.WithTotalItems(count), response.WithItems(records))
	}
}

func (api *api) getReportRecordDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), platformReportDefaultTimeout)
		defer cancel()

		uuid, err := param.QueryString(r, "uuid")
		if err != nil || uuid == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest, errors.New("no id"),
					"请指定报告id", "not specify report id"))
			return
		}

		service, ok := platformreport.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		report, err := service.GetReport(ctx, uuid)
		if err != nil {
			if err == def.ErrReportNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err,
						"报告不存在", "report not found"))
				return
			}
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(platformReportAPIVersion), response.WithItem(report))
	}
}
