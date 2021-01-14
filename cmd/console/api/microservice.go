package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"net/http"
	"time"
)

//@Router /api/v1/microservice
func (api *api) Microservice() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/vulnerabilities/details/{namespace}/{resourceKind}/{resourceName}", api.getMicroOnlineVulnerabilityDetails())
		r.Get("/reportsByImage", api.listServiceScannedImages())
	}
}

// @Summary Get service  details of online vulnerabiilty
// @Description Get details of online vulnerabiilty
// @Produce json
// @Router /api/v1/microservice/vulnerabilities/details/{namespace}/{resourceKind}/{resourceName} [get]
// @Param resourceKind query string false "case-sensitive resource kind"
// @Param resourceName query string false "case-sensitive resource name"
func (api *api) getMicroOnlineVulnerabilityDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		namespace := chi.URLParam(r, "namespace")
		if namespace == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'namespace'"),
					Suberror{"namespace", ""}))
			return
		}

		resourceName := chi.URLParam(r, "resourceName")
		if resourceName == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'resourceName'"),
					Suberror{"resourceName", ""}))
			return
		}

		resourceKind := chi.URLParam(r, "resourceKind")
		if resourceKind == "" && resourceKind != "service" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'resourceKind'"),
					Suberror{"resourceKind", "only support service"}))
			return
		}

		vulnDetails, err := api.onlineVulnsSvc.GetOnlineVulnerabilityDetails(ctx, namespace, resourceKind, resourceName)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(*vulnDetails))
	}
}

// @Summary List service images and their vulnerabilities
// @Description List images and their vulnerabilities
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param maxImageAgeInHours query int false "return only images that have only scans younger than this number; 0 or empty disables"
// @Param sortBy query string false "finishedAt/overallSeverity/repository/tag/imageDigest"
// @Param namespace query string
// @Patam selecter query string "only service"
// @Patam svcname  query string "servername"
// @Router /api/v1/microservice/scanner/reportsByImage [get]
func (api *api) listServiceScannedImages() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"namespace", "string"}))
			return
		}

		selecter := r.URL.Query().Get("selecter")
		if selecter != "service" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("current only support service"),
				Suberror{"selecter", "service"}))
			return
		}
		svcname := r.URL.Query().Get("svcname")
		if svcname == "" {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest,
				fmt.Errorf("should not be empty"),
				Suberror{"svcname", "string"}))
			return
		}

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultScannedImagesSortableName(), model.GetScannedImagesSortableNames()...)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		items, docNum, err := api.scannerService.GetServiceScannedImages(ctx, offset, limit, model.ScannedImagesSortableFields[sortBy], namespace, svcname, sortOrder)
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}
		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}
