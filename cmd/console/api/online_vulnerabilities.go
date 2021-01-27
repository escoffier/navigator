package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) onlineVulnerabilities() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/current", api.getCurrentOnlineVulnerabilities())
		r.Get("/details/{namespace}/{resourceKind}/{resourceName}", api.getOnlineVulnerabilityDetails())
	}
}

// @Summary List current online vulnerabilities
// @Description List current online vulnerabilities
// @Produce json
// @Router /api/v1/onlineVulnerabilities/current [get]
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param cluster string false "case sensitive cluster name"
func (api *api) getCurrentOnlineVulnerabilities() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		offset, limit := api.getOffsetAndLimit(r)

		cluster := chi.URLParam(r, "cluster")
		if len(cluster) == 0 {
			cluster = "default"
		}

		vulns, err := api.onlineVulnsSvc.ListCurrentOnlineVulnerabilities(ctx, cluster, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		docNum := int64(len(vulns))
		actualOffset := int(math.Min(float64(offset), float64(len(vulns))))
		actualLimit := int(math.Min(float64(offset+limit), float64(len(vulns))))
		response.Ok(w,
			response.WithItems(vulns[actualOffset:actualLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Get details of online vulnerabiilty
// @Description Get details of online vulnerabiilty
// @Produce json
// @Router /api/v1/onlineVulnerabilities/details/{namespace}/{resourceKind}/{resourceName} [get]
// @Param resourceKind query string false "case-sensitive resource kind"
// @Param resourceName query string false "case-sensitive resource name"
// @Param cluster query string false "case-sensitive k8s cluster name"
func (api *api) getOnlineVulnerabilityDetails() http.HandlerFunc {
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

		cluster := chi.URLParam(r, "cluster")
		if cluster == "" {
			cluster = "default"
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
		if resourceKind == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Missing param 'resourceKind'"),
					Suberror{"resourceKind", ""}))
			return
		}

		vulnDetails, err := api.onlineVulnsSvc.GetOnlineVulnerabilityDetails(ctx, cluster, namespace, resourceKind, resourceName)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItem(*vulnDetails))
	}
}
