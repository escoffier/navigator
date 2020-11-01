package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// @Summary List all crons
// @Description List all crons (for all check types and clusters)
// @Produce json
// @Router /api/v1/scap/crons [get]
func (api *api) listAllCrons() http.HandlerFunc {
	type RespItem struct {
		CronType    string `json:"cronType"`
		CronString  string `json:"cronString"`
		ClusterID   string `json:"clusterId"`
		ClusterName string `json:"clusterName"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		clusters, _, err := api.clusterService.ListClusters(ctx, 0, 9999999)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Couldn't list clusters: %w", err))
			return
		}

		respItems := []RespItem{}
		for _, clust := range clusters {
			respItems = append(respItems, RespItem{
				ClusterID:   clust.ID.Hex(),
				ClusterName: clust.ClusterName,
				CronType:    model.ComplianceCheckTargetTypeDocker,
				CronString:  clust.CronConfig.DockerBenchCron.CronString,
			})
			respItems = append(respItems, RespItem{
				ClusterID:   clust.ID.Hex(),
				ClusterName: clust.ClusterName,
				CronType:    model.ComplianceCheckTargetTypeHost,
				CronString:  clust.CronConfig.HostBenchCron.CronString,
			})
			respItems = append(respItems, RespItem{
				ClusterID:   clust.ID.Hex(),
				ClusterName: clust.ClusterName,
				CronType:    "kubernetes",
				CronString:  clust.CronConfig.KubeBenchCron.CronString,
			})
		}

		response.Ok(w,
			response.WithItems(respItems))
	}
}

// @Summary Get cron configured for this checkType and cluster
// @Description Get cron configured for this checkType and cluster
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron [get]
func (api *api) getCron() http.HandlerFunc {
	type respStruct struct {
		CronString string `json:"cronString,omitempty"`
		LastRun    int    `json:"lastRun,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		resp := respStruct{}

		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if checkType != model.ComplianceCheckTargetTypeKube &&
			checkType != model.ComplianceCheckTargetTypeDocker &&
			checkType != model.ComplianceCheckTargetTypeHost {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		cronConfig, err := api.cronService.GetCron(ctx, clusterObjectID, checkType)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to get cron: %w", err)))
			return
		}
		resp.CronString = cronConfig

		response.Ok(w, response.WithItem(resp))
	}
}

// @Summary Update cron configured for this checkType and cluster
// @Description Update cron configured for this checkType and cluster. To disable, send empty string.
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param cronString body string true "new crontab string to assign; empty string to disable"
// @Router /api/v1/scap/{checkType}/{clusterID}/cron [put]
func (api *api) putCron() http.HandlerFunc {
	type req struct {
		NewCronString string `json:"cronString"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if checkType != model.ComplianceCheckTargetTypeKube &&
			checkType != model.ComplianceCheckTargetTypeDocker &&
			checkType != model.ComplianceCheckTargetTypeHost {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		var req req
		err = util.DecodeJSONBody(w, r, &req)
		if err != nil {
			RespAndLog(w, r,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		err = api.cronService.UpdateCron(api.ctx, clusterObjectID, checkType, req.NewCronString)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to update cron: %w", err))
			return
		}

		response.Ok(w)
	}
}
