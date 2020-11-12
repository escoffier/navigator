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

func (api *api) config() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/clusters", api.listClusters())
		r.Post("/cluster", api.addCluster())
		r.Get("/cluster/{clusterID}", api.getCluster())
		r.Delete("/cluster/{clusterID}", api.delCluster())
		r.Put("/cluster/{clusterID}", api.updateCluster())
	}
}

// @Summary Get single cluster information
// @Description Get single cluster information
// @ID v1-config-cluster-get
// @Produce json
// @Param clusterID path string true "clusterID"
// @Router /api/v1/config/clusters/{clusterID} [get]
func (api *api) getCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		queryCluster, err := api.clusterService.GetCluster(ctx, clusterObjectID, true)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't get cluster: %w", err))
			return
		}

		response.Ok(w, response.WithItem(*queryCluster))
	}
}

// @Summary Get all clusters information
// @Description Get all cluster information
// @ID v1-config-cluster-get-all
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/config/clusters [get]
func (api *api) listClusters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()
		offset, limit := api.getOffsetAndLimit(r)

		clusters, docNum, err := api.clusterService.ListClusters(ctx, offset, limit)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't list clusters: %w", err))
			return
		}

		response.Ok(w,
			response.WithItems(clusters),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Update single cluster information
// @Description Update single cluster information
// @ID v1-config-cluster-put
// @Produce json
// @Param clusterID path string true "clusterID"
// @Param name body string true "clusterID"
// @Param config body string true "kubeConfig -- base64String"
// @Router /api/v1/config/clusters/{clusterID} [put]
func (api *api) updateCluster() http.HandlerFunc {
	type resp struct {
		Message string `json:"message"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*120) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		var upCluster model.ClusterUpdateRequest

		err = util.DecodeJSONBody(w, r, &upCluster)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		_, err = api.clusterService.UpdateCluster(ctx, clusterObjectID, &upCluster)

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(resp{
			Message: "Successful updated",
		}))
	}
}

// @Summary Add new cluster
// @Description Add new cluster
// @ID v1-config-cluster-post
// @Produce json
// @Param name body string true "clusterName"
// @Param config body string true "kubeConfig -- base64String "
// @Router /api/v1/config/clusters [post]
func (api *api) addCluster() http.HandlerFunc {
	type resp struct {
		ClusterID string `json:"clusterID"`
	}
	type param struct {
		ClusterName string `json:"name" bson:"name"`
		KubeConfig  string `json:"config" bson:"config"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*120) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		err := util.DecodeJSONBody(w, r, &param)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		// For now, cap at 1 cluster max:
		_, numClusters, err := api.clusterService.ListClusters(ctx, 0, 9999999)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't list clusters: %w", err))
			return
		}
		if numClusters >= 1 {
			RespAndLog(w, ctx,
				NewMaxNumberOfClustersReached(http.StatusConflict,
					fmt.Errorf("Max num of clusters reached")))
			return
		}

		id, err := api.clusterService.AddCluster(ctx, param.ClusterName, param.KubeConfig)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Couldn't add cluster: %w", err))
			return
		}

		response.Ok(w, response.WithItem(resp{
			ClusterID: fmt.Sprintf("%v", id.Hex()),
		}))
	}
}

// @Summary Delete a cluster
// @Description Delete a cluster by cluster ID
// @ID v1-config-cluster-delete
// @Produce json
// @Param clusterID path string true "clusterID"
// @Router /api/v1/config/clusters/{clusterID} [delete]
func (api *api) delCluster() http.HandlerFunc {
	type resp struct {
		Message string `json:"message"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*120) // long timeout because onlineVulnerabilities need sync
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read clusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		deletedCount, err := api.clusterService.DeleteCluster(ctx, clusterObjectID)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't delete ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		response.Ok(w, response.WithItem(resp{
			Message: fmt.Sprintf("MongoDB DeletedCount: %d", deletedCount),
		}))
	}
}
