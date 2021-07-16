package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// @Summary Get single cluster information
// @Description Get single cluster information
// @ID v1-config-cluster-get
// @Produce json
// @Param clusterID path string true "clusterID"
// @Router /api/v1/config/clusters/{clusterID} [get]
func (api *api) getCluster() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		clusterService, _ := cluster.Get(ctx)
		queryCluster, err := clusterService.GetCluster(ctx, clusterObjectID, true)
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
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
		defer cancel()
		offset, limit := api.getOffsetAndLimit(r)

		clusterService, _ := cluster.Get(ctx)
		clusters, docNum, err := clusterService.ListClusters(ctx, offset, limit)
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

		var upCluster model.Cluster

		err = util.DecodeJSONBody(w, r, &upCluster)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("Failed to decode json: %w", err)))
			return
		}

		clusterService, _ := cluster.Get(ctx)
		updatedCluster, err := clusterService.UpdateCluster(ctx, clusterObjectID, &upCluster)

		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(*updatedCluster))
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
		clusterService, _ := cluster.Get(ctx)
		_, numClusters, err := clusterService.ListClusters(ctx, 0, 9999999)
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

		id, err := clusterService.AddCluster(ctx, param.ClusterName, param.KubeConfig)
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

		clusterService, _ := cluster.Get(ctx)
		deletedCount, err := clusterService.DeleteCluster(ctx, clusterObjectID)
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
