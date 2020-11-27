package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kube"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/{clusterID}/reports", api.getScapReports())
		r.Post("/{checkType}/{clusterID}", api.scapCheck())
		r.Get("/{checkType}/{nodeName}/{checkID}/details", api.getNodeCheckDetails())
		r.Get("/{checkType}/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/{checkType}/breakdown/{checkID}", api.getCheckBreakdown())
		r.Get("/{checkType}/history", api.getCheckHistory())
		r.Get("/crons", api.listAllCrons())
		r.Get("/{checkType}/{clusterID}/cron", api.getCron())
		r.Put("/{checkType}/{clusterID}/cron", api.putCron())
	}
}

// @Summary Get node check details
// @Description Get node check details
// @ID v1-node-check-details-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param nodeName path string true "nodeName"
// @Param checkID path string true "checkID"
// @Router /api/v1/scap/{checkType}/{nodeName}/{checkID}/details [get]
func (api *api) getNodeCheckDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		filter := bson.M{}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		nodeName := chi.URLParam(r, "nodeName")
		if nodeName == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("nodeName param missing"),
					Suberror{"nodeName", ""}))
			return
		}
		filter["nodeName"] = nodeName

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		col := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType))

		nodeCheckDetails := &scap.NodeCheckDetails{}
		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host history entries: %w", err)))
				return
			}
		}
		response.Ok(w, response.WithItem(*nodeCheckDetails))
	}
}

// @Summary Get scap history
// @Description Get scap history
// @ID v1-scap-history
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID query string false "checkID"
// @Param clusterID query string false "clusterID"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param sortBy query string false "createdAt/finishedAt/checkID/clusterID/numSuccessful/numFailed/numError/numWaiting/numInconclusive"
// @Router /api/v1/scap/{checkType}/history [get]
func (api *api) getCheckHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		filter := bson.M{}

		checkID := r.URL.Query().Get("checkID")
		if checkID != "" {
			filter["checkId"] = checkID
		}

		clusterID := r.URL.Query().Get("clusterID")
		if clusterID != "" {
			filter["clusterId"] = clusterID
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		sortBy, err := api.sortByFromQuery(r, "createdAt", "finishedAt", "checkID", "numSuccessful", "numFailed", "numError", "numWaiting", "numInconclusive")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "asc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		findOptions := options.Find().SetMaxTime(time.Second * 10)

		cursor, err := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		checkMap := make(map[string]*scap.CheckHistoryEntry)
		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeHistoryEntries(ctx, checkMap, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerHistoryEntries(ctx, checkMap, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostHistoryEntries(ctx, checkMap, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host history entries: %w", err)))
				return
			}
		}

		// We want to return cluster names to frontend for nice rendering
		clusterNames := make(map[string]string)
		inactiveClusters := make(map[string]bool)
		for _, v := range checkMap {
			if _, ok := inactiveClusters[v.ClusterID]; ok {
				// Scap check references to deleted cluster
				continue
			}
			if _, ok := clusterNames[v.ClusterID]; !ok {
				clusterIDPrimitive, err := primitive.ObjectIDFromHex(v.ClusterID)
				if err != nil {
					RespAndLog(w, ctx,
						NewFieldError(http.StatusInternalServerError,
							fmt.Errorf("Cluster with invalid ID %s: %w", v.ClusterID, err)))
					return
				}

				queryCluster, err := api.clusterService.GetCluster(ctx, clusterIDPrimitive, true)
				if err != nil {
					switch err.(type) {
					case ClusterDoesntExistError:
						// Scap check references a deleted cluster
						inactiveClusters[v.ClusterID] = true
						continue
					default:
						RespAndLog(w, ctx, fmt.Errorf("Couldn't get cluster: %w", err))
						return
					}
				}

				clusterNames[v.ClusterID] = queryCluster.ClusterName
			}
			v.ClusterName = clusterNames[v.ClusterID]
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))
			return
		}

		docNum := int64(len(checkMap))

		var results []*scap.CheckHistoryEntry
		for _, v := range checkMap {
			if _, ok := inactiveClusters[v.ClusterID]; ok {
				continue
			}
			// Convert -1 to 0 to omit the FinishedAt field
			if v.FinishedAt == -1 {
				v.FinishedAt = 0
			}
			results = append(results, v)
		}

		sort.Slice(results, func(i, j int) bool {
			return api.sortBy(results[i], results[j], sortBy, sortOrder)
		})

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
		response.Ok(w,
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Get scap job breakdown
// @Description Get scap job breakdown
// @ID v1-scap-job-breakdown
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "check ID"
// @Param policyNumber query string false "policy number"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Param sortBy query string false "policyNumber/name/numFailed/numSuccessful/numInfo/numWarn"
// @Router /api/v1/scap/{checkType}/breakdown/{checkID} [get]
func (api *api) getCheckBreakdown() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		policyNumber := r.URL.Query().Get("policyNumber")

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		sortBy, err := api.sortByFromQuery(r, "policyNumber", "name", "numFailed", "numSuccessful", "numInfo", "numWarn")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		sortOrder, err := api.sortOrderFromQuery(r, "asc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		filter := bson.M{"checkId": checkID}

		findOptions := options.Find().SetMaxTime(time.Second * 10)

		count, err := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))

			return
		}
		if count == 0 {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID not existing"),
					Suberror{"checkID", checkID}))
			return
		}

		cursor, err := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find documents: %w", err)))

			return
		}
		defer cursor.Close(ctx)

		waitingOn := []string{}
		errorOn := []string{}
		successOn := []string{}
		checkMap := make(map[string]*scap.CheckBreakdown)

		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host breakdown entries: %w", err)))
				return
			}
		}

		var results []*scap.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))

			return
		}

		docNum := int64(len(checkMap))

		sort.Slice(results, func(i, j int) bool {
			return api.sortBy(results[i], results[j], sortBy, sortOrder)
		})

		resultsOffset := int(math.Min(float64(offset), float64(len(results))))
		resultsLimit := int(math.Min(float64(offset+limit), float64(len(results))))
		response.Ok(w,
			response.WithCustomField("waitingOn", waitingOn),
			response.WithCustomField("errorOn", errorOn),
			response.WithCustomField("successOn", successOn),
			response.WithItems(results[resultsOffset:resultsLimit]),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Get scap job policy
// @Description Get scap job policy
// @ID v1-scap-job-policy
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "check ID"
// @Param policyNumber path string true "policy number"
// @Router /api/v1/scap/{checkType}/breakdown/{checkID}/{policyNumber}/details [get]
func (api *api) getPolicyDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		policyNumber := chi.URLParam(r, "policyNumber")
		if policyNumber == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("policyNumber param missing"),
					Suberror{"policyNumber", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return

		}
		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		filter := bson.M{"checkId": checkID}

		count, err := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))

			return
		}
		if count == 0 {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID not existing"),
					Suberror{"checkID", checkID}))
			return
		}

		findOptions := options.Find().SetMaxTime(time.Second * 10)

		cursor, err := api.mongodb.Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))

			return
		}
		defer cursor.Close(ctx)

		policyDetails := &scap.PolicyDetails{}

		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubePolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube policy details: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerPolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker policy details: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostPolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host policy details: %w", err)))
				return
			}
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))

			return
		}

		response.Ok(w, response.WithItem(*policyDetails))
	}
}

// @Summary Get scap reports
// @Description Get scap report for cluster and filter criteria
// @ID v1-scap-job-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param checkID query string false "check ID"
// @Param nodeName query string false "node name"
// @Param status query string false "status (inprogress/error/completed)"
// @Router /api/v1/scap/{checkType}/{clusterID}/reports [get]
func (api *api) getScapReports() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return

		}
		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		checkID := r.URL.Query().Get("checkId")
		nodeName := r.URL.Query().Get("nodeName")
		status := r.URL.Query().Get("status")

		results, err := api.scapper.GetJobEntriesForCheck(ctx, clusterObjectID.Hex(), checkType, checkID, nodeName, status)
		if err != nil {
			RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithItems(results))
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterID} [post]
func (api *api) scapCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("Couldn't read ClusterID: %w", err),
					Suberror{"clusterID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkType param missing"),
					Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
					Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		cluster, err := api.clusterService.GetCluster(ctx, clusterObjectID, true)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get cluster from Mongo: %w", err))
			return
		}

		checkUUID, err := api.scapper.RunComplianceCheck(ctx, api.ctx, clusterObjectID, cluster, checkType)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to run compliance check: %w", err))
			return
		}

		type resp struct {
			CheckUUID string `json:"checkUUID"`
		}

		response.Ok(w, response.WithItem(resp{
			CheckUUID: checkUUID.String(),
		}))
	}
}
