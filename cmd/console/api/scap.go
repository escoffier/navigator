package api

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cluster"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/{clusterID}/reports", api.getScapReports())
		r.Post("/{checkType}/{clusterID}", api.scapCheck())
		r.Get("/{checkType}/{nodeName}/{checkID}/details", api.getNodeCheckDetails())
		r.Get("/{checkType}/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/{checkType}/breakdown/{checkID}", api.getCheckBreakdown())
		r.Get("/{checkType}/breakdown", api.getLatestScanRecord())
		r.Get("/{checkType}/history", api.getCheckHistory())
		r.Get("/crons", api.listAllCrons())
		r.Post("/harborScan", api.harborScan())
		r.Get("/harborScanList", api.harborScanList())
		r.Get("/{checkType}/{clusterID}/cron", api.getCron())
		r.Put("/{checkType}/{clusterID}/cron", api.putCron())
		r.Get("/{checkType}/{checkID}/exportfile", api.exportFile())
		r.Get("/{checkID}/getfile", api.getFile())
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
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		filter := bson.M{}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		nodeName := chi.URLParam(r, "nodeName")
		if nodeName == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("nodeName param missing"), Suberror{"nodeName", ""}))
			return
		}
		filter["nodeName"] = nodeName

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		scapService, _ := scapper.GetService(ctx)

		col := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType))

		nodeCheckDetails := &scap.NodeCheckDetails{}
		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			err := scapService.GetKubeNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeDocker:
			err := scapService.GetDockerNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeHost:
			err := scapService.GetHostNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host history entries: %w", err)))
				return
			}
		default:
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("checkType is error, %v.", checkType)))
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

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		sortBy, err := api.sortByFromQuery(r, model.GetDefaultScapSortableName(), model.GetScapSortableNames()...)
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

		scapService, _ := scapper.GetService(ctx)
		clusterService, _ := cluster.Get(ctx)

		items, docNum, err := scapService.GetCheckHistory(ctx, checkType, "", offset, limit, model.GetScapSortableField(sortBy), sortOrder)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host history entries: %w", err)))
			return
		}
		// We want to return cluster names to frontend for nice rendering
		clusterNames := make(map[string]string)
		inactiveClusters := make(map[string]bool)
		for i := range items {
			if _, ok := inactiveClusters[items[i].ClusterID]; ok {
				// Scap check references to deleted cluster
				continue
			}
			if _, ok := clusterNames[items[i].ClusterID]; !ok {
				clusterIDPrimitive, err := primitive.ObjectIDFromHex(items[i].ClusterID)
				if err != nil {
					RespAndLog(w, ctx, NewFieldError(http.StatusInternalServerError, fmt.Errorf("Cluster with invalid ID %s: %w", items[i].ClusterID, err)))
					return
				}

				queryCluster, err := clusterService.GetCluster(ctx, clusterIDPrimitive, true)
				if err != nil {
					switch err.(type) {
					case ClusterDoesntExistError:
						// Scap check references a deleted cluster
						inactiveClusters[items[i].ClusterID] = true
						continue
					default:
						RespAndLog(w, ctx, fmt.Errorf("Couldn't get cluster: %w", err))
						return
					}
				}

				clusterNames[items[i].ClusterID] = queryCluster.ClusterName
			}
			items[i].ClusterName = clusterNames[items[i].ClusterID]
			if items[i].FinishedAt == -1 {
				items[i].FinishedAt = 0
			}
		}

		response.Ok(w,
			response.WithItems(items),
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
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		sortOrder, err := api.sortOrderFromQuery(r, "asc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		policyNumber := r.URL.Query().Get("policyNumber")

		sortBy, err := api.sortByFromQuery(r, "policyNumber", "name", "numFailed", "numSuccessful", "numInfo", "numWarn")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		filter := bson.M{"checkId": checkID}

		findOptions := options.Find().SetMaxTime(time.Second * 2)

		count, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		if count == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID not existing"), Suberror{"checkID", checkID}))
			return
		}

		cursor, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		waitingOn := []string{}
		errorOn := []string{}
		successOn := []string{}
		checkMap := make(map[string]*scap.CheckBreakdown)

		scapService, _ := scapper.GetService(ctx)
		if checkType == model.ComplianceCheckTargetTypeKube {
			err := scapService.GetKubeBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := scapService.GetDockerBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := scapService.GetHostBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host breakdown entries: %w", err)))
				return
			}
		}

		var results []*scap.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Cursor error: %w", err)))
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

// @Summary Get scap job breakdown
// @Description Get scap job breakdown
// @ID v1-scap-job-breakdown
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param policyNumber query string false "policy number"
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Param sortOrder query string false "asc/desc"
// @Router /api/v1/scap/{checkType}/breakdown [get]
func (api *api) getLatestScanRecord() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)
		sortOrder, err := api.sortOrderFromQuery(r, "desc")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		scapService, _ := scapper.GetService(ctx)
		latest, err := scapService.GetLatestHistory(ctx, checkType, "", "createdAt", sortOrder)
		if err != nil {
			response.Ok(w, response.WithTotalItems(0))
			return
		}
		checkID := latest.CheckID

		policyNumber := r.URL.Query().Get("policyNumber")

		sortBy, err := api.sortByFromQuery(r, "policyNumber", "name", "numFailed", "numSuccessful", "numInfo", "numWarn")
		if err != nil {
			RespAndLog(w, r.Context(), err)
			return
		}

		filter := bson.M{"checkId": checkID}

		findOptions := options.Find().SetMaxTime(time.Second * 2)

		count, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		if count == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID not existing"), Suberror{"checkID", checkID}))
			return
		}

		cursor, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		waitingOn := []string{}
		errorOn := []string{}
		successOn := []string{}
		checkMap := make(map[string]*scap.CheckBreakdown)

		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			err := scapService.GetKubeBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeDocker:
			err := scapService.GetDockerBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeHost:
			err := scapService.GetHostBreakdownEntries(ctx, checkMap, &waitingOn, &errorOn, &successOn, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host breakdown entries: %w", err)))
				return
			}
		default:
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("checkType is error, %v.", checkType)))
			return
		}

		var results []*scap.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Cursor error: %w", err)))
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
			response.WithCheckId(checkID),
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
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing"), Suberror{"checkID", ""}))
			return
		}

		policyNumber := chi.URLParam(r, "policyNumber")
		if policyNumber == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("policyNumber param missing"), Suberror{"policyNumber", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return

		}
		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)"),
				Suberror{"checkType", "allowed: kube/docker/host"}))
			return
		}

		filter := bson.M{"checkId": checkID}

		count, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		if count == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID not existing"), Suberror{"checkID", checkID}))
			return
		}

		findOptions := options.Find().SetMaxTime(time.Second * 2)
		cursor, err := api.mongodb.Get().Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter, findOptions)
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update cluster: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		policyDetails := &scap.PolicyDetails{}
		policyDetails.CheckID = checkID

		scapService, _ := scapper.GetService(ctx)

		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			err := scapService.GetKubePolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get kube policy details: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeDocker:
			err := scapService.GetDockerPolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get docker policy details: %w", err)))
				return
			}
		case model.ComplianceCheckTargetTypeHost:
			err := scapService.GetHostPolicyDetails(ctx, policyDetails, policyNumber, cursor)
			if err != nil {
				RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get host policy details: %w", err)))
				return
			}
		default:
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("checkType is error, %v.", checkType)))
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, ctx, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Cursor error: %w", err)))
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
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID: %w", err), Suberror{"clusterID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return

		}
		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		checkID := r.URL.Query().Get("checkId")
		nodeName := r.URL.Query().Get("nodeName")
		status := r.URL.Query().Get("status")

		scapper, _ := scapper.GetScapper(ctx)
		results, err := scapper.GetJobEntriesForCheck(ctx, clusterObjectID.Hex(), checkType, checkID, nodeName, status)
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
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Couldn't read ClusterID: %w", err), Suberror{"clusterID", ""}))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing"), Suberror{"checkType", ""}))
			return
		}

		if !model.IsAnyCheckType(checkType) {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("invalid checkType param value (allowed: kube/docker/host)")))
			return
		}

		clusterService, _ := cluster.Get(ctx)
		cluster, err := clusterService.GetCluster(ctx, clusterObjectID, true)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("Failed to get cluster from Mongo: %w", err))
			return
		}
		//username
		username := "unknown"
		//get token
		_, claims, err := jwtauth.FromContext(r.Context())
		if err == nil && claims != nil {
			//get username from token
			username = claims[JWT_KEY_USERNAME].(string)
		}

		scapper, _ := scapper.GetScapper(ctx)
		checkUUID, err := scapper.RunComplianceCheck(ctx, api.ctx, clusterObjectID, cluster, checkType, username)
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

// @Router /api/v1/scap/harborScan [post]
func (api *api) harborScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*30)
		defer cancel()

		scapper, _ := scapper.GetScapper(ctx)
		checkUUID, err := scapper.RunHarborCheck(ctx, api.harborClient)
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

// @Router /api/v1/scap/harborScanList  {get}
func (api *api) harborScanList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
		defer cancel()

		projectName := r.URL.Query().Get("projectname")
		checkID := r.URL.Query().Get("checkid")
		offset, limit := api.getOffsetAndLimit(r)
		scapper, _ := scapper.GetScapper(ctx)
		items, docNum, err := scapper.HarborConfigList(ctx, offset, limit, projectName, checkID)
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

// @Router /{checkType}/exportfile  {get}
func (api *api) exportFile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		//username
		username := "unknown"
		//get token
		_, claims, err := jwtauth.FromContext(ctx)
		if err == nil && claims != nil {
			//get username from token
			username = claims[JWT_KEY_USERNAME].(string)
		}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing")))
			return
		}

		checkType := model.ComplianceCheckType(chi.URLParam(r, "checkType"))
		if checkType == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkType param missing")))
			return
		}

		var task model.ExportTask
		task.Status = 1
		filter := bson.M{"checkId": checkID, "username": username}

		findOptions := options.FindOne().SetMaxTime(time.Second * 1)
		//find export file task
		err = api.mongodb.Get().Collection(model.ExportFileTaskCollection.String()).FindOne(ctx, filter, findOptions).Decode(&task)
		if err == nil {
			_, err = os.Stat(task.FileName)
			if task.Status == 2 || err != nil {
				task.Status = 2
				os.Remove(task.FileName)
				_, delErr := api.mongodb.Get().Collection(model.ExportFileTaskCollection.String()).DeleteMany(ctx, filter)
				if delErr != nil {
					logging.GetLogger().WithContext(ctx).Errorf(delErr, "delete export tasks error")
				}
			}
			response.Ok(w, response.WithExportFileStatus(task.Status))
			return
		}
		language := lang.Language(ctx)
		task.UserName = username
		task.CheckType = string(checkType)
		task.CheckId = checkID
		task.CreatedAt = time.Now().Unix()
		task.FileName = fmt.Sprintf("/var/www/%s-%s-%v.xlsx", string(checkType), string(language), task.CreatedAt)
		//insert task data to mongo
		_, err = api.mongodb.Get().Collection(model.ExportFileTaskCollection.String()).InsertOne(ctx, task)
		if err != nil {
			task.Status = 2
		} else {
			//run export file task
			scapper, _ := scapper.GetScapper(ctx)
			go scapper.RunExportFileTask(api.ctx, checkType, &task, language)
		}

		response.Ok(w, response.WithExportFileStatus(task.Status))
	}
}

// @Router /{checkType}/getfile  {get}
func (api *api) getFile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*60)
		defer cancel()

		//username
		username := "unknown"
		//get token
		_, claims, err := jwtauth.FromContext(r.Context())
		if err == nil && claims != nil {
			//get username from token
			username = claims[JWT_KEY_USERNAME].(string)
		}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("checkID param missing")))
			return
		}
		var task model.ExportTask
		//filter
		filter := bson.M{"checkId": checkID, "username": username}

		findOptions := options.FindOne().SetMaxTime(time.Second * 1)
		//find export file task
		err = api.mongodb.Get().Collection(model.ExportFileTaskCollection.String()).FindOne(ctx, filter, findOptions).Decode(&task)
		if err != nil {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("%v", err)))
			return
		}
		//task status
		if task.Status == 1 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("Please wait while the file is being exported.")))
			return
		}
		//delete record
		_, delErr := api.mongodb.Get().Collection(model.ExportFileTaskCollection.String()).DeleteMany(ctx, filter)
		if delErr != nil {
			logging.GetLogger().WithContext(ctx).Errorf(delErr, "delete export tasks error")
		}
		if task.Status == 2 {
			os.Remove(task.FileName)
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("export file failed.")))
			return
		}
		//open file
		file, err := os.Open(task.FileName)
		if err != nil {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("%v", err)))
			return
		}
		defer file.Close()
		//file stat
		info, err := file.Stat()
		if err != nil {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, fmt.Errorf("%v", err)))
			return
		}
		data := strings.Split(task.FileName, "/")
		filename := data[len(data)-1]
		//set header
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		//file seek
		file.Seek(0, 0)
		io.Copy(w, file)
		//remove file
		os.Remove(task.FileName)
	}
}
