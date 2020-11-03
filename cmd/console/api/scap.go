package api

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kube"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	"go.mongodb.org/mongo-driver/bson"
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
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		filter := bson.M{}

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		nodeName := chi.URLParam(r, "nodeName")
		if nodeName == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("nodeName param missing"),
					Suberror{"nodeName", ""}))
			return
		}
		filter["nodeName"] = nodeName

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

		col := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType))

		nodeCheckDetails := &scap.NodeCheckDetails{}
		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostNodeCheckDetails(ctx, col, filter, checkID, nodeCheckDetails)
			if err != nil {
				RespAndLog(w, r,
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
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
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

		sortBy := r.URL.Query().Get("sortBy")
		if sortBy == "" {
			sortBy = "createdAt"
		}
		if sortBy != "createdAt" && sortBy != "finishedAt" && sortBy != "checkID" && sortBy != "clusterID" && sortBy != "numSuccessful" && sortBy != "numFailed" && sortBy != "numError" && sortBy != "numWaiting" && sortBy != "numInconclusive" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortBy param value (allowed: createdAt/finishedAt/checkID/clusterID/numSuccessful/numFailed/numError/numWaiting/numInconclusive)"),
					Suberror{"sortBy", "allowed: createdAt/finishedAt/checkID/clusterID/numSuccessful/numFailed/numError/numWaiting/numInconclusive"}))
			return
		}

		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortOrder param value (allowed: asc/desc)"),
					Suberror{"sortOrder", "allowed: asc/desc"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))
			return
		}
		defer cursor.Close(ctx)

		checkMap := make(map[string]*scap.CheckHistoryEntry)
		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker history entries: %w", err)))
				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host history entries: %w", err)))
				return
			}
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))
			return
		}

		docNum := int64(len(checkMap))

		var results []*scap.CheckHistoryEntry
		for _, v := range checkMap {
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
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		policyNumber := r.URL.Query().Get("policyNumber")

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

		sortBy := r.URL.Query().Get("sortBy")
		if sortBy == "" {
			sortBy = "policyNumber"
		}
		if sortBy != "policyNumber" && sortBy != "name" && sortBy != "numFailed" && sortBy != "numSuccessful" && sortBy != "numInfo" && sortBy != "numWarn" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortBy param value (allowed: policyNumber/name/numFailed/numSuccessful/numInfo/numWarn)"),
					Suberror{"sortBy", "allowed: policyNumber/name/numFailed/numSuccessful/numInfo/numWarn"}))
			return
		}

		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("invalid sortOrder param value (allowed: asc/desc)"),
					Suberror{"sortOrder", "allowed: asc/desc"}))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		filter := bson.M{"checkId": checkID}

		count, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))

			return
		}
		if count == 0 {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID not existing"),
					Suberror{"checkID", checkID}))
			return
		}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find documents: %w", err)))

			return
		}
		defer cursor.Close(ctx)

		numWaiting := int64(0)
		numError := int64(0)
		checkMap := make(map[string]*scap.CheckBreakdown)

		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubeBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube breakdown entries: %w", err)))

				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker breakdown entries: %w", err)))

				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
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
			RespAndLog(w, r,
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
			response.WithCustomField("numWaiting", numWaiting),
			response.WithCustomField("numError", numError),
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
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID param missing"),
					Suberror{"checkID", ""}))
			return
		}

		policyNumber := chi.URLParam(r, "policyNumber")
		if policyNumber == "" {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("policyNumber param missing"),
					Suberror{"policyNumber", ""}))
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

		filter := bson.M{"checkId": checkID}

		count, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).CountDocuments(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find document: %w", err)))

			return
		}
		if count == 0 {
			RespAndLog(w, r,
				NewFieldError(http.StatusBadRequest,
					fmt.Errorf("checkID not existing"),
					Suberror{"checkID", checkID}))
			return
		}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't update cluster: %w", err)))

			return
		}
		defer cursor.Close(ctx)

		policyDetails := &scap.PolicyDetails{}
		numWaiting := int64(0)
		numError := int64(0)

		if checkType == model.ComplianceCheckTargetTypeKube {
			err := kube.GetKubePolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get kube policy details: %w", err)))

				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeDocker {
			err := docker.GetDockerPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get docker policy details: %w", err)))

				return
			}
		} else if checkType == model.ComplianceCheckTargetTypeHost {
			err := host.GetHostPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't get host policy details: %w", err)))

				return
			}
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))

			return
		}

		response.Ok(w, response.WithCustomField("numWaiting", numWaiting), response.WithCustomField("numError", numError), response.WithItem(*policyDetails))
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

		filter := bson.M{"clusterId": clusterObjectID.Hex()}

		checkID := r.URL.Query().Get("checkId")
		if checkID != "" {
			filter["checkId"] = checkID
		}

		nodeName := r.URL.Query().Get("nodeName")
		if nodeName != "" {
			filter["nodeName"] = nodeName
		}

		status := r.URL.Query().Get("status")
		if status != "" {
			if status != model.ComplianceCheckStatusCompleted && status != model.ComplianceCheckStatusInProgress && status != model.ComplianceCheckStatusFailed {
				allowed := strings.Join([]string{model.ComplianceCheckStatusCompleted, model.ComplianceCheckStatusInProgress, model.ComplianceCheckStatusFailed}, "/")
				RespAndLog(w, r,
					NewFieldError(http.StatusBadRequest,
						fmt.Errorf("invalid status param value (allowed: %s)", allowed),
						Suberror{"status", fmt.Sprintf("allowed: %s", allowed)}))
				return
			}
			filter["status"] = status
		}

		cursor, err := api.scapper.MongoDB.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't find documents: %w", err)))

			return
		}
		defer cursor.Close(ctx)

		var results []scap.JobEntry
		for cursor.Next(ctx) {
			var result scap.JobEntry
			err := cursor.Decode(&result)
			if err != nil {
				RespAndLog(w, r,
					NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Couldn't decode document: %w", err)))

				return
			}
			// TODO: pagination, maybe https://github.com/gobeam/mongo-go-pagination?
			results = append(results, result)
		}

		err = cursor.Err()
		if err != nil {
			RespAndLog(w, r,
				NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Cursor error: %w", err)))

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

		cluster, err := api.clusterService.GetCluster(ctx, clusterObjectID)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to get cluster from Mongo: %w", err))
			return
		}

		checkUUID, err := api.scapper.RunComplianceCheck(ctx, api.ctx, clusterObjectID, cluster, checkType)
		if err != nil {
			RespAndLog(w, r, fmt.Errorf("Failed to run compliance check: %w", err))
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
