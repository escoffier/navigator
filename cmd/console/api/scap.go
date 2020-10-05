package api

import (
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kube"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	"go.mongodb.org/mongo-driver/bson"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/{clusterID}/reportsummaries", api.getScapReports())
		r.Get("/{checkType}/{clusterID}/reports", api.getScapReports())
		r.Post("/{checkType}/{clusterID}", api.scapCheck())
		r.Get("/{checkType}/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/{checkType}/breakdown/{checkID}", api.getCheckBreakdown())
		r.Get("/{checkType}/history", api.getCheckHistory())
		r.Get("/{checkType}/{clusterID}/cron", api.getCron())
		r.Put("/{checkType}/{clusterID}/cron", api.putCron())
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
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return

		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		sortBy := r.URL.Query().Get("sortBy")
		if sortBy == "" {
			sortBy = "createdAt"
		}
		if sortBy != "createdAt" && sortBy != "finishedAt" && sortBy != "checkID" && sortBy != "clusterID" && sortBy != "numSuccessful" && sortBy != "numFailed" && sortBy != "numError" && sortBy != "numWaiting" && sortBy != "numInconclusive" {
			logging.GetLogger().Info().Msg("invalid sortBy param value (allowed: createdAt/finishedAt/checkID/clusterID/numSuccessful/numFailed/numError/numWaiting/numInconclusive)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("sortBy", ""))
			return
		}

		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			logging.GetLogger().Info().Msg("invalid sortOrder param value (allowed: asc/desc)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("sortOrder", ""))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		checkMap := make(map[string]*scap.CheckHistoryEntry)
		if checkType == "kube" {
			err := kube.GetKubeHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := docker.GetDockerHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := host.GetHostHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
			logging.GetLogger().Info().Msg("checkID param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkID", ""))
			return
		}

		policyNumber := r.URL.Query().Get("policyNumber")

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		sortBy := r.URL.Query().Get("sortBy")
		if sortBy == "" {
			sortBy = "policyNumber"
		}
		if sortBy != "policyNumber" && sortBy != "name" && sortBy != "numFailed" && sortBy != "numSuccessful" && sortBy != "numInfo" && sortBy != "numWarn" {
			logging.GetLogger().Info().Msg("invalid sortBy param value (allowed: policyNumber/name/numFailed/numSuccessful/numInfo/numWarn)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("sortBy", ""))
			return
		}

		sortOrder := r.URL.Query().Get("sortOrder")
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			logging.GetLogger().Info().Msg("invalid sortOrder param value (allowed: asc/desc)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("sortOrder", ""))
			return
		}

		offset, limit := api.getOffsetAndLimit(r)

		filter := bson.M{"checkId": checkID}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		numWaiting := int64(0)
		numError := int64(0)
		checkMap := make(map[string]*scap.CheckBreakdown)

		if checkType == "kube" {
			err := kube.GetKubeBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := docker.GetDockerBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := host.GetHostBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		}

		var results []*scap.CheckBreakdown
		for _, v := range checkMap {
			results = append(results, v)
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Cursor error")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
			logging.GetLogger().Info().Msg("checkID param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkID", ""))
			return
		}

		policyNumber := chi.URLParam(r, "policyNumber")
		if policyNumber == "" {
			logging.GetLogger().Info().Msg("policyNumber param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("policyNumber", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return

		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		filter := bson.M{"checkId": checkID}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		policyDetails := &scap.PolicyDetails{}
		numWaiting := int64(0)
		numError := int64(0)

		if checkType == "kube" {
			err := kube.GetKubePolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := docker.GetDockerPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := host.GetHostPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Cursor error")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return

		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
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
			if status != "inprogress" && status != "error" && status != "completed" {
				logging.GetLogger().Info().Msg("invalid status param value (allowed: inprogress/error/completed)")
				response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("status", ""))
				return
			}
			filter["status"] = status
		}

		cursor, err := api.scapper.MongoDB.Collection(api.scapper.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		var results []scap.JobEntry
		for cursor.Next(ctx) {
			var result scap.JobEntry
			err := cursor.Decode(&result)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			// TODO: pagination, maybe https://github.com/gobeam/mongo-go-pagination?
			results = append(results, result)
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Cursor error")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w, response.WithItems(results))
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @ID v1-scap-check
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
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		cluster, err := api.clusterService.GetCluster(ctx, clusterObjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to get cluster from Mongo")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		checkUUID, err := api.scapper.RunComplianceCheck(ctx, api.ctx, clusterObjectID, cluster, checkType)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to run compliance check")
			apperror.RespondWithSuggested(w, r, err)
		}

		type resp struct {
			CheckUUID string `json:"checkUUID"`
		}

		response.Ok(w, response.WithItem(resp{
			CheckUUID: checkUUID.String(),
		}))
	}
}
