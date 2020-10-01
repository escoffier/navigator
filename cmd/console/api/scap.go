package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/{clusterID}/reportsummaries", api.getScapReports())
		r.Get("/{checkType}/{clusterID}/reports", api.getScapReports())
		r.Post("/{checkType}/{clusterID}", api.scapCheck())
		r.Get("/kube/breakdown/{checkID}/{policyNumber}/details", api.getPolicyDetails())
		r.Get("/kube/breakdown/{checkID}", api.getKubeBreakdown())
		r.Get("/kube/history", api.getKubeHistory())
		r.Get("/{checkType}/{clusterID}/cron", api.getCron())
		r.Post("/{checkType}/{clusterID}/cron", api.postCron())
	}
}

type KubeCheckBreakdown struct {
	PolicyNumber  string `json:"policyNumber"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	NumSuccessful int64  `json:"numSuccessful"`
	NumFailed     int64  `json:"numFailed"`
	NumInfo       int64  `json:"numInfo"`
	NumWarn       int64  `json:"numWarn"`
}

type JobEntry struct {
	ID         primitive.ObjectID      `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string                  `json:"check_id" bson:"checkId"`
	NodeName   string                  `json:"node_name" bson:"nodeName"`
	ClusterID  string                  `json:"cluster_id" bson:"clusterId"`
	Status     string                  `json:"status" bson:"status,omitempty"`
	CreatedAt  int64                   `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                   `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     map[string]ReportResult `json:"report" bson:"report,omitempty"`
}

type ReportResult struct {
	ID       string    `json:"id" bson:"id"`
	Version  string    `json:"version" bson:"version"`
	Text     string    `json:"text" bson:"text"`
	NodeType string    `json:"node_type" bson:"node_type"`
	Tests    []Section `json:"tests" bson:"tests"`
}

type Section struct {
	Section     string       `json:"section" bson:"section"`
	Pass        int64        `json:"pass" bson:"pass"`
	Fail        int64        `json:"fail" bson:"fail"`
	Warn        int64        `json:"warn" bson:"warn"`
	Info        int64        `json:"info" bson:"info"`
	Description string       `json:"desc" bson:"desc"`
	Results     []TestResult `json:"results" bson:"results"`
}

type KubeCheckHistoryEntry struct {
	CheckId         string `json:"checkId"`
	ClusterId       string `json:"clusterId"`
	CreatedAt       int64  `json:"createdAt"`
	FinishedAt      int64  `json:"finishedAt,omitempty"`
	NumSuccessful   int64  `json:"numSuccessful"`
	NumFailed       int64  `json:"numFailed"`
	NumError        int64  `json:"numError"`
	NumWaiting      int64  `json:"numWaiting"`
	NumInconclusive int64  `json:"numInconclusive"`
}

type TestResult struct {
	TestNumber      string   `json:"test_number" bson:"test_number"`
	TestDescription string   `json:"test_desc" bson:"test_desc"`
	Audit           string   `json:"audit" bson:"audit"`
	Type            string   `json:"type" bson:"type"`
	Remediation     string   `json:"remediation" bson:"remediation"`
	TestInfo        []string `json:"test_info" bson:"test_info"`
	ExpectedResult  string   `json:"expected_result" bson:"expected_result"`
	IsMultiple      bool     `json:"IsMultiple" bson:"IsMultiple"`
	ActualValue     string   `json:"actual_value" bson:"actual_value"`
	Status          string   `json:"status" bson:"status"`
}

type PolicyDetails struct {
	PolicyNumber   string   `json:"policyNumber"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Audit          string   `json:"audit"`
	ExpectedResult string   `json:"expectedResult"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"testInfo"`
	NumSuccessful  int64    `json:"numSuccessful"`
	NumFailed      int64    `json:"numFailed"`
	NumInfo        int64    `json:"numInfo"`
	NumWarn        int64    `json:"numWarn"`
	FailedOn       []string `json:"failedOn"`
	WarnOn         []string `json:"warnOn"`
	InfoOn         []string `json:"infoOn"`
	SuccessfulOn   []string `json:"successfulOn"`
}

// @Summary Get kube history
// @Description Get kube history
// @ID v1-kube-history
// @Produce json
// @Param checkID query string false "checkID"
// @Param clusterID query string false "clusterID"
// @Router /api/v1/scap/kube/history [get]
func (api *api) getKubeHistory() http.HandlerFunc {
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

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType("kube")).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		kubeCheckMap := make(map[string]*KubeCheckHistoryEntry)
		for cursor.Next(ctx) {
			var complianceTest JobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			if _, ok := kubeCheckMap[complianceTest.CheckID]; !ok {
				kubeCheckMap[complianceTest.CheckID] = &KubeCheckHistoryEntry{
					CheckId:   complianceTest.CheckID,
					ClusterId: complianceTest.ClusterID,
					CreatedAt: complianceTest.CreatedAt,
				}
				// We already had a node that didn't finish yet
			}
			if complianceTest.CreatedAt < kubeCheckMap[complianceTest.CheckID].CreatedAt {
				kubeCheckMap[complianceTest.CheckID].CreatedAt = complianceTest.CreatedAt
			}
			if kubeCheckMap[complianceTest.CheckID].FinishedAt != -1 {
				if complianceTest.Status == "inprogress" {
					// Set to -1 not to 0, because 0 is the starting value.
					kubeCheckMap[complianceTest.CheckID].FinishedAt = -1
				} else {
					if kubeCheckMap[complianceTest.CheckID].FinishedAt < complianceTest.FinishedAt {
						kubeCheckMap[complianceTest.CheckID].FinishedAt = complianceTest.FinishedAt
					}
				}
			}
			if complianceTest.Status == "inprogress" {
				kubeCheckMap[complianceTest.CheckID].NumWaiting++
				continue
			}
			if complianceTest.Status == "error" {
				kubeCheckMap[complianceTest.CheckID].NumError++
				continue
			}
			policiesFailed := int64(0)
			policiesInconclusive := int64(0)
			policiesPassed := int64(0)
			for _, reportDetails := range complianceTest.Report {
				for _, section := range reportDetails.Tests {
					policiesFailed += section.Fail
					policiesPassed += section.Pass
					policiesInconclusive += section.Info
					policiesInconclusive += section.Warn
				}
			}
			if policiesFailed != 0 {
				kubeCheckMap[complianceTest.CheckID].NumFailed++
			} else if policiesInconclusive != 0 {
				kubeCheckMap[complianceTest.CheckID].NumInconclusive++
			} else {
				kubeCheckMap[complianceTest.CheckID].NumSuccessful++
			}
		}

		var results []*KubeCheckHistoryEntry
		for _, v := range kubeCheckMap {
			// Convert -1 to 0 to omit the FinishedAt field
			if v.FinishedAt == -1 {
				v.FinishedAt = 0
			}
			results = append(results, v)
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

// @Summary Get kube scap job breakdown
// @Description Get kube scap job breakdown
// @ID v1-kube-job-breakdown
// @Produce json
// @Param checkID path string true "check ID"
// @Param policyNumber query string false "policy number"
// @Router /api/v1/scap/kube/breakdown/{checkID} [get]
func (api *api) getKubeBreakdown() http.HandlerFunc {
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

		filter := bson.M{"checkId": checkID}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType("kube")).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		numWaiting := 0
		numError := 0
		kubeCheckMap := make(map[string]*KubeCheckBreakdown)
		for cursor.Next(ctx) {
			var complianceTest JobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			if complianceTest.Status == "error" {
				numError++
				continue
			}
			if complianceTest.Status == "inprogress" {
				numWaiting++
				continue
			}
			for _, reportDetails := range complianceTest.Report {
				for _, section := range reportDetails.Tests {
					testName := section.Description
					for _, test := range section.Results {
						testDescription := test.TestDescription
						testNumber := test.TestNumber
						if policyNumber != "" && policyNumber != testNumber {
							continue
						}
						if _, ok := kubeCheckMap[testName]; !ok {
							kubeCheckMap[testName] = &KubeCheckBreakdown{
								PolicyNumber: testNumber,
								Name:         testName,
								Description:  testDescription,
							}
						}
						testStatus := test.Status
						if testStatus == "FAIL" {
							kubeCheckMap[testName].NumFailed++
						} else if testStatus == "WARN" {
							kubeCheckMap[testName].NumWarn++
						} else if testStatus == "PASS" {
							kubeCheckMap[testName].NumSuccessful++
						} else if testStatus == "INFO" {
							kubeCheckMap[testName].NumInfo++
						}
					}
				}
			}
		}
		var results []*KubeCheckBreakdown
		for _, v := range kubeCheckMap {
			results = append(results, v)
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Cursor error")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w, response.WithCustomField("numWaiting", numWaiting), response.WithCustomField("numError", numError), response.WithItems(results))
	}
}

// @Summary Get kube scap job policy
// @Description Get kube scap job policy
// @ID v1-kube-job-policy
// @Produce json
// @Param checkID path string true "check ID"
// @Param policyNumber path string true "policy number"
// @Router /api/v1/scap/kube/breakdown/{checkID}/{policyNumber}/details [get]
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

		filter := bson.M{"checkId": checkID}

		cursor, err := api.mongodb.Collection(api.scapper.GetMongoCollectionForCheckType("kube")).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		policyDetails := &PolicyDetails{}
		numWaiting := 0
		numError := 0
		for cursor.Next(ctx) {
			var complianceTest JobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			if complianceTest.Status == "error" {
				numError++
				continue
			}
			if complianceTest.Status == "inprogress" {
				numWaiting++
				continue
			}

			for _, reportDetails := range complianceTest.Report {
				for _, section := range reportDetails.Tests {
					for _, test := range section.Results {
						if test.TestNumber == policyNumber {
							policyDetails.PolicyNumber = test.TestNumber
							policyDetails.Name = test.TestNumber
							policyDetails.Description = test.TestDescription
							policyDetails.Audit = test.Audit
							policyDetails.ExpectedResult = test.ExpectedResult
							policyDetails.Remediation = test.Remediation
							policyDetails.TestInfo = test.TestInfo
							testStatus := test.Status
							if testStatus == "FAIL" {
								policyDetails.NumFailed++
								policyDetails.FailedOn = append(policyDetails.FailedOn, complianceTest.NodeName)
							} else if testStatus == "WARN" {
								policyDetails.NumWarn++
								policyDetails.WarnOn = append(policyDetails.WarnOn, complianceTest.NodeName)
							} else if testStatus == "PASS" {
								policyDetails.NumSuccessful++
								policyDetails.SuccessfulOn = append(policyDetails.SuccessfulOn, complianceTest.NodeName)
							} else if testStatus == "INFO" {
								policyDetails.NumInfo++
								policyDetails.InfoOn = append(policyDetails.InfoOn, complianceTest.NodeName)
							}
						}
					}
				}
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

type Check struct {
	CheckType string
	CheckUUID uuid.UUID
	ClusterID string
	Namespace string
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

		var results []JobEntry
		for cursor.Next(ctx) {
			var result JobEntry
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

		cluster, err := api.getClusterFromMongo(ctx, clusterObjectID)
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
