package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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
		r.Post("/{checkType}/{clusterID}/cron", api.postCron())
	}
}

type JobEntry struct {
	ID         primitive.ObjectID     `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string                 `json:"check_id" bson:"checkId"`
	NodeName   string                 `json:"node_name" bson:"nodeName"`
	ClusterID  string                 `json:"cluster_id" bson:"clusterId"`
	Status     string                 `json:"status" bson:"status,omitempty"`
	CreatedAt  int64                  `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                  `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     map[string]interface{} `json:"report" bson:"report,omitempty"`
}

type HostJobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	ClusterID  string             `json:"cluster_id" bson:"clusterId"`
	Status     string             `json:"status" bson:"status,omitempty"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     HostReportResult   `json:"report" bson:"report,omitempty"`
}

type HostReportResult struct {
	Profile string           `json:"profile" bson:"profile"`
	Results []HostReportTest `json:"results" bson:"results"`
}

type HostReportTest struct {
	Description string `json:"profile" bson:"profile"`
	Rationale   string `json:"rationale" bson:"rationale"`
	Result      string `json:"result" bson:"result"`
	RuleID      string `json:"rule-id" bson:"rule-id"`
	Title       string `json:"title" bson:"title"`
}

type DockerJobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	ClusterID  string             `json:"cluster_id" bson:"clusterId"`
	Status     string             `json:"status" bson:"status,omitempty"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     DockerReportResult `json:"report" bson:"report,omitempty"`
}

type DockerReportResult struct {
	DockerBenchSecurity string          `json:"dockerbenchsecurity" bson:"dockerbenchsecurity"`
	Start               int64           `json:"start" bson:"start"`
	End                 int64           `json:"end" bson:"end"`
	Score               int64           `json:"score" bson:"score"`
	Checks              int64           `json:"checks" bson:"checks"`
	Hostname            string          `json:"hostname" bson:"hostname"`
	NodeType            string          `json:"node_type" bson:"node_type"`
	Tests               []DockerSection `json:"tests" bson:"tests"`
}

type DockerSection struct {
	ID          string       `json:"id" bson:"id"`
	Description string       `json:"description" bson:"description"`
	Results     []DockerTest `json:"results" bson:"results"`
}

type DockerTest struct {
	ID          string   `json:"id" bson:"id"`
	Description string   `json:"description" bson:"description"`
	Result      string   `json:"result" bson:"result"`
	Details     string   `json:"details" bson:"details"`
	Items       []string `json:"items" bson:"items"`
}

type KubeJobEntry struct {
	ID         primitive.ObjectID          `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string                      `json:"check_id" bson:"checkId"`
	NodeName   string                      `json:"node_name" bson:"nodeName"`
	ClusterID  string                      `json:"cluster_id" bson:"clusterId"`
	Status     string                      `json:"status" bson:"status,omitempty"`
	CreatedAt  int64                       `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                       `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     map[string]KubeReportResult `json:"report" bson:"report,omitempty"`
}

type KubeReportResult struct {
	ID       string        `json:"id" bson:"id"`
	Version  string        `json:"version" bson:"version"`
	Text     string        `json:"text" bson:"text"`
	NodeType string        `json:"node_type" bson:"node_type"`
	Tests    []KubeSection `json:"tests" bson:"tests"`
}

type KubeSection struct {
	Section     string           `json:"section" bson:"section"`
	Pass        int64            `json:"pass" bson:"pass"`
	Fail        int64            `json:"fail" bson:"fail"`
	Warn        int64            `json:"warn" bson:"warn"`
	Info        int64            `json:"info" bson:"info"`
	Description string           `json:"desc" bson:"desc"`
	Results     []KubeTestResult `json:"results" bson:"results"`
}

type KubeTestResult struct {
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

type CheckHistoryEntry struct {
	CheckID         string `json:"checkId"`
	ClusterID       string `json:"clusterId"`
	CreatedAt       int64  `json:"createdAt"`
	FinishedAt      int64  `json:"finishedAt,omitempty"`
	NumSuccessful   int64  `json:"numSuccessful"`
	NumFailed       int64  `json:"numFailed"`
	NumError        int64  `json:"numError"`
	NumWaiting      int64  `json:"numWaiting"`
	NumInconclusive int64  `json:"numInconclusive"`
}

type CheckBreakdown struct {
	PolicyNumber  string `json:"policyNumber"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	NumSuccessful int64  `json:"numSuccessful"`
	NumFailed     int64  `json:"numFailed"`
	NumInfo       int64  `json:"numInfo"`
	NumWarn       int64  `json:"numWarn"`
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

		checkMap := make(map[string]*CheckHistoryEntry)
		if checkType == "kube" {
			err := api.getKubeHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := api.getDockerHistoryEntries(checkMap, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := api.getHostHistoryEntries(checkMap, cursor, ctx)
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

		var results []*CheckHistoryEntry
		for _, v := range checkMap {
			// Convert -1 to 0 to omit the FinishedAt field
			if v.FinishedAt == -1 {
				v.FinishedAt = 0
			}
			results = append(results, v)
		}

		sort.Slice(results, func(i, j int) bool {
			if sortBy == "createdAt" {
				if sortOrder == "asc" {
					return results[i].CreatedAt < results[j].CreatedAt
				}
				return results[i].CreatedAt > results[j].CreatedAt
			} else if sortBy == "finishedAt" {
				if sortOrder == "asc" {
					return results[i].FinishedAt < results[j].FinishedAt
				}
				return results[i].FinishedAt > results[j].FinishedAt
			} else if sortBy == "checkID" {
				if sortOrder == "asc" {
					return results[i].CheckID < results[j].CheckID
				}
				return results[i].CheckID > results[j].CheckID
			} else if sortBy == "clusterID" {
				if sortOrder == "asc" {
					return results[i].ClusterID < results[j].ClusterID
				}
				return results[i].ClusterID > results[j].ClusterID
			} else if sortBy == "numSuccessful" {
				if sortOrder == "asc" {
					return results[i].NumSuccessful < results[j].NumSuccessful
				}
				return results[i].NumSuccessful > results[j].NumSuccessful
			} else if sortBy == "numFailed" {
				if sortOrder == "asc" {
					return results[i].NumFailed < results[j].NumFailed
				}
				return results[i].NumFailed > results[j].NumFailed
			} else if sortBy == "numWaiting" {
				if sortOrder == "asc" {
					return results[i].NumWaiting < results[j].NumWaiting
				}
				return results[i].NumWaiting > results[j].NumWaiting
			} else if sortBy == "numError" {
				if sortOrder == "asc" {
					return results[i].NumError < results[j].NumError
				}
				return results[i].NumError > results[j].NumError
			} else if sortBy == "numInconclusive" {
				if sortOrder == "asc" {
					return results[i].NumInconclusive < results[j].NumInconclusive
				}
				return results[i].NumInconclusive > results[j].NumInconclusive
			}
			if sortOrder == "asc" {
				return results[i].CreatedAt < results[j].CreatedAt
			}
			return results[i].CreatedAt > results[j].CreatedAt
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

func (api *api) getKubeHistoryEntries(checkMap map[string]*CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		fmt.Println("A")
		if _, ok := checkMap[complianceTest.CheckID]; !ok {
			checkMap[complianceTest.CheckID] = &CheckHistoryEntry{
				CheckID:   complianceTest.CheckID,
				ClusterID: complianceTest.ClusterID,
				CreatedAt: complianceTest.CreatedAt,
			}
			// We already had a node that didn't finish yet
		}
		fmt.Printf("%+v\n", checkMap)
		if complianceTest.CreatedAt < checkMap[complianceTest.CheckID].CreatedAt {
			checkMap[complianceTest.CheckID].CreatedAt = complianceTest.CreatedAt
		}
		if checkMap[complianceTest.CheckID].FinishedAt != -1 {
			if complianceTest.Status == "inprogress" {
				// Set to -1 not to 0, because 0 is the starting value.
				checkMap[complianceTest.CheckID].FinishedAt = -1
			} else {
				if checkMap[complianceTest.CheckID].FinishedAt < complianceTest.FinishedAt {
					checkMap[complianceTest.CheckID].FinishedAt = complianceTest.FinishedAt
				}
			}
		}
		if complianceTest.Status == "inprogress" {
			checkMap[complianceTest.CheckID].NumWaiting++
			continue
		}
		if complianceTest.Status == "error" {
			checkMap[complianceTest.CheckID].NumError++
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
			checkMap[complianceTest.CheckID].NumFailed++
		} else if policiesInconclusive != 0 {
			checkMap[complianceTest.CheckID].NumInconclusive++
		} else {
			checkMap[complianceTest.CheckID].NumSuccessful++
		}
	}
	return nil
}

func (api *api) getDockerHistoryEntries(checkMap map[string]*CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if _, ok := checkMap[complianceTest.CheckID]; !ok {
			checkMap[complianceTest.CheckID] = &CheckHistoryEntry{
				CheckID:   complianceTest.CheckID,
				ClusterID: complianceTest.ClusterID,
				CreatedAt: complianceTest.CreatedAt,
			}
			// We already had a node that didn't finish yet
		}
		if complianceTest.CreatedAt < checkMap[complianceTest.CheckID].CreatedAt {
			checkMap[complianceTest.CheckID].CreatedAt = complianceTest.CreatedAt
		}
		if checkMap[complianceTest.CheckID].FinishedAt != -1 {
			if complianceTest.Status == "inprogress" {
				// Set to -1 not to 0, because 0 is the starting value.
				checkMap[complianceTest.CheckID].FinishedAt = -1
			} else {
				if checkMap[complianceTest.CheckID].FinishedAt < complianceTest.FinishedAt {
					checkMap[complianceTest.CheckID].FinishedAt = complianceTest.FinishedAt
				}
			}
		}
		if complianceTest.Status == "inprogress" {
			checkMap[complianceTest.CheckID].NumWaiting++
			continue
		}
		if complianceTest.Status == "error" {
			checkMap[complianceTest.CheckID].NumError++
			continue
		}
		policiesFailed := int64(0)
		policiesInconclusive := int64(0)
		policiesPassed := int64(0)
		for _, test := range complianceTest.Report.Tests {
			for _, result := range test.Results {
				if result.Result == "INFO" {
					policiesInconclusive++
				} else if result.Result == "NOTE" {
					policiesInconclusive++
				} else if result.Result == "PASS" {
					policiesPassed++
				} else {
					policiesFailed++
				}
			}
		}
		if policiesFailed != 0 {
			checkMap[complianceTest.CheckID].NumFailed++
		} else if policiesInconclusive != 0 {
			checkMap[complianceTest.CheckID].NumInconclusive++
		} else {
			checkMap[complianceTest.CheckID].NumSuccessful++
		}
	}
	return nil
}

func (api *api) getHostHistoryEntries(checkMap map[string]*CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest HostJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if _, ok := checkMap[complianceTest.CheckID]; !ok {
			checkMap[complianceTest.CheckID] = &CheckHistoryEntry{
				CheckID:   complianceTest.CheckID,
				ClusterID: complianceTest.ClusterID,
				CreatedAt: complianceTest.CreatedAt,
			}
			// We already had a node that didn't finish yet
		}
		if complianceTest.CreatedAt < checkMap[complianceTest.CheckID].CreatedAt {
			checkMap[complianceTest.CheckID].CreatedAt = complianceTest.CreatedAt
		}
		if checkMap[complianceTest.CheckID].FinishedAt != -1 {
			if complianceTest.Status == "inprogress" {
				// Set to -1 not to 0, because 0 is the starting value.
				checkMap[complianceTest.CheckID].FinishedAt = -1
			} else {
				if checkMap[complianceTest.CheckID].FinishedAt < complianceTest.FinishedAt {
					checkMap[complianceTest.CheckID].FinishedAt = complianceTest.FinishedAt
				}
			}
		}
		if complianceTest.Status == "inprogress" {
			checkMap[complianceTest.CheckID].NumWaiting++
			continue
		}
		if complianceTest.Status == "error" {
			checkMap[complianceTest.CheckID].NumError++
			continue
		}
		policiesFailed := int64(0)
		policiesInconclusive := int64(0)
		policiesPassed := int64(0)
		for _, test := range complianceTest.Report.Results {
			if test.Result == "notselected" {
				policiesInconclusive++
			} else if test.Result == "pass" {
				policiesPassed++
			} else if test.Result == "fail" {
				policiesFailed++
			}
		}
		if policiesFailed != 0 {
			checkMap[complianceTest.CheckID].NumFailed++
		} else if policiesInconclusive != 0 {
			checkMap[complianceTest.CheckID].NumInconclusive++
		} else {
			checkMap[complianceTest.CheckID].NumSuccessful++
		}
	}
	return nil
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
		checkMap := make(map[string]*CheckBreakdown)

		if checkType == "kube" {
			err := api.getKubeBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := api.getDockerBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := api.getHostBreakdownEntries(checkMap, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		}

		var results []*CheckBreakdown
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
			if sortBy == "policyNumber" {
				if sortOrder == "asc" {
					return results[i].PolicyNumber < results[j].PolicyNumber
				}
				return results[i].PolicyNumber > results[j].PolicyNumber
			} else if sortBy == "name" {
				if sortOrder == "asc" {
					return results[i].Name < results[j].Name
				}
				return results[i].Name > results[j].Name
			} else if sortBy == "numFailed" {
				if sortOrder == "asc" {
					return results[i].NumFailed < results[j].NumFailed
				}
				return results[i].NumFailed > results[j].NumFailed
			} else if sortBy == "numSuccessful" {
				if sortOrder == "asc" {
					return results[i].NumSuccessful < results[j].NumSuccessful
				}
				return results[i].NumSuccessful > results[j].NumSuccessful
			} else if sortBy == "numInfo" {
				if sortOrder == "asc" {
					return results[i].NumInfo < results[j].NumInfo
				}
				return results[i].NumInfo > results[j].NumInfo
			} else if sortBy == "numWarn" {
				if sortOrder == "asc" {
					return results[i].NumWarn < results[j].NumWarn
				}
				return results[i].NumWarn > results[j].NumWarn
			}
			if sortOrder == "asc" {
				return results[i].PolicyNumber < results[j].PolicyNumber
			}
			return results[i].PolicyNumber > results[j].PolicyNumber
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

func (api *api) getKubeBreakdownEntries(checkMap map[string]*CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
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
					if _, ok := checkMap[testNumber]; !ok {
						checkMap[testNumber] = &CheckBreakdown{
							PolicyNumber: testNumber,
							Name:         testName,
							Description:  testDescription,
						}
					}
					testStatus := test.Status
					if testStatus == "FAIL" {
						checkMap[testNumber].NumFailed++
					} else if testStatus == "WARN" {
						checkMap[testNumber].NumWarn++
					} else if testStatus == "PASS" {
						checkMap[testNumber].NumSuccessful++
					} else if testStatus == "INFO" {
						checkMap[testNumber].NumInfo++
					}
				}
			}
		}
	}
	return nil
}

func (api *api) getDockerBreakdownEntries(checkMap map[string]*CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
			continue
		}
		for _, test := range complianceTest.Report.Tests {
			testName := test.Description
			for _, result := range test.Results {
				testDescription := result.Description
				testNumber := result.ID
				if policyNumber != "" && policyNumber != testNumber {
					continue
				}
				if _, ok := checkMap[testNumber]; !ok {
					checkMap[testNumber] = &CheckBreakdown{
						PolicyNumber: testNumber,
						Name:         testName,
						Description:  testDescription,
					}
				}
				testStatus := result.Result
				if testStatus == "WARN" {
					checkMap[testNumber].NumFailed++
				} else if testStatus == "NOTE" {
					checkMap[testNumber].NumInfo++
				} else if testStatus == "PASS" {
					checkMap[testNumber].NumSuccessful++
				} else if testStatus == "INFO" {
					checkMap[testNumber].NumInfo++
				}
			}
		}
	}
	return nil
}

func (api *api) getHostBreakdownEntries(checkMap map[string]*CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest HostJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
			continue
		}
		for _, test := range complianceTest.Report.Results {
			testDescription := test.Description
			testNumber := test.RuleID
			testName := test.Title
			if policyNumber != "" && policyNumber != testNumber {
				continue
			}
			if _, ok := checkMap[testNumber]; !ok {
				checkMap[testNumber] = &CheckBreakdown{
					PolicyNumber: testNumber,
					Name:         testName,
					Description:  testDescription,
				}
			}
			testStatus := test.Result
			if testStatus == "fail" {
				checkMap[testNumber].NumFailed++
			} else if testStatus == "notselected" {
				checkMap[testNumber].NumInfo++
			} else if testStatus == "pass" {
				checkMap[testNumber].NumSuccessful++
			}
		}
	}
	return nil
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

		policyDetails := &PolicyDetails{}
		numWaiting := int64(0)
		numError := int64(0)

		if checkType == "kube" {
			err := api.getKubePolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "docker" {
			err := api.getDockerPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
		} else if checkType == "host" {
			err := api.getHostPolicyDetails(policyDetails, &numWaiting, &numError, policyNumber, cursor, ctx)
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

func (api *api) getKubePolicyDetails(policyDetails *PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
			continue
		}

		for _, reportDetails := range complianceTest.Report {
			for _, section := range reportDetails.Tests {
				testName := section.Description
				for _, test := range section.Results {
					if policyNumber != test.TestNumber {
						continue
					}
					policyDetails.PolicyNumber = test.TestNumber
					policyDetails.Name = testName
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
	return nil
}

func (api *api) getDockerPolicyDetails(policyDetails *PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
			continue
		}

		for _, test := range complianceTest.Report.Tests {
			testName := test.Description
			for _, result := range test.Results {
				if result.ID == policyNumber {
					policyDetails.PolicyNumber = result.ID
					policyDetails.Name = testName
					policyDetails.Description = result.Description
					// TODO: how to classify Docker policy specific information?
					testStatus := result.Result
					if testStatus == "WARN" {
						policyDetails.NumFailed++
						policyDetails.FailedOn = append(policyDetails.FailedOn, complianceTest.NodeName)
					} else if testStatus == "NOTE" {
						policyDetails.NumInfo++
						policyDetails.InfoOn = append(policyDetails.InfoOn, complianceTest.NodeName)
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
	return nil
}

func (api *api) getHostPolicyDetails(policyDetails *PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest HostJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == "error" {
			*numError++
			continue
		}
		if complianceTest.Status == "inprogress" {
			*numWaiting++
			continue
		}

		for _, test := range complianceTest.Report.Results {
			if test.RuleID == policyNumber {
				policyDetails.PolicyNumber = test.RuleID
				policyDetails.Name = test.Title
				policyDetails.Description = test.Description
				// TODO: how to classify Host policy specific information?
				testStatus := test.Result
				if testStatus == "fail" {
					policyDetails.NumFailed++
					policyDetails.FailedOn = append(policyDetails.FailedOn, complianceTest.NodeName)
				} else if testStatus == "notselected" {
					policyDetails.NumInfo++
					policyDetails.InfoOn = append(policyDetails.InfoOn, complianceTest.NodeName)
				} else if testStatus == "pass" {
					policyDetails.NumSuccessful++
					policyDetails.SuccessfulOn = append(policyDetails.SuccessfulOn, complianceTest.NodeName)
				}
			}
		}
	}
	return nil
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
