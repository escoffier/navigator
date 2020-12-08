package scapper

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	rcache "gitlab.com/piccolo_su/vegeta/pkg/cache"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ScapService struct {
	mongodb         *mongo.Database
	kubeScapCache   *rcache.ScapCache
	dockerScapCache *rcache.ScapCache
	hostScapCache   *rcache.ScapCache
}

func NewScapService(
	ctx context.Context,
	redisClient *redis.Client,
	mongodb *mongo.Database,
) (*ScapService, error) {
	kubeScapCache, err := rcache.NewScapCache(ctx, mongodb, redisClient, model.ComplianceCheckTargetTypeKube)
	if err != nil {
		return nil, err
	}
	dockerScapCache, err := rcache.NewScapCache(ctx, mongodb, redisClient, model.ComplianceCheckTargetTypeDocker)
	if err != nil {
		return nil, err
	}
	hostScapCache, err := rcache.NewScapCache(ctx, mongodb, redisClient, model.ComplianceCheckTargetTypeHost)
	if err != nil {
		return nil, err
	}
	return &ScapService{
		mongodb:         mongodb,
		kubeScapCache:   kubeScapCache,
		dockerScapCache: dockerScapCache,
		hostScapCache:   hostScapCache,
	}, nil
}

func (s *ScapService) GetCheckHistory(ctx context.Context, checkType model.ComplianceCheckType, clusterID string, offset int64, limit int64, sortBy string, sortOrder string) ([]model.CheckHistoryEntry, int64, error) {
	var docNum int64
	var checkHistoryEntryIds []model.CacheEntry
	var err error
	switch checkType {
	case model.ComplianceCheckTargetTypeKube:
		checkHistoryEntryIds, docNum, err = s.kubeScapCache.GetItems(ctx, string(checkType), clusterID, offset, limit, sortBy, sortOrder)
	case model.ComplianceCheckTargetTypeDocker:
		checkHistoryEntryIds, docNum, err = s.dockerScapCache.GetItems(ctx, string(checkType), clusterID, offset, limit, sortBy, sortOrder)
	case model.ComplianceCheckTargetTypeHost:
		checkHistoryEntryIds, docNum, err = s.hostScapCache.GetItems(ctx, string(checkType), clusterID, offset, limit, sortBy, sortOrder)
	}

	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.CheckHistoryEntry, len(checkHistoryEntryIds))
	ids := make([]primitive.ObjectID, len(checkHistoryEntryIds))
	for i := range checkHistoryEntryIds {
		ids[i] = checkHistoryEntryIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)
	opts.SetSort(bson.D{{sortBy, util.SortOrderToInt(sortOrder)}})

	coll := s.mongodb.Collection(model.CheckHistoryEntryCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var checkHistoryNo int = 0
	for cur.Next(mongoCtx) {
		var checkHistory model.CheckHistoryEntry
		err := cur.Decode(&checkHistory)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		items[checkHistoryNo] = checkHistory
		checkHistoryNo++
	}
	return items, docNum, nil
}

func (s *ScapService) GetKubeNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest model.KubeJobEntry

	findOptions := options.FindOne().SetMaxTime(time.Second * 10)

	if checkID == "latest" {
		findOptions.SetSort(bson.D{{"finishedAt", -1}})
	} else {
		filter["checkId"] = checkID
	}

	err := col.FindOne(ctx, filter, findOptions).Decode(&complianceTest)
	if err != nil {
		return err
	}

	nodeCheckDetails.CheckID = complianceTest.CheckID
	nodeCheckDetails.ClusterID = complianceTest.ClusterID
	nodeCheckDetails.NodeName = complianceTest.NodeName
	nodeCheckDetails.Status = complianceTest.Status
	nodeCheckDetails.Logs = complianceTest.Logs
	if nodeCheckDetails.Status == model.ComplianceCheckStatusInProgress || nodeCheckDetails.Status == model.ComplianceCheckStatusFailed {
		return nil
	}

	complianceMap := make([]scap.ComplianceMapEntry, 0)

	for _, reportDetails := range complianceTest.Report {
		for _, section := range reportDetails.Tests {
			for _, test := range section.Results {
				complianceMapEntry := &scap.ComplianceMapEntry{}

				if lang.Language(ctx) == lang.LanguageZH {
					complianceMapEntry.Section = section.DescriptionZh
					complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionZh)
				} else {
					complianceMapEntry.Section = section.DescriptionEn
					complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionEn)
				}

				complianceMapEntry.PolicyNumber = test.TestNumber
				complianceMapEntry.TestStatus = test.Status
				complianceMap = append(complianceMap, *complianceMapEntry)
			}
		}
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func (s *ScapService) GetKubeBreakdownEntries(ctx context.Context, checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			*errorOn = util.AppendIfMissing(*errorOn, complianceTest.NodeName)
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			*waitingOn = util.AppendIfMissing(*waitingOn, complianceTest.NodeName)
			continue
		}
		for _, reportDetails := range complianceTest.Report {
			for _, section := range reportDetails.Tests {
				for _, test := range section.Results {

					testSection := section.DescriptionEn
					testDescription := util.RemoveScoredNotScoredFrom(test.TestDescriptionEn)
					if lang.Language(ctx) == lang.LanguageZH {
						testSection = section.DescriptionZh
						testDescription = util.RemoveScoredNotScoredFrom(test.TestDescriptionZh)
					}

					testNumber := test.TestNumber
					if policyNumber != "" && policyNumber != testNumber {
						continue
					}
					if _, ok := checkMap[testNumber]; !ok {
						checkMap[testNumber] = &scap.CheckBreakdown{
							PolicyNumber: testNumber,
							Section:      testSection,
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
		*successOn = util.AppendIfMissing(*successOn, complianceTest.NodeName)
	}
	return nil
}

func (s *ScapService) GetKubePolicyDetails(ctx context.Context, policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			policyDetails.ErrorOn = append(policyDetails.ErrorOn, complianceTest.NodeName)
			policyDetails.NumError++
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			policyDetails.WaitingOn = append(policyDetails.WaitingOn, complianceTest.NodeName)
			policyDetails.NumWaiting++
			continue
		}

		for _, reportDetails := range complianceTest.Report {
			for _, section := range reportDetails.Tests {
				for _, test := range section.Results {
					if policyNumber != test.TestNumber {
						continue
					}

					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Section = section.DescriptionZh
						policyDetails.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionZh)
						policyDetails.Remediation = test.RemediationZh
					} else {
						policyDetails.Section = section.DescriptionEn
						policyDetails.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionEn)
						policyDetails.Remediation = test.RemediationEn
					}

					policyDetails.PolicyNumber = test.TestNumber
					policyDetails.Audit = test.Audit
					policyDetails.ExpectedResult = test.ExpectedResult
					policyDetails.TestInfo = test.TestInfo
					policyDetails.Reason = test.Reason
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

func (s *ScapService) GetHostBreakdownEntries(ctx context.Context, checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.HostJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			*errorOn = util.AppendIfMissing(*errorOn, complianceTest.NodeName)
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			*waitingOn = util.AppendIfMissing(*waitingOn, complianceTest.NodeName)
			continue
		}
		for _, test := range complianceTest.Report.Results {

			testDescription := test.TitleEn
			if lang.Language(ctx) == lang.LanguageZH {
				testDescription = test.TitleZh
			}

			testNumber := test.RuleID
			if policyNumber != "" && policyNumber != testNumber {
				continue
			}
			if _, ok := checkMap[testNumber]; !ok {
				checkMap[testNumber] = &scap.CheckBreakdown{
					PolicyNumber: testNumber,
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
		*successOn = util.AppendIfMissing(*successOn, complianceTest.NodeName)
	}
	return nil
}

func (s *ScapService) GetHostNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest model.HostJobEntry

	findOptions := options.FindOne()

	if checkID == "latest" {
		findOptions.SetSort(bson.D{{"finishedAt", -1}})
	} else {
		filter["checkId"] = checkID
	}

	err := col.FindOne(ctx, filter, findOptions).Decode(&complianceTest)
	if err != nil {
		return err
	}

	nodeCheckDetails.CheckID = complianceTest.CheckID
	nodeCheckDetails.ClusterID = complianceTest.ClusterID
	nodeCheckDetails.NodeName = complianceTest.NodeName
	nodeCheckDetails.Status = complianceTest.Status
	nodeCheckDetails.Logs = complianceTest.Logs
	if nodeCheckDetails.Status == model.ComplianceCheckStatusInProgress || nodeCheckDetails.Status == model.ComplianceCheckStatusFailed {
		return nil
	}

	complianceMap := make([]scap.ComplianceMapEntry, 0)

	for _, test := range complianceTest.Report.Results {
		complianceMapEntry := &scap.ComplianceMapEntry{}

		if lang.Language(ctx) == lang.LanguageZH {
			complianceMapEntry.Description = test.TitleZh
		} else {
			complianceMapEntry.Description = test.TitleEn
		}

		complianceMapEntry.PolicyNumber = test.RuleID
		complianceMapEntry.TestStatus = test.Result
		complianceMap = append(complianceMap, *complianceMapEntry)
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func (s *ScapService) GetHostPolicyDetails(ctx context.Context, policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.HostJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			policyDetails.ErrorOn = append(policyDetails.ErrorOn, complianceTest.NodeName)
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			policyDetails.WaitingOn = append(policyDetails.WaitingOn, complianceTest.NodeName)
			continue
		}

		for _, test := range complianceTest.Report.Results {
			if test.RuleID == policyNumber {

				if lang.Language(ctx) == lang.LanguageZH {
					policyDetails.Description = test.TitleZh
					policyDetails.Details = test.DescriptionZh
					policyDetails.Rationale = test.RationaleZh
				} else {
					policyDetails.Description = test.TitleEn
					policyDetails.Details = test.DescriptionEn
					policyDetails.Rationale = test.RationaleEn
				}

				policyDetails.PolicyNumber = test.RuleID
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

func (s *ScapService) GetDockerNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest model.DockerJobEntry
	findOptions := options.FindOne()

	if checkID == "latest" {
		findOptions.SetSort(bson.D{{"finishedAt", -1}})
	} else {
		filter["checkId"] = checkID
	}

	err := col.FindOne(ctx, filter, findOptions).Decode(&complianceTest)
	if err != nil {
		return err
	}

	nodeCheckDetails.CheckID = complianceTest.CheckID
	nodeCheckDetails.ClusterID = complianceTest.ClusterID
	nodeCheckDetails.NodeName = complianceTest.NodeName
	nodeCheckDetails.Status = complianceTest.Status
	nodeCheckDetails.Logs = complianceTest.Logs
	if nodeCheckDetails.Status == model.ComplianceCheckStatusInProgress || nodeCheckDetails.Status == model.ComplianceCheckStatusFailed {
		return nil
	}

	complianceMap := make([]scap.ComplianceMapEntry, 0)

	for _, test := range complianceTest.Report.Tests {
		for _, result := range test.Results {
			complianceMapEntry := &scap.ComplianceMapEntry{}

			if lang.Language(ctx) == lang.LanguageZH {
				complianceMapEntry.Section = test.DescriptionZh
				complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(result.DescriptionZh)
			} else {
				complianceMapEntry.Section = test.DescriptionEn
				complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(result.DescriptionEn)
			}

			complianceMapEntry.PolicyNumber = result.ID
			complianceMapEntry.TestStatus = result.Result
			complianceMap = append(complianceMap, *complianceMapEntry)
		}
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func (s *ScapService) GetDockerBreakdownEntries(ctx context.Context, checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			*errorOn = util.AppendIfMissing(*errorOn, complianceTest.NodeName)
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			*waitingOn = util.AppendIfMissing(*waitingOn, complianceTest.NodeName)
			continue
		}
		for _, test := range complianceTest.Report.Tests {

			for _, result := range test.Results {

				testSection := test.DescriptionEn
				testDescription := util.RemoveScoredNotScoredFrom(result.DescriptionEn)
				if lang.Language(ctx) == lang.LanguageZH {
					testSection = test.DescriptionZh
					testDescription = util.RemoveScoredNotScoredFrom(result.DescriptionZh)
				}

				testNumber := result.ID
				if policyNumber != "" && policyNumber != testNumber {
					continue
				}
				if _, ok := checkMap[testNumber]; !ok {
					checkMap[testNumber] = &scap.CheckBreakdown{
						PolicyNumber: testNumber,
						Section:      testSection,
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
		*successOn = util.AppendIfMissing(*successOn, complianceTest.NodeName)
	}
	return nil
}

func (s *ScapService) GetDockerPolicyDetails(ctx context.Context, policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest model.DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			policyDetails.ErrorOn = append(policyDetails.ErrorOn, complianceTest.NodeName)
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			policyDetails.WaitingOn = append(policyDetails.WaitingOn, complianceTest.NodeName)
			continue
		}

		for _, test := range complianceTest.Report.Tests {
			for _, result := range test.Results {
				if result.ID == policyNumber {

					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Section = test.DescriptionZh
						policyDetails.Description = util.RemoveScoredNotScoredFrom(result.DescriptionZh)
						policyDetails.Details = result.DetailsZh
					} else {
						policyDetails.Section = test.DescriptionEn
						policyDetails.Description = util.RemoveScoredNotScoredFrom(result.DescriptionEn)
						policyDetails.Details = result.DetailsEn
					}

					policyDetails.PolicyNumber = result.ID
					policyDetails.Items = result.Items
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
