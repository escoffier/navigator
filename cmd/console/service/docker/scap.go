package docker

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetDockerHistoryEntries(ctx context.Context, checkMap map[string]*scap.CheckHistoryEntry, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest docker.DockerJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if _, ok := checkMap[complianceTest.CheckID]; !ok {
			checkMap[complianceTest.CheckID] = &scap.CheckHistoryEntry{
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
			if complianceTest.Status == model.ComplianceCheckStatusInProgress {
				// Set to -1 not to 0, because 0 is the starting value.
				checkMap[complianceTest.CheckID].FinishedAt = -1
			} else {
				if checkMap[complianceTest.CheckID].FinishedAt < complianceTest.FinishedAt {
					checkMap[complianceTest.CheckID].FinishedAt = complianceTest.FinishedAt
				}
			}
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
			checkMap[complianceTest.CheckID].NumWaiting++
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
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

		checkMap[complianceTest.CheckID].TotalPoliciesPassed += policiesPassed
		checkMap[complianceTest.CheckID].TotalPoliciesTried += policiesFailed + policiesInconclusive + policiesPassed

		if policiesFailed != 0 {
			checkMap[complianceTest.CheckID].NumFailed++
		} else if policiesInconclusive != 0 {
			checkMap[complianceTest.CheckID].NumInconclusive++
		} else {
			checkMap[complianceTest.CheckID].NumSuccessful++
		}
	}

	for _, ch := range checkMap {
		finishedNodesNum := ch.NumFailed + ch.NumInconclusive + ch.NumSuccessful
		if finishedNodesNum != 0 {
			ch.Score = float32(ch.TotalPoliciesPassed) / float32(finishedNodesNum)
			ch.MaxScore = float32(ch.TotalPoliciesTried) / float32(finishedNodesNum)
		}
	}

	return nil
}

func GetDockerNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest docker.DockerJobEntry
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
			complianceMapEntry.PolicyNumber = result.ID
			if lang.Language(ctx) == lang.LanguageZH {
				complianceMapEntry.Section = test.DescriptionZh
			} else {
				complianceMapEntry.Section = test.DescriptionEn
			}
			if lang.Language(ctx) == lang.LanguageZH {
				complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(result.DescriptionZh)
			} else {
				complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(result.DescriptionEn)
			}
			complianceMapEntry.TestStatus = result.Result
			complianceMap = append(complianceMap, *complianceMapEntry)
		}
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func GetDockerBreakdownEntries(ctx context.Context, checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest docker.DockerJobEntry
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
			testSection := test.DescriptionEn
			if lang.Language(ctx) == lang.LanguageZH {
				testSection = test.DescriptionZh
			}

			for _, result := range test.Results {
				testDescription := util.RemoveScoredNotScoredFrom(result.DescriptionEn)
				if lang.Language(ctx) == lang.LanguageZH {
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

func GetDockerPolicyDetails(ctx context.Context, policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest docker.DockerJobEntry
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
			testName := test.DescriptionEn
			if lang.Language(ctx) == lang.LanguageZH {
				testName = test.DescriptionZh
			}

			for _, result := range test.Results {
				if result.ID == policyNumber {
					policyDetails.PolicyNumber = result.ID
					policyDetails.Section = testName
					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Description = util.RemoveScoredNotScoredFrom(result.DescriptionZh)
					} else {
						policyDetails.Description = util.RemoveScoredNotScoredFrom(result.DescriptionEn)
					}
					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Details = util.RemoveScoredNotScoredFrom(result.DetailsZh)
					} else {
						policyDetails.Details = util.RemoveScoredNotScoredFrom(result.DetailsEn)
					}
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
