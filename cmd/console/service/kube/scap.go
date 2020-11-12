package kube

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/kube"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetKubeHistoryEntries(ctx context.Context, checkMap map[string]*scap.CheckHistoryEntry, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest kube.KubeJobEntry
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
		for _, reportDetails := range complianceTest.Report {
			for _, section := range reportDetails.Tests {
				policiesFailed += section.Fail
				policiesPassed += section.Pass
				policiesInconclusive += section.Info
				policiesInconclusive += section.Warn
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

func GetKubeNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest kube.KubeJobEntry

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

	for _, reportDetails := range complianceTest.Report {
		for _, section := range reportDetails.Tests {
			for _, test := range section.Results {
				complianceMapEntry := &scap.ComplianceMapEntry{}
				complianceMapEntry.PolicyNumber = test.TestNumber
				complianceMapEntry.Section = section.Description
				if lang.Language(ctx) == lang.LanguageZH {
					complianceMapEntry.Section = section.DescriptionZh
				} else {
					complianceMapEntry.Section = section.Description
				}
				if lang.Language(ctx) == lang.LanguageZH {
					complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionZh)
				} else {
					complianceMapEntry.Description = util.RemoveScoredNotScoredFrom(test.TestDescription)
				}
				complianceMapEntry.TestStatus = test.Status
				complianceMap = append(complianceMap, *complianceMapEntry)
			}
		}
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func GetKubeBreakdownEntries(ctx context.Context, checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest kube.KubeJobEntry
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

				testSection := section.Description
				if lang.Language(ctx) == lang.LanguageZH {
					testSection = section.DescriptionZh
				}

				for _, test := range section.Results {

					testDescription := util.RemoveScoredNotScoredFrom(test.TestDescription)
					if lang.Language(ctx) == lang.LanguageZH {
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

func GetKubePolicyDetails(ctx context.Context, policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor) error {
	for cursor.Next(ctx) {
		var complianceTest kube.KubeJobEntry
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
				testSection := section.Description
				if lang.Language(ctx) == lang.LanguageZH {
					testSection = section.DescriptionZh
				}

				for _, test := range section.Results {
					if policyNumber != test.TestNumber {
						continue
					}
					policyDetails.PolicyNumber = test.TestNumber
					policyDetails.Section = testSection
					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Description = util.RemoveScoredNotScoredFrom(test.TestDescriptionZh)
					} else {
						policyDetails.Description = util.RemoveScoredNotScoredFrom(test.TestDescription)
					}
					policyDetails.Audit = test.Audit
					policyDetails.ExpectedResult = test.ExpectedResult
					if lang.Language(ctx) == lang.LanguageZH {
						policyDetails.Remediation = util.RemoveScoredNotScoredFrom(test.RemediationZh)
					} else {
						policyDetails.Remediation = util.RemoveScoredNotScoredFrom(test.Remediation)
					}
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
