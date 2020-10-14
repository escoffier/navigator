package kube

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/kube"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func GetKubeHistoryEntries(checkMap map[string]*scap.CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
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
		}
	}

	return nil
}

func GetKubeBreakdownEntries(checkMap map[string]*scap.CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest kube.KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return err
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			*numError++
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
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
						checkMap[testNumber] = &scap.CheckBreakdown{
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

func GetKubePolicyDetails(policyDetails *scap.PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest kube.KubeJobEntry
		err := cursor.Decode(&complianceTest)
		if err != nil {
			return nil
		}
		if complianceTest.Status == model.ComplianceCheckStatusFailed {
			*numError++
			continue
		}
		if complianceTest.Status == model.ComplianceCheckStatusInProgress {
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
