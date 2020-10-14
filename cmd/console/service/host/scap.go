package host

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func GetHostHistoryEntries(checkMap map[string]*scap.CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest host.HostJobEntry
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

func GetHostBreakdownEntries(checkMap map[string]*scap.CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest host.HostJobEntry
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
		for _, test := range complianceTest.Report.Results {
			testDescription := test.Description
			testNumber := test.RuleID
			testName := test.Title
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

func GetHostPolicyDetails(policyDetails *scap.PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest host.HostJobEntry
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
