package host

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/host"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson/primitive"
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

func GetHostBreakdownEntries(checkMap map[string]*scap.CheckBreakdown, waitingOn *[]string, errorOn *[]string, successOn *[]string, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest host.HostJobEntry
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
			testDescription := test.Title
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

func GetHostNodeCheckDetails(ctx context.Context, col *mongo.Collection, filter primitive.M, checkID string, nodeCheckDetails *scap.NodeCheckDetails) error {
	var complianceTest host.HostJobEntry

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
	if nodeCheckDetails.Status == model.ComplianceCheckStatusInProgress || nodeCheckDetails.Status == model.ComplianceCheckStatusFailed {
		return nil
	}

	complianceMap := make([]scap.ComplianceMapEntry, 0)

	for _, test := range complianceTest.Report.Results {
		complianceMapEntry := &scap.ComplianceMapEntry{}
		complianceMapEntry.PolicyNumber = test.RuleID
		complianceMapEntry.Description = test.Title
		complianceMapEntry.TestStatus = test.Result
		complianceMap = append(complianceMap, *complianceMapEntry)
	}
	nodeCheckDetails.ComplianceMap = complianceMap
	return nil
}

func GetHostPolicyDetails(policyDetails *scap.PolicyDetails, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest host.HostJobEntry
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
				policyDetails.PolicyNumber = test.RuleID
				policyDetails.Description = test.Title
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
