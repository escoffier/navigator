package docker

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
)

func GetDockerHistoryEntries(checkMap map[string]*scap.CheckHistoryEntry, cursor *mongo.Cursor, ctx context.Context) error {
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

func GetDockerBreakdownEntries(checkMap map[string]*scap.CheckBreakdown, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest docker.DockerJobEntry
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
					checkMap[testNumber] = &scap.CheckBreakdown{
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

func GetDockerPolicyDetails(policyDetails *scap.PolicyDetails, numWaiting *int64, numError *int64, policyNumber string, cursor *mongo.Cursor, ctx context.Context) error {
	for cursor.Next(ctx) {
		var complianceTest docker.DockerJobEntry
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
