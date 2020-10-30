package component

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
)

type HarborRESTClient struct {
	address       string // like "https://localhost:30003"
	username      string
	password      string
	skipTLSVerify bool
}

func NewHarborRESTClient(harborOpts *flag.HarborOpts) *HarborRESTClient {
	return &HarborRESTClient{
		address:       harborOpts.URL,
		username:      harborOpts.Username,
		password:      harborOpts.Password,
		skipTLSVerify: harborOpts.SkipTLSVerify,
	}
}

type harborHTTPSubError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type harborHTTPErrorResp struct {
	Errors []harborHTTPSubError `json:"errors"`
}

func (h HarborRESTClient) ScanAll(ctx context.Context) error {
	// Example curl request:
	// curl -X POST -u tensorsec:Tensorsec123 -H "Content-type: application/json" -k -i -d '{"schedule": {"type": "Manual"}}'  https://localhost:30003/api/v2.0/system/scanAll/schedule

	type ScheduleType struct {
		Type string `json:"type"`
	}

	type ScheduleReq struct {
		Schedule ScheduleType `json:"schedule"`
	}

	// "Type: "Manual"" is not docummented in Harbor's API doc (v2.0), but it is
	// sent by Harbor portal when pressing "Scan all" button.
	payload := ScheduleReq{Schedule: ScheduleType{Type: "Manual"}}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal scan all request to Harbor: %w", err))
	}

	url := fmt.Sprintf("%s/api/v2.0/system/scanAll/schedule", h.address)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare scan all request to Harbor: %w", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	httpClient := http.Client{}
	if h.skipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}

	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send scan all request to Harbor: %w", err))
	}
	defer resp.Body.Close()

	// Harbor's API doc doesn't mention 201 return code, but it is returned
	// to Harbor portal upon pressing "Scan all" button.
	// Just in case, we assume both 200 and 201 status codes are OK.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {

		var errorResp harborHTTPErrorResp
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		if err != nil {
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
		}

		if resp.StatusCode == http.StatusUnauthorized {
			return NewHarborUnauthorizedError(resp.StatusCode, fmt.Errorf("Harbor API returned status Unauthorized: %+v", errorResp))
		} else if resp.StatusCode == http.StatusForbidden {
			return NewHarborForbiddenError(resp.StatusCode, fmt.Errorf("Harbor API returned status Forbidden: %+v", errorResp))
		} else if resp.StatusCode == http.StatusConflict {
			return NewHarborScanAllInProgressError(resp.StatusCode, fmt.Errorf("Harbor scan already in progress: %+v", errorResp))
		} else if resp.StatusCode == http.StatusServiceUnavailable {
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error, potentially no scanners detected: %+v", errorResp))
		} else {
			return NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
		}
	}

	return nil
}

func (h HarborRESTClient) GetHarborScanResultsLink(ctx context.Context, fullRepoName, shaDigest string) (string, error) {

	projectNameRepoName := strings.Split(fullRepoName, "/") // e.g. tensorsecns/tensorsec-console
	if len(projectNameRepoName) != 2 {
		return "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Unexpected number of elements after splitting fullRepoName"))
	}
	projectName := projectNameRepoName[0]
	repoName := projectNameRepoName[1]

	url := fmt.Sprintf("%s/api/v2.0/projects", h.address)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to prepare get projects request to Harbor: %w", err))
	}
	req.SetBasicAuth(h.username, h.password)

	httpClient := http.Client{}
	if h.skipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}

	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return "", NewConnectionError(http.StatusInternalServerError, fmt.Errorf("Failed to send get projects request to Harbor: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp harborHTTPErrorResp
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		if err != nil {
			return "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode error message from Harbor: %w", err))
		}

		return "", NewHarborError(resp.StatusCode, fmt.Errorf("Harbor API returned error: %+v", errorResp))
	}

	// Relevant response bit:
	// [
	//   {
	//     "name": "library",
	//     "project_id": 1,
	//   },
	// ]
	type respItemT struct {
		Name      string `json:"name"`
		ProjectID int    `json:"project_id"`
	}

	var respItems []respItemT
	err = json.NewDecoder(resp.Body).Decode(&respItems)
	if err != nil {
		return "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode message from Harbor: %w", err))
	}

	for _, item := range respItems {
		if item.Name == projectName {
			// https://localhost:30003/harbor/projects/2/repositories/tensorsec-console/artifacts/sha256:ebf90b1ae8550ec6962e070344c857cf4a510477eadaf83988bae043156c4465
			return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s", h.address, item.ProjectID, repoName, shaDigest), nil
		}
	}

	return "", NewAnError(http.StatusInternalServerError, fmt.Errorf("Didn't find such project in Harbor"))
}
