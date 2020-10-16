package component

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
)

type HarborRESTClient struct {
	address               string // like "https://localhost:30003"
	username              string
	password              string
	skipRegistryTLSVerify bool
}

func NewHarborRESTClient(harborOpts *flag.HarborOpts) *HarborRESTClient {
	return &HarborRESTClient{
		address:               harborOpts.URL,
		username:              harborOpts.Username,
		password:              harborOpts.Password,
		skipRegistryTLSVerify: harborOpts.SkipRegistryTLSVerify,
	}
}

// curl -X POST -u tensorsec:Tensorsec123 -H "Content-type: application/json" -k -i -d '{"schedule": {"type": "Manual"}}'  https://localhost:30003/api/v2.0/system/scanAll/schedule
func (h HarborRESTClient) ScanAll(ctx context.Context) error {
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
		return fmt.Errorf("Failed to marshal scan all request to Harbor: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2.0/system/scanAll/schedule", h.address)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("Failed to prepare scan all request to Harbor: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(h.username, h.password)

	httpClient := http.Client{}
	if h.skipRegistryTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}

	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("Failed to send scan all request to Harbor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		// Harbor's API doc doesn't mention 201 return code, but it is returned
		// to Harbor portal upon pressing "Scan all" button.

		// TODO handle other error codes better
		// 	'200':
		// 	description: Updated scan_all's schedule successfully.
		//   '400':
		// 	description: Invalid schedule type.
		//   '401':
		// 	description: User need to log in first.
		//   '403':
		// 	description: User does not have permission of admin role.
		//   '409':
		// 	description: There is a "scanall" job in progress, so the request cannot be served.
		//   '500':
		// 	description: Unexpected internal errors.
		//   '503':
		// 	description: Harbor is not deployed with scanners.

		return fmt.Errorf("Failed to schedule scan all in Harbor: %w", err)
	}

	return nil
}
