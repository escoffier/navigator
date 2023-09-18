package configs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	dataCreateTimeout = time.Second * 4
)

func (ms MicroSegOperator) getURL(path string, a ...interface{}) string {
	microsegURL := os.Getenv("MICROSEG_URL")
	switch path {
	case "createTenants":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/tenants", a...)
	case "deleteTenants":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/tenants/%s", a...)
	case "updateTenants":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/tenants/%s", a...)
	case "enablingTenantPolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/tenants/%s/policy/enabling", a...)
	case "deleteLogicClusters":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/logicclusters/%s", a...)
	case "createLogicClusters":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/logicclusters", a...)
	case "createNsgrps":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/nsgrps", a...)
	case "updateNsgrps":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/nsgrps/%s", a...)
	case "deleteNsgrps":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/nsgrps/%s", a...)
	case "enablingNsgrpPolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/nsgrps/%s/policy/enabling", a...)
	case "deleteSegments":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/segments/%s", a...)
	case "createSegments":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/segments", a...)
	case "updateSegments":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/segments/%s", a...)
	case "createSegmentPolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/segments/%s/policy", a...)
	case "enableSegmentPolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/segments/%s/policy/enabling", a...)
	case "getResourcePolicyEnabling":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/kinds/%s/resources/%s/policy/enabling", a...)
	case "createResourcePolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/kinds/%s/resources/%s/policy", a...)
	case "enableResourcePolicy":
		return microsegURL + fmt.Sprintf("/api/v2/microseg/clusters/%s/namespaces/%s/kinds/%s/resources/%s/policy/enabling", a...)
	}

	return ""
}

// microseg_tenants
func (ms MicroSegOperator) createMicrosegTenants(createReq CreateTenantRequest, clusterKey string) (SingleTenant, error) {
	ctx := context.TODO()

	var newTenantData SingleTenant

	url := ms.getURL("createTenants", clusterKey)

	// get req data
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return newTenantData, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return newTenantData, err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return newTenantData, err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newTenantData, err
	}

	type Response struct {
		APIVersion string       `json:"apiVersion"`
		Data       SingleTenant `json:"data"`
		Error      RespErr      `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return newTenantData, err
	}

	if resp.StatusCode != 200 {
		return newTenantData, fmt.Errorf(result.Error.Message)
	}

	return result.Data, nil
}

func (ms *MicroSegOperator) UpdateMicrosegTenant(updateRq UpdateTenantRequest, clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("updateTenants", clusterKey, strconv.FormatInt(id, 10))
	jsonReqData, err := json.Marshal(updateRq)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("marshal err")
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		logging.Get().Error().Err(err).Msgf("req err")
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("resp err")
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	type Response struct {
		APIVersion string       `json:"apiVersion"`
		Data       SingleTenant `json:"data"`
		Error      RespErr      `json:"error"`
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil

}

func (ms *MicroSegOperator) DeleteMicrosegTenant(clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("deleteTenants", clusterKey, strconv.FormatInt(id, 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

func (ms *MicroSegOperator) EnablingTenantPolicy(enableConfig PolicyEnabling, clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("enablingTenantPolicy", clusterKey, strconv.FormatInt(id, 10))

	jsonReqData, err := json.Marshal(enableConfig)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

// microseg_logic_clusters
func (ms *MicroSegOperator) DeleteMicrosegLogicCluster(clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("deleteLogicClusters", clusterKey, strconv.FormatInt(id, 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)

	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

func (ms *MicroSegOperator) createMicrosegLogicCluster(createReq CreateLogicClusterRequest, clusterKey string) (SingleLogicCluster, error) {
	ctx := context.TODO()

	var newLogicCluster SingleLogicCluster

	url := ms.getURL("createLogicClusters", clusterKey)
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return newLogicCluster, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return newLogicCluster, err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return newLogicCluster, err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newLogicCluster, err
	}

	type Response struct {
		APIVersion string             `json:"apiVersion"`
		Data       SingleLogicCluster `json:"data"`
		Error      RespErr            `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return newLogicCluster, err
	}

	if resp.StatusCode != 200 {
		return newLogicCluster, fmt.Errorf(result.Error.Message)
	}

	return result.Data, nil

}

// ivan_microseg_nsgrps
func (ms *MicroSegOperator) createMicrosegNsgrp(createReq CreateNsgrpRequest, clusterKey string) (SingleNsgrp, error) {
	ctx := context.TODO()

	var newLogicCluster SingleNsgrp

	url := ms.getURL("createNsgrps", clusterKey)
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return newLogicCluster, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return newLogicCluster, err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return newLogicCluster, err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newLogicCluster, err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       SingleNsgrp `json:"data"`
		Error      RespErr     `json:"error"`
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return newLogicCluster, err
	}

	if resp.StatusCode != 200 {
		return newLogicCluster, fmt.Errorf(result.Error.Message)
	}

	return result.Data, nil
}

func (ms *MicroSegOperator) UpdateMicrosegNsgrp(updateRq UpdateNsgrpRequest, clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("updateNsgrps", clusterKey, strconv.FormatInt(id, 10))

	jsonReqData, err := json.Marshal(updateRq)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("marshal err")
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		logging.Get().Error().Err(err).Msgf("req err")
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("resp err")
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       SingleNsgrp `json:"data"`
		Error      RespErr     `json:"error"`
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

func (ms *MicroSegOperator) DeleteMicrosegNsgrp(clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("deleteNsgrps", clusterKey, strconv.FormatInt(id, 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

func (ms *MicroSegOperator) EnablingNsgrpPolicy(enableConfig PolicyEnabling, clusterKey string, id int64) error {
	ctx := context.TODO()

	url := ms.getURL("enablingNsgrpPolicy", clusterKey, strconv.FormatInt(id, 10))

	jsonReqData, err := json.Marshal(enableConfig)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

// ivan_microseg_segments
func (ms *MicroSegOperator) DeleteMicrosegSegment(clusterKey, namespace, segmentName string) error {
	ctx := context.TODO()

	url := ms.getURL("deleteSegments", clusterKey, namespace, segmentName)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)

	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	type Response struct {
		APIVersion string  `json:"apiVersion"`
		Data       string  `json:"data"`
		Error      RespErr `json:"error"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	return nil
}

// createMicrosegResourcePolicy
func (ms MicroSegOperator) createMicrosegSegment(createReq CreateSegmentRequest, clusterKey, namespace string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("createSegments", clusterKey, namespace)

	// get req data
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return nil
}

func (ms MicroSegOperator) updateMicrosegSegment(updateReq []K8sResource, clusterKey, namespace, segmentName string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("updateSegments", clusterKey, namespace, segmentName)

	// get req data
	request := make(map[string][]K8sResource)
	request["resources"] = updateReq
	jsonReqData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}

	return nil
}

type getMicrosegResourcePolicyEnablingResponseDataItem struct {
	Enable   int `json:"enable"`
	Revision int `json:"revision"`
}

type getMicrosegResourcePolicyEnablingResponseData struct {
	Item getMicrosegResourcePolicyEnablingResponseDataItem `json:"item"`
}

type getMicrosegResourcePolicyEnablingResponse struct {
	APIVersion string                                        `json:"apiVersion"`
	Data       getMicrosegResourcePolicyEnablingResponseData `json:"data"`
	Error      RespErr                                       `json:"error"`
}

// getMicrosegResourcePolicyEnabling
func (ms MicroSegOperator) getMicrosegResourcePolicyEnabling(clusterKey, namespace, kind, resource string) (*getMicrosegResourcePolicyEnablingResponse, error) {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("getResourcePolicyEnabling", clusterKey, namespace, kind, resource)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := getMicrosegResourcePolicyEnablingResponse{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return nil, fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return &result, nil
}

// createMicrosegResourcePolicy
func (ms MicroSegOperator) createMicrosegResourcePolicy(createReq CreatePolicyRequest, clusterKey, namespace, kind, resource string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("createResourcePolicy", clusterKey, namespace, kind, resource)

	// get req data
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return nil
}

// createMicrosegSegmentPolicy
func (ms MicroSegOperator) createMicrosegSegmentPolicy(createReq CreatePolicyRequest, clusterKey, namespace, segment string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("createSegmentPolicy", clusterKey, namespace, segment)

	// get req data
	jsonReqData, err := json.Marshal(createReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return nil
}

// enableMicrosegSegmentPolicy
func (ms MicroSegOperator) enableMicrosegSegmentPolicy(enableReq PolicyEnabling, clusterKey, namespace, segment string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("enableSegmentPolicy", clusterKey, namespace, segment)

	// get req data
	jsonReqData, err := json.Marshal(enableReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}
	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return nil
}

// enableMicrosegResourcePolicy
func (ms MicroSegOperator) enableMicrosegResourcePolicy(enableReq PolicyEnabling, clusterKey, namespace, kind, resource string) error {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, dataCreateTimeout)
	defer cancel()

	url := ms.getURL("enableResourcePolicy", clusterKey, namespace, kind, resource)

	// get req data
	jsonReqData, err := json.Marshal(enableReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonReqData))
	if err != nil {
		return err
	}

	req.Header.Set("loginUser", ms.GetAperator())

	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer util.CloseBodyWithLog(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	type Response struct {
		APIVersion string      `json:"apiVersion"`
		Data       interface{} `json:"data"`
		Error      RespErr     `json:"error"`
	}
	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf(result.Error.Message)
	}

	if result.Error.Message != "" || result.Error.Code != 0 {
		return fmt.Errorf("microseg error %s, code %d", result.Error.Message, result.Error.Code)
	}
	return nil
}
