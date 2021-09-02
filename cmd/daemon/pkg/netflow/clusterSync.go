package netflow

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"io/ioutil"
	"net/http"
)

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int32  `json:"status"`
}

func PostK8sResData(url string, res *daemon.K8sNetResMap) error {
	data, err := json.Marshal(res)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return errors.Errorf("Error reading request, %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Errorf("Error reading response, %v", err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Errorf("Error reading body, %v ", err)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("PUT method's response code error, code = %v", resp.StatusCode)
	}

	return nil
}

func UpdateK8sResData(url string, nowTime int64, state int32) error {
	value := map[string]int64{
		"time":   nowTime,
		"status": int64(state),
	}

	data, err := json.Marshal(value)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return errors.Errorf("Error reading request, %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Errorf("Error reading response, %v", err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Errorf("Error reading body, %v ", err)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("POST method's response code error, code = %v", resp.StatusCode)
	}

	return nil
}

func GetK8sClusterInfo(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errors.Errorf("Error reading request, %v", err)
	}

	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Errorf("Error reading response, %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("Error reading body, %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("GET method's response code error, code = %v", resp.StatusCode)
	}

	clusterInfo := TensorCluster{}
	err = json.Unmarshal(body, &clusterInfo)
	if err != nil {
		return "", errors.Errorf("json unmarshal failed, %v", err)
	}

	if clusterInfo.Status != 0 {
		return "", errors.Errorf("get cluster failed, status : %v", clusterInfo.Status)
	}

	return clusterInfo.Key, nil
}
