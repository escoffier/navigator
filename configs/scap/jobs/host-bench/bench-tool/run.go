package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/pkg/errors"
	"hash/fnv"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Id    string `json:"rule-id"`
	State string `json:"result"`
}

type ScanInfo struct {
	Profile  string   `json:"profile"`
	ScanRets []Result `json:"results"`
}

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int32  `json:"status"`
	ConsoleUrl  string `json:"console_url"`
}

func GetConsoleUrl(url string) (string, error) {
	if url == "" {
		return "", errors.Errorf("cluster url is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	if clusterInfo.Status != 0 || clusterInfo.ConsoleUrl == "" {
		return "", errors.Errorf("get cluster failed, status : %v", clusterInfo.Status)
	}

	return clusterInfo.ConsoleUrl, nil
}

func (s ScanInfo) PutScanResult(url string, scanData []ScanResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := json.Marshal(scanData)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(data))
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

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("PUT method's response code error, code = %v", resp.StatusCode)
	}

	return nil
}

func (s *ScanInfo) ParseScanResult(file string) error {
	out, err := ioutil.ReadFile(file)
	if err != nil {
		return errors.Errorf("read %s file failed, %v", file, err)
	}

	return json.Unmarshal(out, s)
}

func (s ScanInfo) SaveResultToPostgre(pg *PostgreDB) error {
	var ret ScanResult
	ret.TaskID = TaskID
	ret.NodeName = NodeName
	ret.CheckType = "host"
	ret.CreatedAt = time.Now().Unix()
	ret.ClusterKey = ClusterID

	for _, hostRet := range s.ScanRets {
		ret.PolicyID = hostRet.Id
		ret.State = hostRet.State
		ret.ID = GenID(ret.TaskID, ret.CheckType, ret.ClusterKey, ret.PolicyID, ret.NodeName)
		err := pg.SaveScanResult(&ret)
		if err != nil {
			return errors.Errorf("write docker-bench scan result to postgre db failed, %v", err)
		}
	}

	return nil
}

func (s ScanInfo) SendResutlToConsole(url string) error {
	var ret ScanResult
	ret.TaskID = TaskID
	ret.NodeName = NodeName
	ret.CheckType = "host"
	ret.CreatedAt = time.Now().Unix()
	ret.ClusterKey = ClusterID

	scanRets := make([]ScanResult, 0)
	for _, hostRet := range s.ScanRets {
		ret.PolicyID = hostRet.Id
		ret.State = hostRet.State
		ret.ID = GenID(ret.TaskID, ret.CheckType, ret.ClusterKey, ret.PolicyID, ret.NodeName)
		//add result to array
		scanRets = append(scanRets, ret)
	}

	return s.PutScanResult(url, scanRets)
}

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
