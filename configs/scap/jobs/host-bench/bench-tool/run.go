package main

import (
	"encoding/json"
	"github.com/pkg/errors"
	"hash/fnv"
	"io/ioutil"
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

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
