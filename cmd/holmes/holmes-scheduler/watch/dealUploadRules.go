package watch

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	token         = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	UploadThrPath = "/tmp/holmes_rules.thr"
)

type httpRequestInfo struct {
	token                 string
	url                   string
	currentRulesVersion   int
	currentSettingVersion int
	CloseRules            []string
}

type latestVersionResp struct {
	Data struct {
		Item struct {
			Data                 string   `json:"data"`
			Closerules           []string `json:"closedRules"`
			LatestDataVersion    int      `json:"latestDataVersion"`
			LatestSettingVersion int      `json:"latestSettingVersion"`
			DataChanged          bool     `json:"dataChanged"`
			SettingChanged       bool     `json:"settingChanged"`
		} `json:"item"`
	} `json:"data"`
}

func NewHttpRequest(url string) *httpRequestInfo {
	return &httpRequestInfo{token, url, -1, -1, nil}
}

func saveRulesFile(writeBytes []byte, path string) {
	fp, err := os.Create(path)
	if err != nil {
		log.Println(err)
		return
	}
	defer fp.Close()
	_, err = fp.Write(writeBytes)
	if err != nil {
		log.Println(err)
		return
	}
	fp.Sync()
}

func (ri *httpRequestInfo) RulesUpdateLoop(udpateC chan<- int, errorC chan error) {
	log.Println("update loop...")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		httpStreamData, err := ri.getData()
		if err != nil {
			log.Println(err)
			errorC <- err
		}
		if httpStreamData.Data.Item.DataChanged || httpStreamData.Data.Item.SettingChanged {

			if ri.currentRulesVersion != httpStreamData.Data.Item.LatestDataVersion {
				ri.currentRulesVersion = httpStreamData.Data.Item.LatestDataVersion
				tmpBytes, _ := base64.StdEncoding.DecodeString(httpStreamData.Data.Item.Data)
				saveRulesFile(tmpBytes, UploadThrPath)
			}
			if ri.currentSettingVersion != httpStreamData.Data.Item.LatestSettingVersion {
				ri.currentSettingVersion = httpStreamData.Data.Item.LatestSettingVersion
				ri.CloseRules = httpStreamData.Data.Item.Closerules
			}

			udpateC <- 0
		}
		<-t.C
	}
}

func (ri *httpRequestInfo) getData() (latestVersionResp, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s?curDataVersion=%d&curSettingVersion=%d", ri.url, ri.currentRulesVersion, ri.currentSettingVersion)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return latestVersionResp{}, err
	}
	req.Header.Set("X-Tensorsec-cicd-key", token)
	resp, err := client.Do(req)
	if err != nil {
		return latestVersionResp{}, err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	respStru := latestVersionResp{}
	err = json.Unmarshal(body, &respStru)
	if err != nil {
		return latestVersionResp{}, err
	}
	return respStru, nil
}

func saveThrFile(httpData []byte) {

}
