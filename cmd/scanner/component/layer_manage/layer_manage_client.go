package layerManage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type LocalLayerManageClient struct {
	serverAddr string
	llms       *LocalLayerManageSrv
}

func NewLocalLayerManageClient(llms *LocalLayerManageSrv) (*LocalLayerManageClient, error) {
	llmc := &LocalLayerManageClient{
		llms: llms,
	}

	llmc.serverAddr = fmt.Sprintf("http://%s:%d%s", llms.serverIp, llms.port, httpRequestPath)
	return llmc, nil
}

func (llmc *LocalLayerManageClient) GetLayer(username, password, url, repository, digest string, skipTls bool) (string, string, error) {
	rq := RequestLayerInfo{
		Username:   username,
		Password:   password,
		Url:        url,
		Repository: repository,
		Digest:     digest,
		SkipTls:    skipTls,
	}
	jsonStr, err := json.Marshal(rq)
	if err != nil {

		return "", "", err
	}
	log.Debug().Msgf("client server addr %s,repo %s,digest %s", llmc.serverAddr, rq.Repository,rq.Digest)

	req, err := http.NewRequest("POST", llmc.serverAddr, bytes.NewBuffer(jsonStr))
	if err != nil {

		log.Error().Msgf("new req err %v", err)
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonStr)))
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {

		log.Error().Msgf("client do req err %v", err)
		return "", "", err
	}
	defer rsp.Body.Close()
	log.Info().Msgf("layer manage client request end.%d,body %+v", rsp.StatusCode, rsp.Body)

	if rsp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("request layer err:%v", rsp.StatusCode)
	}

	body, _ := ioutil.ReadAll(rsp.Body)
	rspLayerInfo := &ResponseLayerInfo{}
	err = json.Unmarshal(body, &rspLayerInfo)
	if err != nil {

		return "", "", err
	}
	log.Info().Msgf("layer manage client get rsp %+v", rspLayerInfo)
	return rspLayerInfo.LayerUrl, rspLayerInfo.Url, nil
}

func (llmc *LocalLayerManageClient) DeleteLayer(digest string) error {
	req, err := http.NewRequest("DELETE", llmc.serverAddr, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("digest", digest)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("request layer err:%v", rsp.StatusCode)
	}
	body, _ := ioutil.ReadAll(rsp.Body)
	rspLayerInfo := &ResponseLayerInfo{}
	err = json.Unmarshal(body, &rspLayerInfo)
	if err != nil {
		return err
	}
	if rspLayerInfo.Code != 0 {
		return fmt.Errorf("delete err.(%d)%s", rspLayerInfo.Code, rspLayerInfo.Msg)
	}
	return nil
}
