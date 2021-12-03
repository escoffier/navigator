package image_cache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type ImageCacheClient struct {
	serverAddr string
	//sics       *ScannerImageCacheService
}

func GenerateImageCacheUrl(repoName, tag string) string {
	return fmt.Sprintf("%s:%d/%s:%s", innerRegistryIp, innerRegistryPort, repoName, tag)
}

func NewLocalLayerManageClientT(URI string) (*ImageCacheClient, error) {
	icc := &ImageCacheClient{
		//sics: sics,
	}

	icc.serverAddr = fmt.Sprintf("http://%s:%d%s", innerRegistryIp, innerRegistryPort, URI)
	return icc, nil
}

func NewLocalLayerManageClient() (*ImageCacheClient, error) {
	icc := &ImageCacheClient{
		//sics: sics,
	}

	icc.serverAddr = fmt.Sprintf("http://%s:%d%s", innerRegistryIp, innerRegistryPort, httpRequestPath)
	return icc, nil
}
func (icc *ImageCacheClient) GetManifest(username, password, url, repository, tag string, skipTls bool) (string, error) {
	rq := RequestLayerInfo{
		Username:   username,
		Password:   password,
		Url:        url,
		Repository: repository,
		Tag:        tag,
		SkipTls:    skipTls,
	}
	jsonStr, err := json.Marshal(rq)
	if err != nil {
		return "", err
	}
	log.Info().Msgf("client server addr %s,repo %s,tag %s", icc.serverAddr, rq.Repository, rq.Tag)
	req, err := http.NewRequest("POST", icc.serverAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Error().Msgf("new req err %v", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonStr)))
	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("client do req err %v", err)
		return "", err
	}
	defer rsp.Body.Close()
	log.Info().Msgf("layer manage client request end. status code: %d", rsp.StatusCode)

	if rsp.StatusCode != http.StatusOK {
		return "", err
	}

	body, _ := ioutil.ReadAll(rsp.Body)
	return string(body), nil
}

func (icc *ImageCacheClient) GetLayer(username, password, url, repository, digest string, skipTls bool) (string, string, error) {
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
	log.Debug().Msgf("client server addr %s,repo %s,digest %s", icc.serverAddr, rq.Repository, rq.Digest)

	req, err := http.NewRequest("POST", icc.serverAddr, bytes.NewBuffer(jsonStr))
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
	log.Info().Msgf("layer manage client request end. statuscode: %d", rsp.StatusCode)

	if rsp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("request layer err:%v", rsp.StatusCode)
	}

	body, _ := ioutil.ReadAll(rsp.Body)
	//log.Info().Msgf("layer manage client request end. body: %s", body)

	rspLayerInfo := &ResponseLayerInfo{}
	err = json.Unmarshal(body, &rspLayerInfo)
	if err != nil {

		return "", "", err
	}
	log.Info().Msgf("layer manage client get rsp %+v", rspLayerInfo)
	return rspLayerInfo.LayerUrl, rspLayerInfo.Url, nil
}

func (icc *ImageCacheClient) DeleteLayer(digest string) error {
	req, err := http.NewRequest("DELETE", icc.serverAddr, nil)
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
