package imagecache

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
)

type Client struct {
	serverAddr string
}

func GenerateImageCacheURL(repoName, tag string) string {
	return fmt.Sprintf("%s:%d/%s:%s", innerRegistryIP, innerRegistryPort, repoName, tag)
}

func NewLocalLayerManageClientT(URI string) (*Client, error) {
	icc := &Client{}

	icc.serverAddr = fmt.Sprintf("http://%s:%d%s", innerRegistryIP, innerRegistryPort, URI)
	return icc, nil
}

func NewLocalLayerManageClient() (*Client, error) {
	icc := &Client{}

	icc.serverAddr = fmt.Sprintf("http://%s:%d%s", innerRegistryIP, innerRegistryPort, httpRequestPath)
	return icc, nil
}
func (icc *Client) GetManifest(username, password, url, repository, tag string, skipTLS bool) (string, error) {
	rq := RequestLayerInfo{
		Username:   username,
		Password:   password,
		URL:        url,
		Repository: repository,
		Tag:        tag,
		SkipTLS:    skipTLS,
	}
	jsonStr, err := json.Marshal(rq)
	if err != nil {
		return "", err
	}
	logging.Get().Info().Msgf("client server addr %s,repo %s,tag %s", icc.serverAddr, rq.Repository, rq.Tag)
	req, err := http.NewRequest("POST", icc.serverAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		logging.Get().Err(err).Msg("new req err")
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonStr)))

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.Get().Err(err).Msg("client do req err")
		return "", err
	}
	defer func() { _ = rsp.Body.Close() }()

	if rsp.StatusCode != http.StatusOK {
		logging.Get().Error().Msgf("manifest manage client request end. status code: %d", rsp.StatusCode)
		return "", err
	}

	body, _ := io.ReadAll(rsp.Body)
	return string(body), nil
}

func (icc *Client) GetLayer(username, password, url, repository, digest string, skipTLS bool) (string, string, error) {
	rq := RequestLayerInfo{
		Username:   username,
		Password:   password,
		URL:        url,
		Repository: repository,
		Digest:     digest,
		SkipTLS:    skipTLS,
	}
	jsonStr, err := json.Marshal(rq)
	if err != nil {

		return "", "", err
	}
	logging.Get().Debug().Msgf("client server addr %s,repo %s,digest %s", icc.serverAddr, rq.Repository, rq.Digest)

	req, err := http.NewRequest("POST", icc.serverAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		logging.Get().Err(err).Msg("new req err")
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonStr)))
	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.Get().Err(err).Msg("client do req err")
		return "", "", err
	}
	defer rsp.Body.Close()
	logging.Get().Debug().Msgf("layer manage client request end. statuscode: %d", rsp.StatusCode)

	if rsp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("request layer err:%v", rsp.StatusCode)
	}

	body, _ := ioutil.ReadAll(rsp.Body)
	// log.Info().Msgf("layer manage client request end. body: %s", body)

	rspLayerInfo := &ResponseLayerInfo{}
	err = json.Unmarshal(body, &rspLayerInfo)
	if err != nil {

		return "", "", err
	}
	logging.Get().Debug().Msgf("layer manage client get rsp %+v", rspLayerInfo)
	return rspLayerInfo.LayerURL, rspLayerInfo.URL, nil
}

func (icc *Client) DeleteLayer(digest string) error {
	req, err := http.NewRequest("DELETE", icc.serverAddr, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("digest", digest)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	rsp, err := httputil.DefaultClient.Do(req)
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
