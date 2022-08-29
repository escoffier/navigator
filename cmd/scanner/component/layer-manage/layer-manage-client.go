package layermanage

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
)

type LocalLayerManageClient struct {
	serverAddr string
	llms       *LocalLayerManageSrv
}

func NewLocalLayerManageClient(llms *LocalLayerManageSrv) (*LocalLayerManageClient, error) {
	llmc := &LocalLayerManageClient{
		llms: llms,
	}

	llmc.serverAddr = fmt.Sprintf("http://%s:%d%s", llms.serverIP, llms.port, httpRequestPath)
	return llmc, nil
}

func (llmc *LocalLayerManageClient) GetLayer(ctx context.Context, username, password, url, repository, digest string, skipTLS bool) (string, string, error) {
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
	logging.Get().Debug().Msgf("client server addr %s,repo %s,digest %s", llmc.serverAddr, rq.Repository, rq.Digest)

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodPost, llmc.serverAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		logging.Get().Err(err).Msgf("new req err")
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(jsonStr)))
	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.Get().Err(err).Msgf("client do req err")
		return "", "", err
	}
	defer rsp.Body.Close()
	logging.Get().Info().Msgf("layer manage client request end. statuscode: %d", rsp.StatusCode)

	if rsp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("request layer err:%v", rsp.StatusCode)
	}

	body, _ := ioutil.ReadAll(rsp.Body)
	logging.Get().Info().Msgf("layer manage client request end. body: %s", body)

	rspLayerInfo := &ResponseLayerInfo{}
	err = json.Unmarshal(body, &rspLayerInfo)
	if err != nil {

		return "", "", err
	}
	logging.Get().Info().Msgf("layer manage client get rsp %+v", rspLayerInfo)
	return rspLayerInfo.LayerURL, rspLayerInfo.URL, nil
}

func (llmc *LocalLayerManageClient) DeleteLayer(ctx context.Context, digest string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", llmc.serverAddr, nil)
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
