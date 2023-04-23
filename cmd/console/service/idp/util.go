package idp

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"moul.io/http2curl"
)

func request(method string, api string, headers map[string]string, payload io.Reader) (*http.Response, error) {
	logging.Get().Debug().Msgf("send HTTP request: URL=%s method=%s", api, method)
	req, err := http.NewRequest(method, api, payload)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	if curlCmd, curlErr := http2curl.GetCurlCommand(req); curlErr == nil {
		logging.Get().Debug().Msgf("HTTP request as curl: cmd=%s", curlCmd)
	}

	config := &tls.Config{
		//InsecureSkipVerify: true,
	}
	client := getClient(config)
	return client.Do(req)

}

func requestWithData(method string, api string, headers map[string]string, payload io.Reader) ([]byte, error) {
	response, err := request(method, api, headers, payload)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func getClient(config *tls.Config) *http.Client {
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 15,
	}
	return client
}
