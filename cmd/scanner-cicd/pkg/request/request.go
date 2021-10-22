package request

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type Request struct {
	appKey  string
	host    string
	timeout time.Duration
}

func NewRequest(appKey, host string, timeout int) (*Request, error) {
	_, err := url.Parse(host)
	if err != nil {
		return nil, errors.Wrap(err, "parse host failed")
	}
	return &Request{appKey: appKey, host: host, timeout: time.Duration(timeout) * time.Second}, nil
}

func (r *Request) Do(path, method string, body io.Reader, result interface{}) error {
	if result != nil && reflect.TypeOf(result).Kind() != reflect.Ptr {
		return errors.New("result must be a pointer")
	}
	h, err := url.Parse(r.host)
	if err != nil {
		log.Error().Err(err).Msgf("can't parse request host, host: %s", r.host)
		return err
	}

	h1, err := url.Parse(path)
	if err != nil {
		log.Error().Err(err).Msgf("can't parse request path, path: %s", path)
		return err
	}

	log.Info().Msgf("request url:%s\n", h.ResolveReference(h1).String())

	request, err := http.NewRequest(method, h.ResolveReference(h1).String(), body) // 2
	if err != nil {
		log.Error().Err(err).Msgf("new http request err")
		return err
	}
	request.Header.Add("X-Tensorsec-cicd-key", r.appKey)
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: r.timeout}
	resp, err := client.Do(request)
	if err != nil {
		log.Error().Err(err).Msg("request failed")
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		errRes, _ := ioutil.ReadAll(resp.Body)
		log.Warn().Msgf(
			"get response result err,try again.url: %s, status_code: %d, err: %v",
			resp.Request.URL.String(),
			resp.StatusCode,
			string(errRes),
		)

		return fmt.Errorf("response err.%d, status_code: %d, url: %s", resp.StatusCode, resp.StatusCode, resp.Request.URL.String())
	}

	if result != nil {
		err = json.NewDecoder(resp.Body).Decode(result)
		if err != nil {
			log.Error().Err(err).Msg("unmarshal resp Body error")
		}
	}

	log.Info().Msgf("request successful")
	return nil
}
