package netflow

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func GetSubmitFunc(url string) SubmitFunc {
	//
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//http client
	client := &http.Client{Transport: tr}
	//http put
	return func(ctx context.Context, flows []*model.TensorNetworkFlow) error {
		tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		data, err := json.Marshal(flows)
		if err != nil {
			return errors.Errorf("json marshal failed, %v", err)
		}

		req, err := http.NewRequestWithContext(tctx, "PUT", url, bytes.NewBuffer(data))
		if err != nil {
			return errors.Errorf("Error reading request, %v", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			return errors.Errorf("Error reading response, %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("PUT method's response code error, code = %v", resp.StatusCode)
		}

		return nil
	}
}
