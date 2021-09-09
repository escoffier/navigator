package netflow

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int32  `json:"status"`
}

func GetK8sClusterInfo(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

	if clusterInfo.Status != 0 {
		return "", errors.Errorf("get cluster failed, status : %v", clusterInfo.Status)
	}

	return clusterInfo.Key, nil
}

func GetSubmitFunc(url string) SubmitFunc {
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
}
