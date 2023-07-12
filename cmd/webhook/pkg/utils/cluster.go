package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/avast/retry-go"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type TensorCluster struct {
	Key           string                 `json:"key"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Status        int32                  `json:"status"`
	K8SRestConfig *k8s.InfoForRestConfig `json:"k8s_rest_config"`
}

type ImageRepoSecret struct {
	User     string
	Password string
}

// DockerConfigJson represents ~/.docker/config.json file info
type DockerConfigJSON struct {
	Auths DockerConfig `json:"auths"`
}

type DockerConfig map[string]DockerConfigEntry

type DockerConfigEntry struct {
	Username string
	Password string
	Email    string
	Auth     string
}

func GetClusterInfo(url string) *TensorCluster {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	var cluster TensorCluster

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logrus.Errorf("get cluster err %v", err)
			return err
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &cluster)
		if err != nil {
			return err
		}
		return nil
	}
	err = util.HTTPRequest(ctx, client, req, respHandler, retry.Attempts(10))
	if err != nil {
		return nil
	}
	return &cluster
}
