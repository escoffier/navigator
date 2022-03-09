package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type TensorCluster struct {
	Key           string             `json:"key"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Status        int32              `json:"status"`
	ConsoleUrl    string             `json:"console_url"`
	K8SRestConfig *InfoForRestConfig `json:"k8s_rest_config"`
}

type ClusterInfoManager struct {
	cinfoVal atomic.Value
	host     string
}

func NewClusterInfoManager(cmHost string) *ClusterInfoManager {
	m := ClusterInfoManager{
		host: cmHost,
	}
	m.load()
	m.asyncLoop()
	return &m
}

func (m *ClusterInfoManager) load() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	var cinfo *TensorCluster

	tctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	err := util.RetryWithBackoff(tctx, func() error {
		var err error
		cinfo, err = getK8sClusterInfo(tctx, m.host)
		return err
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("get cluster error")
	} else {
		m.cinfoVal.Store(*cinfo)
	}
}
func (m *ClusterInfoManager) asyncLoop() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.load()
			}
		}
	}()
}
func (m *ClusterInfoManager) ClusterKey() (string, bool) {
	cobj := m.cinfoVal.Load()
	if cobj == nil {
		return "", false
	}
	cinfo := cobj.(TensorCluster)

	return cinfo.Key, true
}

func getK8sClusterInfo(ctx context.Context, host string) (*TensorCluster, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/internal/cluster", host), nil)
	if err != nil {
		return nil, errors.Errorf("Error reading request, %v", err)
	}

	clusterInfo := TensorCluster{}
	util.HTTPRequest(ctx, http.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("GET method's response code error, code = %v", resp.StatusCode)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Error reading body, %v", err)
		}

		err = json.Unmarshal(body, &clusterInfo)
		if err != nil {
			return errors.Errorf("json unmarshal failed, %v", err)
		}

		if clusterInfo.Status != 0 {
			return errors.Errorf("get cluster failed, status : %v", clusterInfo.Status)
		}
		return nil
	}, retry.Attempts(100))

	return &clusterInfo, nil
}
