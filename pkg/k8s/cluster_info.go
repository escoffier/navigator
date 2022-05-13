package k8s

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	configmaplister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const clusterInfoKey = "cluster-info"
const clusterInfo = "cluster-info"

type TensorCluster struct {
	Key           string             `json:"key"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Status        int32              `json:"status"`
	ConsoleURL    string             `json:"console_url,omitempty"`
	K8SRestConfig *InfoForRestConfig `json:"k8s_rest_config,omitempty"`
}

type ClusterInfoManager struct {
	cinfoVal      atomic.Value
	host          string
	lister        configmaplister.ConfigMapLister
	hasSynced     func() bool
	workNamespace string
}

func NewClusterInfoManager(cmHost string) *ClusterInfoManager {
	kubeConfig, err := KubeConfig()
	if err != nil {
		return nil
	}
	clientset, err := assets.NewForConfig(kubeConfig)
	if err != nil {
		return nil
	}
	workNamespace := os.Getenv("MY_POD_NAMESPACE")
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 10*time.Hour, informers.WithNamespace(workNamespace))

	m := &ClusterInfoManager{
		host:          cmHost,
		workNamespace: workNamespace,
		lister:        factory.Core().V1().ConfigMaps().Lister(),
		hasSynced:     factory.Core().V1().ConfigMaps().Informer().HasSynced,
	}

	factory.Core().V1().ConfigMaps().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(newObj interface{}) {
			if cm, ok := newObj.(*corev1.ConfigMap); ok {
				if cm.Name == clusterInfo {
					m.updateCluster(cm)
				}
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			if cm, ok := newObj.(*corev1.ConfigMap); ok {
				if cm.Name == clusterInfo {
					m.updateCluster(cm)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
		},
	})

	stopChan := make(chan struct{})
	factory.Start(stopChan)

	if !cache.WaitForNamedCacheSync("cluster-configmap", stopChan, m.hasSynced) {
		logging.Get().Warn().Msg("failed to sync cluster-info from api server")
		return nil
	}

	return m
}

func (m *ClusterInfoManager) updateCluster(configMap *corev1.ConfigMap) {
	data, ok := configMap.BinaryData[clusterInfoKey]
	if ok {
		clusterInfo := &TensorCluster{}
		err := json.Unmarshal(data, clusterInfo)
		if err != nil {
			logging.Get().Err(err).Msg("failed to unmarshal cluster info")
			return
		}
		logging.Get().Debug().Msgf("cluster info: %+v", clusterInfo)
		m.cinfoVal.Store(clusterInfo)
		return
	}
}

func (m *ClusterInfoManager) ClusterKey() (string, bool) {
	cobj := m.cinfoVal.Load()
	if cobj == nil {
		return "", false
	}
	cinfo := cobj.(*TensorCluster)

	return cinfo.Key, true
}

func getK8sClusterInfo(ctx context.Context, host string) (*TensorCluster, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/internal/cluster", host), nil)
	if err != nil {
		return nil, errors.Errorf("Error reading request, %v", err)
	}

	clusterInfo := TensorCluster{}
	err = util.HTTPRequest(ctx, http.DefaultClient, req, func(resp *http.Response, err error) error {
		logging.Get().Debug().Msgf("%s/internal/cluster", host)
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
	}, retry.Attempts(1))
	if err != nil {
		logging.Get().Err(err).Msg("get cluster info err")
		return nil, err
	}

	return &clusterInfo, nil
}
