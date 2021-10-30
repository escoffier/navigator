package imagetrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	"sync"
	"time"
)

var (
	instance *ClusterManager
	rlOnce   sync.Once
)

type ClusterManager struct {
	clientMap        map[string]*kubernetes.Clientset
	stopCh           map[string]chan struct{}
	secretController map[string]Controller
	rdb              *rdbtools.GormWrapper
	sync.RWMutex
}

type ImageRepoSecret struct {
	user     string
	password string
}

// DockerConfigJson represents ~/.docker/config.json file info
type DockerConfigJson struct {
	Auths DockerConfig `json:"auths"`
}

type DockerConfig map[string]DockerConfigEntry

type DockerConfigEntry struct {
	Username string
	Password string
	Email    string
}

func GetClusterManager() (*ClusterManager, bool) {
	return instance, instance != nil
}

func InitClusterManager(postgre *rdbtools.GormWrapper) error {
	rlOnce.Do(func() {
		instance = newClusterManger(postgre)
	})
	return nil
}

func newClusterManger(postgre *rdbtools.GormWrapper) *ClusterManager {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clsm := &ClusterManager{
		clientMap:        make(map[string]*kubernetes.Clientset),
		secretController: make(map[string]Controller),
		rdb:              postgre,
		stopCh:           make(map[string]chan struct{}),
		RWMutex:          sync.RWMutex{},
	}

	err := clsm.loadClientFromDB(ctx)
	if err != nil {
		return nil
	}

	return clsm
}

func (m *ClusterManager) Start() {

	logging.GetLogger().Info().Msg("starting to monitor cluster")
	go wait.Until(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		m.loadClientFromDB(ctx)
	}, time.Second*60, make(chan struct{}))
}

func (m *ClusterManager) Stop() {
	for k := range m.stopCh {
		close(m.stopCh[k])
	}
}

func (m *ClusterManager) loadClientFromDB(ctx context.Context) error {
	m.Lock()
	defer m.Unlock()
	clusters, num, err := dal.GetClusters(ctx, m.rdb, 0, 1000)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get cluster failed")
		return err
	}
	logging.GetLogger().Info().Msgf("cluster number: %d", num)

	for k := range m.clientMap {
		delete(m.clientMap, k)
		close(m.stopCh[k])
		delete(m.secretController, k)
		delete(m.stopCh, k)
	}

	for _, c := range clusters {
		tlsClientConfig := rest.TLSClientConfig{}
		if _, err := certutil.NewPoolFromBytes([]byte(c.CertificateAuthData)); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("load root CA config for cluster %s err", c.Key)
			continue
		} else {
			tlsClientConfig.CAData = []byte(c.CertificateAuthData)
		}
		clientSet, err := kubernetes.NewForConfig(&rest.Config{
			Host:            c.APIServerAddr,
			TLSClientConfig: tlsClientConfig,
			BearerToken:     c.SecretToken,
		})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("create client for cluster %s err", c.Key)
			continue
		}
		m.clientMap[c.Key] = clientSet
		m.stopCh[c.Key] = make(chan struct{})
		logging.GetLogger().Info().Msgf("cluster %s client", c.Key)
		m.secretController[c.Key] = NewController(clientSet, c.Key)
		go m.secretController[c.Key].Start(m.stopCh[c.Key])
	}
	logging.GetLogger().Info().Msgf("get %d k8s client", len(m.clientMap))
	return nil
}

func (m *ClusterManager) GetSecret(clusterName, namespace, name string) (*DockerConfigJson, error) {
	m.RLock()
	defer m.RUnlock()
	clusterKey, err := m.getClusterKeybyName(clusterName)
	if err != nil {
		return nil, err
	}
	logging.GetLogger().Info().Msgf("get secret: %s:%s:%s:%s", clusterName, clusterKey, namespace, name)

	controller, ok := m.secretController[clusterKey]
	if !ok {
		return nil, fmt.Errorf("not found cluster %v", clusterKey)
	}
	secret, err := controller.GetSecret(namespace, name)
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		return nil, errors.New("invalid secret")
	}

	var dockerConfig DockerConfigJson
	err = json.Unmarshal(data, &dockerConfig)
	if err != nil {
		return nil, err
	}
	logging.GetLogger().Info().Msgf("%+v", dockerConfig)
	return &dockerConfig, nil
}

func (m *ClusterManager) getClusterKeybyName(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
	defer cancel()

	cluster := model.TensorCluster{}
	err := m.rdb.Get().WithContext(ctx).Where("name = ?", name).First(&cluster).Error
	return cluster.Key, err
}

func (m *ClusterManager) syncK8sClient(clusters []*model.TensorCluster) {
	for k := range m.clientMap {
		found := false
		for _, cluster := range clusters {
			if cluster.Key == k {
				found = true
			}
		}
		if !found {
			delete(m.clientMap, k)
		}
	}
}
