package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

const maxClusterNum = 1000

var (
	instance *ClusterManager
	initErr  error
	rlOnce   sync.Once
)

type ClusterManager struct {
	clientMap map[string]*kubernetes.Clientset
	watcher   *assets.Watcher
	rdb       *rdbtools.GormWrapper
	creator   CreateWatcherFunc

	clusterManagerURL string
	sync.RWMutex
}

type CreateWatcherFunc func(ctx context.Context) (*assets.Watcher, error)

// InitClusterManager 通过 CreateWatcherFunc 解耦cluster manager与service
func InitClusterManager(postgre *rdbtools.GormWrapper, creator CreateWatcherFunc, clusterManagerURL string) (err error) {
	rlOnce.Do(func() {
		for i := 0; i < 3; i++ {
			instance, initErr = newClusterManger(postgre, creator, clusterManagerURL)
			if initErr == nil {
				break
			} else {
				logging.GetLogger().Err(initErr).Msg("create k8s cluster manager error")
			}
		}
	})
	return initErr
}

func GetClusterManager() (*ClusterManager, bool) {
	return instance, instance != nil
}

func newClusterManger(postgre *rdbtools.GormWrapper, creator CreateWatcherFunc, clusterManagerURL string) (*ClusterManager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clsm := &ClusterManager{
		clientMap:         make(map[string]*kubernetes.Clientset),
		watcher:           nil,
		rdb:               postgre,
		clusterManagerURL: clusterManagerURL,
		RWMutex:           sync.RWMutex{},
		creator:           creator,
	}

	err := clsm.loadClientFromDB(ctx)
	if err != nil {
		return nil, err
	}

	// create k8s resource watcher
	if creator != nil {
		watcher, err := creator(ctx)
		if err != nil {
			return nil, err
		}
		clsm.watcher = watcher
	}
	return clsm, nil
}

func (m *ClusterManager) Start(ctx context.Context) error {
	if m.watcher == nil {
		if m.creator != nil {
			watcher, err := m.creator(ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("create cluster Watcher error")
				return err
			}
			m.watcher = watcher
		} else {
			return nil
		}
	}

	copy := make(map[string]*kubernetes.Clientset)
	m.TraverseClient(func(key string, client *kubernetes.Clientset) bool {
		copy[key] = client
		return true
	})
	err := m.watcher.StartsToWatch(ctx, copy)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Watch kube clients error")
		return err
	}

	return nil
}

func (m *ClusterManager) WatchClusterForRemote(ctx context.Context, cluster *model.TensorCluster) error {
	if m.clusterManagerURL == "" {
		return errors.New("no cluster manager url given")
	}

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	clusterBytes, err := json.Marshal(cluster)
	if err != nil {
		return err
	}
	buff := bytes.NewReader(clusterBytes)
	req, err := http.NewRequestWithContext(tctx, http.MethodPost,
		fmt.Sprintf("%s/internal/watch_cluster", m.clusterManagerURL),
		buff,
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("req error")
	}
	return nil
}

// WatchClusterLocally is to watch the target cluster locally
func (m *ClusterManager) WatchClusterLocally(ctx context.Context, cluster *model.TensorCluster) error {
	// watcher is created in console.Run, it may be not ready right now!!
	//return err, cluster manager will try to register repeatedly until watcher is ready
	if m.watcher == nil {
		return errors.New("watcher is not ready")
	}

	// stop watching the existed cluster
	if _, ok := m.GetClient(cluster.Key); ok {
		err := m.UnWatchCluster(ctx, cluster.Key)
		if err != nil {
			return err
		}
	}

	k8sClient, err := CreateK8sClient(cluster.SecretToken, cluster.CertificateAuthData, cluster.APIServerAddr)
	if err != nil {
		return err
	}

	clientMap := map[string]*kubernetes.Clientset{cluster.Key: k8sClient}
	m.addClient(clientMap)
	err = m.watcher.StartsToWatch(ctx, clientMap)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Watch kube clients error")
		// if the watcher start failed, need to delete client from cluster manager
		m.DeleteClient(cluster.Key)
		return err
	}

	return nil
}

func (m *ClusterManager) loadClientFromDB(ctx context.Context) error {
	clientMap := make(map[string]*kubernetes.Clientset)
	clusters, num, err := dal.GetClusters(ctx, m.rdb, 0, maxClusterNum)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get cluster failed")
		return err
	}
	logging.GetLogger().Info().Msgf("cluster number: %d", num)

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
		clientMap[c.Key] = clientSet
	}
	logging.GetLogger().Info().Msgf("get %d k8s client", len(clientMap))
	m.addClient(clientMap)
	return nil
}

func (m *ClusterManager) UnWatchCluster(ctx context.Context, clusterKey string) error {
	if m.watcher == nil {
		return errors.New("watcher does not exist")
	}

	err := m.watcher.StopWatch(ctx, []string{clusterKey})
	if err != nil {
		return err
	}
	m.DeleteClient(clusterKey)
	return nil
}

func (m *ClusterManager) GetClient(clusterKey string) (*kubernetes.Clientset, bool) {
	m.RLock()
	defer m.RUnlock()
	client, ok := m.clientMap[clusterKey]
	return client, ok
}

func (m *ClusterManager) TraverseClient(visitFunc func(key string, client *kubernetes.Clientset) bool) {
	m.RLock()
	m.RUnlock()
	for key, cli := range m.clientMap {
		if toContinue := visitFunc(key, cli); !toContinue {
			break
		}
	}
}

func (m *ClusterManager) AddCluster(ctx context.Context, cluster *model.TensorCluster) error {
	k8sClient, err := CreateK8sClient(cluster.SecretToken, cluster.CertificateAuthData, cluster.APIServerAddr)
	if err != nil {
		return err
	}

	clientMap := map[string]*kubernetes.Clientset{cluster.Key: k8sClient}
	m.addClient(clientMap)
	return nil
}

func (m *ClusterManager) addClient(clientMap map[string]*kubernetes.Clientset) {
	m.Lock()
	defer m.Unlock()
	for key, c := range clientMap {
		m.clientMap[key] = c
	}
}

func (m *ClusterManager) DeleteClient(clusterKey string) {
	m.Lock()
	defer m.Unlock()
	delete(m.clientMap, clusterKey)
}
