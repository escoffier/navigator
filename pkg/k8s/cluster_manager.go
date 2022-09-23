package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	v1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/cluster/v1"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	clusterV1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/cluster/v1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
)

var (
	instance *ClusterManager
	initErr  error
	rlOnce   sync.Once
)

type ClientConfig struct {
	BearToken string `json:"bearToken,omitempty"`
	// CertData holds PEM-encoded bytes.
	CertData []byte `json:"certData,omitempty"`
	// KeyData holds PEM-encoded bytes.
	KeyData []byte `json:"keyData,omitempty"`
	// CAData holds PEM-encoded bytes.
	CAData []byte `json:"cAData,omitempty"`
}

type ClusterManager struct {
	clientMap         map[string]*assets.Clientset
	HostClient        *assets.Clientset
	watcher           *assets.Watcher
	informerFactory   externalversions.SharedInformerFactory
	stopChan          chan struct{}
	queue             workqueue.RateLimitingInterface
	Lister            v1.ManagedClusterLister
	clusterManagerURL string
	sync.RWMutex
}

func (m *ClusterManager) InformerFactory() externalversions.SharedInformerFactory {
	return m.informerFactory
}

type CreateWatcherFunc func(ctx context.Context) (*assets.Watcher, error)

// InitClusterManager create cluster manager
func InitClusterManager(hostClient *assets.Clientset, factory externalversions.SharedInformerFactory, clusterManagerURL string) (err error) {
	rlOnce.Do(func() {
		for i := 0; i < 3; i++ {
			instance, initErr = newClusterManger(hostClient, factory, clusterManagerURL)
			if initErr == nil {
				break
			} else {
				logging.Get().Err(initErr).Msg("create k8s cluster manager error")
			}
		}
	})
	return initErr
}

func GetClusterManager() (*ClusterManager, bool) {
	return instance, instance != nil
}

func newClusterManger(hostClient *assets.Clientset, factory externalversions.SharedInformerFactory, clusterManagerURL string) (*ClusterManager, error) {
	clsm := &ClusterManager{
		clientMap:         make(map[string]*assets.Clientset),
		watcher:           nil,
		HostClient:        hostClient,
		clusterManagerURL: clusterManagerURL,
		RWMutex:           sync.RWMutex{},
		informerFactory:   factory,
		stopChan:          make(chan struct{}),
		queue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster"),
	}

	return clsm, nil
}

func (m *ClusterManager) Start() {
	go m.watchClusterFromKube(m.informerFactory.Cluster().V1().ManagedClusters().Informer())
}

// WatchClusterResources is to watch the target cluster locally
func (m *ClusterManager) WatchClusterResources(ctx context.Context, cluster *model.TensorCluster) error {
	// stop watching the existed cluster
	if _, ok := m.GetClient(cluster.Key); ok {
		err := m.UnWatchCluster(ctx, cluster.Key)
		if err != nil {
			return err
		}
	}

	logging.Get().Debug().Msgf("creating cluster client: %s-%s", cluster.Name, cluster.APIServerAddr)
	clientset, err := CreateClientset(cluster)
	if err != nil {
		return err
	}

	if cluster.ClusterType == model.HostCluster {
		m.HostClient = clientset
	}
	clientMap := map[string]*assets.Clientset{cluster.Key: clientset}
	m.addClient(clientMap)

	return nil
}

func (m *ClusterManager) UnWatchCluster(ctx context.Context, clusterKey string) error {
	logging.Get().Info().Msgf("unwatch cluster %s", clusterKey)
	m.DeleteClient(clusterKey)
	return nil
}

func (m *ClusterManager) GetClient(clusterKey string) (*assets.Clientset, bool) {
	m.RLock()
	defer m.RUnlock()
	client, ok := m.clientMap[clusterKey]
	return client, ok
}

func (m *ClusterManager) TraverseClient(visitFunc func(key string, client *assets.Clientset) bool) {
	m.RLock()
	defer m.RUnlock()
	for key, cli := range m.clientMap {
		if toContinue := visitFunc(key, cli); !toContinue {
			break
		}
	}
}

func (m *ClusterManager) AddCluster(_ context.Context, cluster *model.TensorCluster) error {
	clientset, err := CreateClientset(cluster)
	if err != nil {
		return err
	}

	clientMap := map[string]*assets.Clientset{cluster.Key: clientset}

	if cluster.ClusterType == model.HostCluster {
		m.HostClient = clientset
	}
	m.addClient(clientMap)
	return nil
}

func (m *ClusterManager) addClient(clientMap map[string]*assets.Clientset) {
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

func (m *ClusterManager) GetHostClient() *assets.Clientset {
	return m.HostClient
}

func (m *ClusterManager) SetHostClient(clientset *assets.Clientset) {
	m.HostClient = clientset
}

func (m *ClusterManager) AddManagedClusterToKube(ctx context.Context, cluster *model.TensorCluster) error {
	if m.HostClient == nil {
		return errors.New("invalid host cluster client")
	}

	clientConfig := &ClientConfig{
		BearToken: cluster.SecretToken,
		CertData:  []byte(cluster.ClientCertData),
		KeyData:   []byte(cluster.ClientKeyData),
		CAData:    []byte(cluster.CertificateAuthData),
	}
	data, err := json.Marshal(clientConfig)
	if err != nil {
		return err
	}
	cls := &clusterV1.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{Name: cluster.Key},
		Spec: clusterV1.ManagedClusterSpec{
			ClusterKey:      cluster.Key,
			ClusterName:     cluster.Name,
			ClientConfig:    data,
			APIServerAddr:   cluster.APIServerAddr,
			WorkerNamespace: cluster.WorkerNamespace,
			ClusterType:     string(cluster.ClusterType),
			Description:     cluster.Description,
		},
	}
	_, err = m.HostClient.TensorClientset.ClusterV1().ManagedClusters().Create(ctx, cls, metav1.CreateOptions{})
	return err
}

func (m *ClusterManager) watchClusterFromKube(informer cache.SharedIndexInformer) {
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cluster, ok := obj.(*clusterV1.ManagedCluster)
			if !ok {
				logging.Get().Err(fmt.Errorf(""))
				return
			}
			m.queue.Add(cluster.Name)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldCluster, ok := oldObj.(*clusterV1.ManagedCluster)
			if !ok {
				logging.Get().Err(fmt.Errorf(""))
				return
			}
			newCluster, ok := newObj.(*clusterV1.ManagedCluster)
			if !ok {
				logging.Get().Err(fmt.Errorf(""))
				return
			}
			if !bytes.Equal(oldCluster.Spec.ClientConfig, newCluster.Spec.ClientConfig) ||
				oldCluster.Spec.APIServerAddr != newCluster.Spec.APIServerAddr {
				m.queue.Add(newCluster.Name)
			}
		},
		DeleteFunc: func(obj interface{}) {
			cluster, ok := obj.(*clusterV1.ManagedCluster)
			if !ok {
				logging.Get().Err(fmt.Errorf(""))
				return
			}
			m.queue.Add(cluster.Name)
		},
	})

	m.Lister = m.informerFactory.Cluster().V1().ManagedClusters().Lister()
	logging.Get().Info().Msg("starting watch cluster")
	if !cache.WaitForCacheSync(m.stopChan, informer.HasSynced) {
		logging.Get().Error().Msg("failed to sync managed-cluster")
		return
	}

	go wait.Until(func() {
		for m.processNextCluster() {
		}
	}, time.Second, m.stopChan)
	return
}

func (m *ClusterManager) processNextCluster() bool {
	key, quit := m.queue.Get()
	if quit {
		return false
	}
	defer m.queue.Done(key)

	err := m.syncCluster(key.(string))

	m.handleErr(err, key)

	return true
}

func (m *ClusterManager) syncCluster(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logging.Get().Info().Msgf("syncing cluster %s", name)
	managedCluster, err := m.Lister.Get(name)
	if err != nil {
		if k8serr.IsNotFound(err) {
			logging.Get().Info().Msgf("cluster: %s does not exist", name)
			err = m.UnWatchCluster(ctx, name)
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}
	tensorCluster, err := ClusterFromCrdToModel(managedCluster)
	if err != nil {
		return err
	}
	err = m.WatchClusterResources(ctx, tensorCluster)

	return err
}

func (m *ClusterManager) handleErr(err error, key interface{}) {
	if err == nil {
		m.queue.Forget(key)
		return
	}
	if m.queue.NumRequeues(key) < 5 {
		logging.Get().Info().Msgf("Error syncing cluster %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		m.queue.AddRateLimited(key)
		return
	}
	m.queue.Forget(key)
	logging.Get().Warn().Msgf("Dropping service %q out of the queue: %v", key, err)
}

func ClusterFromCrdToModel(cluster *clusterV1.ManagedCluster) (*model.TensorCluster, error) {
	var clientConfig ClientConfig
	err := json.Unmarshal(cluster.Spec.ClientConfig, &clientConfig)
	if err != nil {
		logging.Get().Err(err).Msgf("parse cluster client config %s", cluster.Spec.ClusterName)
		return nil, err
	}
	return &model.TensorCluster{
		Key:                 cluster.Spec.ClusterKey,
		Name:                cluster.Spec.ClusterName,
		Description:         cluster.Spec.Description,
		ClusterType:         model.ClusterType(cluster.Spec.ClusterType),
		APIServerAddr:       cluster.Spec.APIServerAddr,
		CertificateAuthData: string(clientConfig.CAData),
		SecretToken:         clientConfig.BearToken,
		ClientCertData:      string(clientConfig.CertData),
		ClientKeyData:       string(clientConfig.KeyData),
		WorkerNamespace:     cluster.Spec.WorkerNamespace,
	}, nil
}

// UpdateCluster Update or Add managed cluster CRD
func (m *ClusterManager) UpdateCluster(ctx context.Context, cluster *model.TensorCluster) error {
	managedCluster, err := m.HostClient.TensorClientset.ClusterV1().ManagedClusters().Get(ctx, cluster.Key, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logging.Get().Info().Msgf("add managed cluster %s", cluster.Key)
			err = m.AddManagedClusterToKube(ctx, cluster)
		}
		return err
	}
	oldCluster, err := ClusterFromCrdToModel(managedCluster)
	if err != nil {
		return err
	}
	if IsClusterChanged(oldCluster, cluster) {
		clientConfig := &ClientConfig{
			BearToken: cluster.SecretToken,
			CertData:  []byte(cluster.ClientCertData),
			KeyData:   []byte(cluster.ClientKeyData),
			CAData:    []byte(cluster.CertificateAuthData),
		}
		var data []byte
		data, err = json.Marshal(clientConfig)
		if err != nil {
			return err
		}

		var clusterName string
		if cluster.Name != "" {
			clusterName = cluster.Name
		} else {
			clusterName = oldCluster.Name
		}
		patchData := map[string]interface{}{
			"spec": map[string]interface{}{
				"clientConfig":    data,
				"clusterName":     clusterName,
				"clusterKey":      cluster.Key,
				"apiServerAddr":   cluster.APIServerAddr,
				"workerNamespace": cluster.WorkerNamespace,
				"clusterType":     cluster.ClusterType,
				"description":     cluster.Description,
			},
		}
		var patchBytes []byte
		patchBytes, err = json.Marshal(patchData)
		if err != nil {
			return err
		}
		logging.Get().Info().Msgf("patch managed cluster %s", cluster.Key)
		_, err = m.HostClient.TensorClientset.ClusterV1().ManagedClusters().Patch(ctx, cluster.Key, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	}
	return err
}

func (m *ClusterManager) UpdateClusterName(ctx context.Context, clusterKey, name, description string) error {
	patchData := map[string]interface{}{
		"spec": map[string]interface{}{
			"clusterName": name,
			"description": description,
		},
	}
	var patchBytes []byte
	var err error
	patchBytes, err = json.Marshal(patchData)
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("patch managed cluster %s", clusterKey)
	_, err = m.HostClient.TensorClientset.ClusterV1().ManagedClusters().Patch(ctx, clusterKey, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (m *ClusterManager) DeleteCluster(ctx context.Context, clusterKey string) error {
	err := m.HostClient.TensorClientset.ClusterV1().ManagedClusters().Delete(ctx, clusterKey, metav1.DeleteOptions{})
	if err != nil {
		if k8serr.IsNotFound(err) {
			return nil
		}
	}
	return err
}

func IsClusterChanged(oldCluster *model.TensorCluster, newCluster *model.TensorCluster) bool {
	if oldCluster.SecretToken != newCluster.SecretToken ||
		oldCluster.CertificateAuthData != newCluster.CertificateAuthData ||
		oldCluster.ClientCertData != newCluster.ClientCertData ||
		oldCluster.ClientKeyData != newCluster.ClientKeyData ||
		oldCluster.APIServerAddr != newCluster.APIServerAddr ||
		oldCluster.ClusterType != newCluster.ClusterType ||
		oldCluster.WorkerNamespace != newCluster.WorkerNamespace ||
		oldCluster.Name != newCluster.Name ||
		oldCluster.APIServerAddr != newCluster.APIServerAddr {
		return true
	}
	return false
}

func (m *ClusterManager) GetClusterByKey(key string) (*clusterV1.ManagedCluster, error) {
	cluster, err := m.Lister.Get(key)
	if err != nil {
		return nil, err
	}
	return cluster, nil
}

func (m *ClusterManager) GetClusterName(key string) (string, error) {
	cluster, err := m.Lister.Get(key)
	if err != nil {
		return "", err
	}
	return cluster.Spec.ClusterName, nil
}
