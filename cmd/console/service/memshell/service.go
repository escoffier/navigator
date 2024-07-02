package memshell

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Service struct {
	esCli         *pkgelastic.ESClient
	db            *databases.RDBInstance
	clusterMgr    *k8s.ClusterManager
	configMapLock sync.Mutex
}

var (
	instance *Service // *Service
	once     sync.Once
)

func InitService(ecCli *pkgelastic.ESClient, rdb *databases.RDBInstance) (err error) {
	once.Do(func() {
		instance = newService(ecCli, rdb)
		instance.initConfigMap(context.Background())
	})
	return nil
}

func newService(client *pkgelastic.ESClient, rdb *databases.RDBInstance) *Service {

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		logging.GetLogger().Error().Msg("k8s cluster manager not initialized")
		return nil
	}
	return &Service{
		esCli:      client,
		db:         rdb,
		clusterMgr: clusterManager,
	}
}

func GetService() (*Service, bool) {
	return instance, instance != nil

}

func (s *Service) initConfigMap(ctx context.Context) error {
	updateNamespace := os.Getenv("MY_POD_NAMESPACE")
	if updateNamespace == "" {
		updateNamespace = "tensorsec"
	}
	s.clusterMgr.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(updateNamespace).Get(ctx, model.MemshellScanSyncConfigMapName, metav1.GetOptions{})
		if err != nil || currentConfigMap == nil {
			logging.GetLogger().Error().Msgf("failed to get configmap %s in namespace %s", model.MemshellScanSyncConfigMapName, updateNamespace)
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.MemshellScanSyncConfigMapName,
					Namespace: updateNamespace,
					Labels: map[string]string{
						strings.Split(model.MemshellConfigMapLabel, "=")[0]: strings.Split(model.MemshellConfigMapLabel, "=")[1],
					},
				},
				Data: make(map[string]string),
			}
			_, err = client.CoreV1().ConfigMaps(updateNamespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Error().Msgf("failed to create configmap %s in namespace %s", model.MemshellScanSyncConfigMapName, updateNamespace)
				return true // continue to next cluster
			}
		}
		return true
	})
	return nil
}

func (s *Service) ScanResource(ctx context.Context, clusterKey, namespace, kind, resourceName string) error {
	// update configmap
	s.updateConfigmap(ctx, clusterKey, namespace, kind, resourceName)
	return nil

}

func (s *Service) updateConfigmap(ctx context.Context, clusterKey, namespace, kind, resourceName string) error {
	updateNamespace := os.Getenv("MY_POD_NAMESPACE")
	if updateNamespace == "" {
		updateNamespace = "tensorsec"
	}
	s.configMapLock.Lock()
	defer s.configMapLock.Unlock()
	updateMap := make(map[string]string)
	timeStamp := time.Now().Unix()
	resourceUUID := util.GenerateUUID(clusterKey, namespace, kind, resourceName)
	configMapKey := fmt.Sprintf(model.MemshellScanSyncKeyTemplate, resourceUUID)
	updateMap[configMapKey] = fmt.Sprintf(model.MemshellScanSyncValueTemplate, clusterKey, namespace, kind, resourceName, timeStamp)
	s.clusterMgr.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(updateNamespace).Get(ctx, model.MemshellScanSyncConfigMapName, metav1.GetOptions{})
		if err != nil || currentConfigMap == nil {
			logging.GetLogger().Error().Msgf("failed to get configmap %s in namespace %s", model.MemshellScanSyncConfigMapName, updateNamespace)
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.MemshellScanSyncConfigMapName,
					Namespace: updateNamespace,
					Labels: map[string]string{
						strings.Split(model.MemshellConfigMapLabel, "=")[0]: strings.Split(model.MemshellConfigMapLabel, "=")[1],
					},
				},
				Data: updateMap,
			}
			_, err = client.CoreV1().ConfigMaps(updateNamespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Error().Msgf("failed to create configmap %s in namespace %s", model.MemshellScanSyncConfigMapName, updateNamespace)
				return true // continue to next cluster
			}
		} else {
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string)
			}
			// currentConfigMap.Data = make(map[string]string)
			for k, v := range updateMap {
				currentConfigMap.Data[k] = v
			}
			_, err = client.CoreV1().ConfigMaps(updateNamespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.GetLogger().Error().Msgf("failed to update configmap %s in namespace %s", model.MemshellScanSyncConfigMapName, updateNamespace)
				return true
			}
		}
		return true
	})
	return nil
}
