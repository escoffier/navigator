package image

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func getImageSHAFromContainer(container corev1.ContainerStatus) string {
	// imageID: docker-pullable://192.168.1.203:5000/tensorsec-console@sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	shaDigestAndPullInfo := strings.Split(container.ImageID, "@")
	return shaDigestAndPullInfo[len(shaDigestAndPullInfo)-1]
}

type OnlineMonitor struct {
	rdb        *databases.RDBInstance
	scannerURL string
}

func NewOnlineMonitor(rdb *databases.RDBInstance, scannerURL string) *OnlineMonitor {
	return &OnlineMonitor{
		rdb:        rdb,
		scannerURL: scannerURL,
	}
}
func (s *OnlineMonitor) BeforeWatchNewCluster(ctx context.Context, clusterKey string, resyncDur time.Duration) assets.ClusterCallback {
	res := &OnlineMonitorCB{
		parent:     s,
		exitMap:    make(map[string]int64, 100),
		lock:       sync.RWMutex{},
		clusterKey: clusterKey,
		inputChan:  make(chan model.RejectOnlineMonitorImage, 50),
	}
	res.asyncLoop()
	return res
}

func (s *OnlineMonitor) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
	}
}

func (s *OnlineMonitor) Name() string {
	return "images_online_monitor"
}

type OnlineMonitorCB struct {
	parent     *OnlineMonitor
	exitMap    map[string]int64
	lock       sync.RWMutex
	clusterKey string
	inputChan  chan model.RejectOnlineMonitorImage
}

func (s *OnlineMonitorCB) checkMap(uid string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	_, ok := s.exitMap[uid]
	return ok
}
func (s *OnlineMonitorCB) addMap(uid string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.exitMap[uid] = time.Now().Unix()
}

// OnTensorPod 对于新增的pod,我们查一下有那些镜像没有被扫描，或扫描失败
func (s *OnlineMonitorCB) OnTensorPod(pod *assets.TensorPod, action assets.AssetsAction) error {
	if pod == nil {
		return nil
	}
	ignoredNameSpaces := []string{"kube-system", "tensorsec"}
	for _, ns := range ignoredNameSpaces {
		if pod.Namespace == ns {
			logging.GetLogger().Debug().Msg("在ignoredNameSpaces中,PodName:" + pod.Name)
			return nil
		}
	}

	if pod.Status.Phase != corev1.PodRunning {
		logging.GetLogger().Debug().Msgf("K8sOnlineMonitor newPod.Status.Phase:%s", pod.Status.Phase)
		return nil
	}
	// 使用一个全局的map做验证
	if s.checkMap(string(pod.UID)) {
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor updated ,podUUID %s", pod.UID)
		return nil
	}

	if action != assets.ActionDelete {
		notify := model.NotifyContext{
			PodUID:    string(pod.UID),
			PodName:   pod.Name,
			Namespace: pod.Namespace,
			Cluster:   pod.Cluster,
		}
		s.sendInput(pod.Pod, notify)
	}
	return nil
}

func (s *OnlineMonitorCB) cleanUpMap(now time.Time) {
	s.lock.RLock()
	toDelete := make([]string, 0, 2)
	for key, timestamp := range s.exitMap {
		if now.Unix()-timestamp > 24*3600 {
			toDelete = append(toDelete, key)
		}
	}
	s.lock.RUnlock()
	if len(toDelete) > 0 {
		s.lock.Lock()
		defer s.lock.Unlock()

		for _, key := range toDelete {
			delete(s.exitMap, key)
		}

		// to prevent the memory leak of go map
		if rand.Float64() < 0.1 { //nolint
			newMap := make(map[string]int64, len(s.exitMap))
			for key, val := range s.exitMap {
				newMap[key] = val
			}
			s.exitMap = newMap
		}
	}
}
func (s *OnlineMonitorCB) asyncLoop() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		buffer := make(map[string]model.RejectOnlineMonitorImage, 50)
		for {
			select {
			case evt := <-s.inputChan:
				buffer[evt.NotifyContext.PodUID] = evt
			case now := <-ticker.C:
				err := s.batchDetectImages(buffer)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("batch update detectImages err. data: %v", buffer)
				}

				for _, rej := range buffer {
					s.addMap(rej.NotifyContext.PodUID)
				}
				buffer = make(map[string]model.RejectOnlineMonitorImage, len(buffer))

				s.cleanUpMap(now)
			}
		}
	}()
}

func (s *OnlineMonitorCB) OnReplicaSetEvent(newRs, oldRs *appsv1.ReplicaSet, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	// monitor resource creation and chages including replicasets, statefulsets, daemonsets, cronjobs, jobs, deployments, replicationcontrollers, pods with no owner.
	return nil
}
func (s *OnlineMonitorCB) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	// monitor pods
	return nil
}
func (s *OnlineMonitorCB) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (s *OnlineMonitorCB) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnHoneyspot(honeyspot *assets.TensorHoneySpot, action assets.AssetsAction) error {
	return nil
}
func (s *OnlineMonitorCB) OnTensorRole(tensorRole *assets.TensorRole, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnTensorClusterRole(tensorRole *assets.TensorClusterRole, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnTensorNamespace(namespace *assets.TensorNamespace, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) OnTensorNode(node *assets.TensorNode, action assets.AssetsAction) error {
	return nil
}

func (s *OnlineMonitorCB) AfterDataSynced(ctx context.Context, dataSynced bool, _ string) {

}

func (s *OnlineMonitorCB) Name() string {
	return "images_online_monitor"
}

func (s *OnlineMonitorCB) sendInput(pod *corev1.Pod, notify model.NotifyContext) {
	for _, container := range pod.Status.ContainerStatuses {
		rej := model.RejectOnlineMonitorImage{
			Digest:        getImageSHAFromContainer(container),
			Image:         container.Image,
			FromType:      model.UsePatternForOnline,
			NotifyContext: notify,
		}

		if len(rej.Digest) > 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			defer timer.Stop()
			select {
			case s.inputChan <- rej:
			case <-timer.C:
				continue
			}
		}
	}
}
func (s *OnlineMonitorCB) batchDetectImages(buffer map[string]model.RejectOnlineMonitorImage) error {
	if len(buffer) == 0 {
		return nil
	}
	body := make([]model.RejectOnlineMonitorImage, 0, len(buffer))
	for _, rej := range buffer {
		body = append(body, rej)
	}

	bys, err := json.Marshal(body)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("detectImage Marshal error")
		return err
	}
	detectURL := fmt.Sprintf("%s/api/v1/imagereject/online_moniter", s.parent.scannerURL)

	tctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, "POST", detectURL, bytes.NewReader(bys))
	if err != nil {
		logging.GetLogger().Err(err).Msg("detectImage NewRequest,error")
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.GetLogger().Err(err).Msg("detectImage 请求scanner服务出错")
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(response.Body)
		scErr := fmt.Errorf("detectImage 请求scanner服务出错:statusCode:%d, msg: %s", response.StatusCode, string(bodyBytes))
		logging.GetLogger().Err(scErr).Msgf("call scanner error")
		return scErr
	}
	return nil
}
