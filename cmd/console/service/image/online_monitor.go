package image

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func getImageSHAFromContainer(container *corev1.ContainerStatus) string {
	// imageID: docker-pullable://192.168.1.203:5000/tensorsec-console@sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	shaDigestAndPullInfo := strings.Split(container.ImageID, "@")
	return shaDigestAndPullInfo[len(shaDigestAndPullInfo)-1]
}

type OnlineMonitor struct {
	postgre    *rdbtools.GormWrapper
	scannerURL string
}

func NewOnlineMonitor(postgre *rdbtools.GormWrapper, scannerURL string) *OnlineMonitor {
	return &OnlineMonitor{
		postgre:    postgre,
		scannerURL: scannerURL,
	}
}
func (s *OnlineMonitor) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncDur time.Duration) assets.ClusterCallback {
	res := &OnlineMonitorCB{
		parent:  s,
		exitMap: make(map[string]int64),
		lock:    sync.Mutex{},
	}
	go res.deleteMap()
	return res
}

func (s *OnlineMonitor) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
		// assets.TensorResources2Watch: {},
	}
}

func (s *OnlineMonitor) Name() string {
	return "images_online_monitor"
}

type OnlineMonitorCB struct {
	parent  *OnlineMonitor
	exitMap map[string]int64
	lock    sync.Mutex
}

func (s *OnlineMonitorCB) OnReplicaSetEvent(newRs, oldRs *appsv1.ReplicaSet, action assets.AssetsAction) error {
	return nil
}

// OnPodEvent 对于新增的pod,我们查一下有那些镜像没有被扫描，或扫描失败
func (s *OnlineMonitorCB) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	ctx := context.Background()
	// logging.GetLogger().WithContext(ctx).Infof("K8sOnlineMonitor 在线监控，开始检测")
	if newPod == nil {
		return nil
	}
	ignoredNameSpaces := []string{"kube-system", "tensorsec"}
	for _, ns := range ignoredNameSpaces {
		if newPod.Namespace == ns {
			logging.GetLogger().Debug().Msg("在ignoredNameSpaces中,PodName:" + newPod.Name)
			return nil
		}
	}

	if newPod.Status.Phase != corev1.PodRunning {
		logging.GetLogger().Debug().Msgf("K8sOnlineMonitor newPod.Status.Phase:%s", newPod.Status.Phase)
		return nil
	}
	// 使用一个全局的map做验证
	s.lock.Lock()
	if _, ok := s.exitMap[string(newPod.UID)]; ok {
		s.lock.Unlock()
		logging.GetLogger().Info().Msgf("K8sOnlineMonitor updated ,podUUID %s", newPod.UID)
		return nil
	}
	s.exitMap[string(newPod.UID)] = time.Now().Unix()
	s.lock.Unlock()

	notify := model.NotifyContext{
		PodUID:    string(newPod.UID),
		PodName:   newPod.Name,
		Namespace: newPod.Namespace,
		Cluster:   newPod.ClusterName,
	}

	logging.GetLogger().Info().Msgf("K8sOnlineMonitor NotifyContext PodId:%s,PodName:%s,Namespace:%s,Cluster:%s,action:%v,status:%s", notify.PodUID, notify.PodName, notify.Namespace, notify.Cluster, action, newPod.Status.Phase)

	if action != assets.ActionDelete {
		if err := s.detectImage(ctx, newPod.Status.ContainerStatuses, &notify); err != nil {
			logging.GetLogger().Err(err).Msgf("K8sOnlineMonitor detect image error")
		}
	}
	return nil
}

func (s *OnlineMonitorCB) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	// monitor resource creation and chages including replicasets, statefulsets, daemonsets, cronjobs, jobs, deployments, replicationcontrollers, pods with no owner.
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
func (s *OnlineMonitorCB) AfterDataSynced(ctx context.Context, dataSynced bool) {

}

func (s *OnlineMonitorCB) Name() string {
	return "images_online_monitor"
}

func (s *OnlineMonitorCB) detectImage(ctx context.Context, containers []corev1.ContainerStatus, notify *model.NotifyContext) error {
	body := make([]model.RejectOnlineMoniterImage, 0)
	// logging.GetLogger().WithContext(ctx).Infof("K8sOnlineMonitor detectImage,containers:%d", len(containers))

	for i := range containers {
		rej := model.RejectOnlineMoniterImage{
			Digest:        getImageSHAFromContainer(&containers[i]),
			Image:         containers[i].Image,
			FromType:      model.UsePatternForOnline,
			NotifyContext: notify,
		}
		// 对于删除的事件，K8s还是会发更新事件，这个时候digest为空
		if rej.Digest != "" {
			body = append(body, rej)
		}
	}
	if len(body) == 0 {
		logging.GetLogger().Debug().Msgf("body is empty")
		return nil
	}

	bys, err := json.Marshal(body)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("detectImage Marshal error")
		return err
	}
	detectURl := fmt.Sprintf("%s/api/v1/imagereject/online_moniter", s.parent.scannerURL)
	logging.GetLogger().Debug().Msgf("detectImage detectURl:%s", detectURl)

	req, err := http.NewRequest("POST", detectURl, bytes.NewReader(bys))
	if err != nil {
		logging.GetLogger().Err(err).Msg("detectImage NewRequest,error")
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	cancelCtx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()
	response, err := http.DefaultClient.Do(req.WithContext(cancelCtx))
	if err != nil {
		logging.GetLogger().Err(err).Msg("detectImage 请求scanner服务出错")
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		logging.GetLogger().Error().Msgf("detectImage 请求scanner服务出错:statusCode:%d", response.StatusCode)
	}
	return nil
}

func (s *OnlineMonitorCB) deleteMap() {
	ticker := time.NewTicker(time.Hour * 24)
	for {
		<-ticker.C
		s.lock.Lock()
		s.exitMap = make(map[string]int64)
		s.lock.Unlock()
	}
}
