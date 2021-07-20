package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

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
func (s *OnlineMonitor) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	return &OnlineMonitorCB{
		parent: s,
	}
}

func (s *OnlineMonitor) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch:            {},
		assets.TensorResources2Watch: {},
	}
}

func (s *OnlineMonitor) Name() string {
	return "images_online_monitor"
}

type OnlineMonitorCB struct {
	parent *OnlineMonitor
}

func (s *OnlineMonitorCB) OnReplicaSetEvent(newRs, oldRs *appsv1.ReplicaSet, action assets.AssetsAction) error {
	return nil
}

// OnPodEvent 对于新增的pod,我们查一下有那些镜像没有被扫描，或扫描失败
func (s *OnlineMonitorCB) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// logging.GetLogger().Info().Msg("在线监控，开始检测")
	if newPod == nil {
		return nil
	}
	ctx := context.Background()
	ignoredNameSpaces := []string{"kube-system", "tensorsec"}
	for _, ns := range ignoredNameSpaces {
		if newPod.Namespace == ns {
			logging.GetLogger().Debug().Msg("在ignoredNameSpaces中,PodName:" + newPod.Name)
			return nil
		}
	}

	notify := model.NotifyContext{
		PodUID:    string(newPod.UID),
		PodName:   newPod.Name,
		Namespace: newPod.Namespace,
		Cluster:   newPod.ClusterName,
	}
	logging.GetLogger().WithContext(ctx).Infof(fmt.Sprintf("k8s在线 NotifyContext PodId:%s,PodName:%s,Namespace:%s,Cluster:%s,action:%v", notify.PodUID, notify.PodName, notify.Namespace, notify.Cluster, action))

	if action != assets.ActionDelete {
		if err := s.detectImage(ctx, newPod.Status.ContainerStatuses, &notify); err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "k8s在线监控镜像OnPodEvent出错")
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
	logging.GetLogger().WithContext(ctx).Infof("在线监控detectImage,containers:%d", len(containers))

	for i := range containers {
		rej := model.RejectOnlineMoniterImage{
			Digest:        getImageSHAFromContainer(&containers[i]),
			Image:         containers[i].Image,
			FromType:      model.UsePatternForOnline,
			NotifyContext: notify,
		}
		body = append(body, rej)
	}

	bys, err := json.Marshal(body)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "detectImage Marshal error")
		return err
	}
	detectURl := fmt.Sprintf("%s/api/v1/imagereject/online_moniter", s.parent.scannerURL)
	logging.GetLogger().Debug().Msgf(fmt.Sprintf("detectImage detectURl:%s", detectURl))

	req, err := http.NewRequest("POST", detectURl, bytes.NewReader(bys))
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "detectImage NewRequest,error")
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := http.Client{}
	cancelCtx, cancelFucn := context.WithCancel(ctx)
	defer cancelFucn()
	response, err := client.Do(req.WithContext(cancelCtx))
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "detectImage 请求scanner服务出错")
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		logging.GetLogger().WithContext(ctx).Errorf(errors.New("detectImage 请求scanner服务出错"), "")
	}
	return nil
}
