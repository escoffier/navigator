package monitor

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"strings"
	"sync"
	"time"
)

var callback *ContainerStatusCallback
var once sync.Once

func initCbOnce(rdb *databases.RDBInstance) {
	once.Do(func() {
		appLabels := util.GetEnvWithDefault(env.MonitorLabelApps, env.DefaultMonitorAppLabels)
		logging.GetLogger().Info().Msgf("containerStatus: monitor appLabels:%v", appLabels)
		callback = &ContainerStatusCallback{
			rdb:                   rdb,
			containerStatusMap:    make(map[string]int8),
			monitorPodLabelApp:    strings.Split(appLabels, ","),
			clusterRefreshTimeMap: make(map[string]time.Time),
		}
	})
}

type ContainerStatusWatcher struct {
	rdb *databases.RDBInstance
}

func NewContainerStatusWatch(rdb *databases.RDBInstance) *ContainerStatusWatcher {
	return &ContainerStatusWatcher{rdb: rdb}
}

func (w *ContainerStatusWatcher) BeforeWatchNewCluster(ctx context.Context, clusterKey string, t time.Duration) assets.ClusterCallback {
	initCbOnce(w.rdb)
	callback.clusterRefreshTimeMap[clusterKey] = time.Now()
	return callback
}

func (w *ContainerStatusWatcher) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
	}
}

func (w *ContainerStatusWatcher) Name() string {
	return "ContainerStatusWatcher"
}

type ContainerStatusCallback struct {
	monitorPodLabelApp     []string
	containerStatusMap     map[string]int8 // cointainerId:status
	containerStatusMapLock sync.Mutex
	clusterRefreshTimeMap  map[string]time.Time
	rdb                    *databases.RDBInstance
}

// 获取container status，比较变化
func (c *ContainerStatusCallback) OnTensorPod(pod *assets.TensorPod, action assets.Action) error {
	var isMonitorObject bool
	logging.GetLogger().Info().Msgf("ContainerStatusCallback action:%d,podName:%s", action, pod.Name)

	if action == assets.ActionDelete { //  pod.Spec.Containers is empty
		affected, err := dal.DeleteContainerStatusByPodName(context.Background(), c.rdb.Get(), pod.Name)
		if err != nil {
			logging.GetLogger().Info().Msgf("ContainerStatusCallback delete pod failed.")
			return err
		}
		if affected == 0 {
			return nil
		}
		targetPrefix := pod.Name + ":"
		for k, _ := range c.containerStatusMap {
			if strings.HasPrefix(k, targetPrefix) {
				delete(c.containerStatusMap, k)
			}
		}
		return nil
	}

	// 检查是否是navigate系统下的pod： 判断容器的env 有否引用名为common-env的cm ；无法从pod信息中拿到 comfigmap的内容
	if len(pod.Status.ContainerStatuses) == 0 {
		logging.GetLogger().Debug().Msgf("ContainerStatusCallback pod.Status.ContainerStatuses is empty ")
		return nil
	}
	isMonitorObject = false
	for _, env := range pod.Spec.Containers[0].EnvFrom {
		if env.ConfigMapRef != nil && env.ConfigMapRef.Name == "common-env" {
			isMonitorObject = true
			break
		}
	}
	if !isMonitorObject {
		logging.GetLogger().Debug().Msg("ContainerStatusCallback env not contain common-env" + pod.Name)
		return nil
	}
	isMonitorObject = false
	//  app 标签 前缀匹配
	appName := pod.Labels["app"]
	for _, monitorValue := range c.monitorPodLabelApp {
		if appName == monitorValue {
			isMonitorObject = true
			logging.GetLogger().Info().Msg("ContainerStatusCallback find container,app:" + appName)
			break
		}
	}
	if !isMonitorObject {
		logging.GetLogger().Debug().Msg("ContainerStatusCallback app label not match,label:" + appName)
		return nil
	}
	logging.GetLogger().Info().Msg("ContainerStatusCallback handler pod:" + pod.Name)
	c.containerStatusMapLock.Lock()
	defer c.containerStatusMapLock.Unlock()
	switch action {
	case assets.ActionAdd, assets.ActionUpdate:
		tctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
		// version  从资产表中获取
		fullContainerId := pod.Status.ContainerStatuses[0].ContainerID
		logging.GetLogger().Info().Msg("fullContainerId:" + fullContainerId)
		if fullContainerId == "" {
			return nil
		}
		containerId := strings.Split(fullContainerId, "://")[1]
		version := dal.GetSoftVersionFromAssetsByCId(tctx, c.rdb.Get(), containerId)
		now := time.Now()
		totalContainer := len(pod.Status.ContainerStatuses)
		var normalCount int
		var changedContainers []*model.TensorsecContainerMonitor
		for _, status := range pod.Status.ContainerStatuses {
			oldStatus, isOk := c.containerStatusMap[pod.Name+":"+status.ContainerID]
			currentStatus := dal.GetContainerCRIState(&status.State, status.Ready)
			if currentStatus == dal.ContainerStatus_normal_int {
				normalCount++
			}
			if isOk && oldStatus == currentStatus {
				continue
			}
			logging.GetLogger().Info().Msgf("ContainerStatusCallback change %s:%s status from %d to %d ", pod.Name, status.Name, oldStatus, currentStatus)
			c.containerStatusMap[pod.Name+":"+status.ContainerID] = currentStatus
			changedContainers = append(changedContainers, &model.TensorsecContainerMonitor{
				TableBase: model.TableBase{
					ID:        util.GenerateUUID(pod.Cluster, pod.Name, status.Name),
					CreatedAt: now,
					UpdatedAt: now,
				},
				ClusterKey:      pod.Cluster,
				NodeName:        pod.Spec.NodeName,
				Namespace:       pod.Namespace,
				PodName:         pod.Name,
				AppLabel:        appName,
				ContainerName:   status.Name,
				ContainerStatus: currentStatus,
				Version:         version,
				MetricsLastTime: now,
			})
		}
		isHolmes := appName == dal.AppLabel_holmes
		var isHealth bool
		if isHolmes {
			isHealth = normalCount == totalContainer
		}

		err := dal.UpsertContainerStatus(tctx, c.rdb.Get(), false, changedContainers, isHolmes, isHealth)
		if err != nil {
			logging.GetLogger().Err(err).Msg("monitor: change container status failed.")
		}
		//	 删除initContainer记录（通过monitor的指标上报上来,运行时无法区分initContainer）
		var deleteIds []uint32
		for _, status := range pod.Status.InitContainerStatuses {
			deleteIds = append(deleteIds, util.GenerateUUID(pod.Cluster, pod.Name, status.Name))
		}
		if len(deleteIds) > 0 {
			_, err = dal.DeleteContainerStatusByIds(tctx, c.rdb.Get(), deleteIds)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("monitor: delete initContainer failed,podName:%s", pod.Name)
			}
		}
	}

	return nil
}

func (c *ContainerStatusCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.Action) error {

	return nil
}

func (c *ContainerStatusCallback) AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string) {
	logging.GetLogger().Info().Msgf("ContainerStatusCallback AfterDataSynced,clusterKey:%s", clusterKey)
	if !dataSynced {
		logging.GetLogger().Warn().Msg("AfterDataSynced dataSynced=false")
		return
	}
	oneCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	ts := c.clusterRefreshTimeMap[clusterKey]
	dal.CleanExpireContainerStatus(oneCtx, c.rdb.Get(), clusterKey, ts, "", "")
}

func (c *ContainerStatusCallback) OnTensorRole(role *assets.TensorRole, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorClusterRole(clusterRole *assets.TensorClusterRole, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorNamespace(ns *assets.TensorNamespace, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorNode(node *assets.TensorNode, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorIngress(node *assets.TensorIngress, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorService(node *assets.TensorService, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorEndpoints(node *assets.TensorEndpoints, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorSecret(node *assets.TensorSecret, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorPV(node *assets.TensorPV, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnTensorPVC(node *assets.TensorPVC, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnHoneyspot(honeyspot *assets.TensorHoneySpot, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnRawContainer(container *assets.TensorRawContainer, action assets.Action) error {
	return nil
}

func (c *ContainerStatusCallback) OnSync(sync *assets.TensorSync) error {
	return nil
}

func (c *ContainerStatusCallback) Name() string {
	return "monitory_container_status"
}
