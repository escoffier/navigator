package monitor

import (
	"context"
	"errors"
	pkgasserts "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sync"
	"time"
)

var (
	instance *MonitorService
	rlOnce   sync.Once
)

type MonitorService struct {
	rdb    *databases.RDBInstance
	stream rpcstream.MessageStream
}

func InitMonitorService(rdb *databases.RDBInstance, stream rpcstream.MessageStream) error {
	var err error
	rlOnce.Do(func() {
		instance, err = NewMonitorService(rdb, stream)
	})
	return err
}

func GetService() (*MonitorService, bool) {
	return instance, instance != nil
}

func NewMonitorService(rdb *databases.RDBInstance, stream rpcstream.MessageStream) (*MonitorService, error) {
	return &MonitorService{
		rdb:    rdb,
		stream: stream,
	}, nil
}

func (m *MonitorService) GetMonitorTotal() (*dal.MonitorTotal, error) {
	return dal.GetMonitorTotal(context.Background(), m.rdb.Get())
}

func (m *MonitorService) GetMonitorHolmes(ctx context.Context, queryOptions *dal.MonitorOption, offset, limit int) ([]*dal.MonitorHolmesResp, int64, error) {
	ctx2, _ := context.WithTimeout(ctx, time.Second*3)
	// pod 的状态标记在了下面的damon记录上
	holmesPod, err := dal.GetMonitorHolmesPod(ctx2, m.rdb.Get(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	total, err := dal.GetMonitorHolmesPodTotal(ctx2, m.rdb.Get(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return holmesPod, total, nil
}

func (m *MonitorService) GetMonitorComponent(ctx context.Context, queryOptions *dal.MonitorOption, offset, limit int) ([]*dal.MonitorComponentResp, int64, error) {
	ctx2, _ := context.WithTimeout(ctx, time.Second*3)
	holmesPod, err := dal.GetMonitorComponentPod(ctx2, m.rdb.Get(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	total, err := dal.GetMonitorComponentPodTotal(ctx2, m.rdb.Get(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return holmesPod, total, nil
}

func (m *MonitorService) RefreshMonitorComponent(ctx context.Context, component string) (interface{}, int64, error) {
	returnResult := func() (interface{}, int64, error) {
		switch component {
		case dal.AppLabel_holmes:
			return m.GetMonitorHolmes(ctx, &dal.MonitorOption{}, 0, 10)
		case dal.AppLabel_clusterManager, dal.AppLabel_scanner:
			return m.GetMonitorComponent(ctx, &dal.MonitorOption{
				WhereEqCondition: map[string]any{
					"app_label": component,
				},
			}, 0, 10)
		default:
			return nil, 0, errors.New("components is not support")
		}
	}

	keys, err := dal.GetClusterKeyList(ctx, m.rdb.Get())
	if len(keys) == 0 {
		return returnResult()
	}
	nsMap, err := dal.GetSoftNamespace(ctx, m.rdb.Get(), keys)
	if err != nil {
		logging.Get().Err(err).Msgf("GetSoftNamespace failed.")
		return returnResult()
	}
	if len(nsMap) == 0 {
		logging.Get().Err(err).Msgf("get namesapce env failed.")
		return returnResult()
	}
	logging.Get().Info().Msgf("nsMap:%v", nsMap)
	now := time.Now()
	for _, key := range keys {
		namespace, isOK := nsMap[key]
		if !isOK {
			continue
		}
		k8sClient, err := m.getK8sClient(ctx, key)
		if err != nil {
			logging.Get().Err(err).Msgf("get k8sClient failed.clusterKey:%s", key)
			continue
		}

		podList, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=" + component,
		})
		if err != nil {
			logging.Get().Err(err).Msgf("get k8sClient failed.clusterKey:%s", key)
			continue
		}
		logging.Get().Info().Msgf("get component:%s podList length:%d in clusterKey:%s", component, len(podList.Items), key)
		var version string
		nodeNames := make(map[string]struct{})
		for _, pod := range podList.Items {
			var containers []*model.TensorsecContainerMonitor
			var containerRunning int
			var isHealth bool
			nodeNames[pod.Spec.NodeName] = struct{}{}

			logging.Get().Info().Msgf("podName:%s, podStatus:%s", pod.Name, pod.Status.String())

			for _, status := range pod.Status.ContainerStatuses {
				tmp := model.TensorsecContainerMonitor{
					TableBase: model.TableBase{
						ID:        util.GenerateUUID(key, pod.Name, status.Name),
						CreatedAt: now,
						UpdatedAt: now,
						Status:    0,
					},
					ClusterKey:      key,
					NodeName:        pod.Spec.NodeName,
					Namespace:       pod.Namespace,
					PodName:         pod.Name,
					PodIsHealth:     0,
					AppLabel:        component,
					MetricsLastTime: now,
					Version:         version,
					ContainerName:   status.Name,
					ContainerStatus: dal.GetContainerCRIState(&status.State, status.Ready),
				}
				logging.Get().Info().Msgf("podName:%s,ContainerStatus:%d,status:%s", pod.Name, tmp.ContainerStatus, status.String())
				if tmp.ContainerStatus == dal.ContainerStatus_normal_int {
					containerRunning++
				}
				if tmp.Version == "" {
					version = dal.GetSoftVersionFromAssetsByKey(ctx, m.rdb.Get(), tmp.ClusterKey, tmp.Namespace)
					tmp.Version = version
				}
				containers = append(containers, &tmp)
			}
			isHealth = containerRunning == len(pod.Status.ContainerStatuses)
			isHolmes := component == dal.AppLabel_holmes
			if len(containers) > 0 {
				err := dal.UpsertContainerStatus(ctx, m.rdb.Get(), false, containers, isHolmes, isHealth)
				if err != nil {
					logging.Get().Err(err).Msgf("UpsertContainerStatus failed.")
					continue
				}
				if err != nil {
					logging.Get().Err(err).Msgf("refresh containerStatus in clusterKey:%s failed.", key)
				}
			}
		}
		//clean
		if component != dal.AppLabel_clusterManager { // cluster-manager 只在心跳时更新时间
			dal.CleanExpireContainerStatus(ctx, m.rdb.Get(), key, now, component, "")
		}
		//	 metrics
		var nodeNameList []string
		for name, _ := range nodeNames {
			nodeNameList = append(nodeNameList, name)
		}
		if len(nodeNameList) == 0 {
			continue
		}
		metrics, err := m.stream.GetContainerMetrics(ctx, key, &pb.ContainerMetricsReq{
			ClusterKey: key,
			NodeName:   nodeNameList,
			AppLabel:   component,
		})
		if err != nil {
			logging.Get().Err(err).Msgf("grpc get metrics failed.component:%s", component)
			continue
		}
		logging.Get().Info().Msgf("grpc get metrics success.length:%d", len(metrics.Metrics))

		var idList []uint32
		var tensorsecMonitorList []*model.TensorsecContainerMonitor
		for _, me := range metrics.Metrics {
			asTime := me.MetricsInfo.Time.AsTime()
			if asTime.IsZero() {
				asTime = now
			}
			value := &model.TensorsecContainerMonitor{
				TableBase: model.TableBase{
					ID:        util.GenerateUUID(me.Self.ClusterKey, me.Self.PodName, me.Self.ContainerName),
					CreatedAt: asTime,
					UpdatedAt: asTime,
				},
				Version:               me.Self.Version,
				MetricsLastTime:       asTime,
				CpuUsageCurrent:       me.MetricsInfo.CpuStats.TotalUsage,
				CpuSystemUsageCurrent: me.MetricsInfo.CpuStats.SystemUsage,
				OnlineCpus:            me.MetricsInfo.CpuStats.OnlineCPUs,
				CpuLimit:              me.MetricsInfo.CpuLimit,
				MemCurrent:            me.MetricsInfo.MemUsage,
				MemLimit:              me.MetricsInfo.MemLimit,
				BlockICurrent:         me.MetricsInfo.BlockITotal,
				BlockOCurrent:         me.MetricsInfo.BLockOTotal,
			}
			idList = append(idList, value.ID)
			tensorsecMonitorList = append(tensorsecMonitorList, value)
		}
		oldMetricsMap, err := dal.GetOldMetricsMap(ctx, m.rdb.Get(), idList)
		if err != nil {
			logging.Get().Err(err).Msgf("get old metrics failed.")
			continue
		}
		for _, monitor := range tensorsecMonitorList {
			oldMetrics, isOK := oldMetricsMap[monitor.ID]
			if isOK == false {
				continue
			}
			monitor.CpuUsageLast = oldMetrics.CpuUsageCurrent
			monitor.CpuSystemUsageLast = oldMetrics.CpuSystemUsageCurrent
			monitor.MemLast = oldMetrics.MemCurrent
			monitor.BlockILast = oldMetrics.BlockICurrent
			monitor.BlockOLast = oldMetrics.BlockOCurrent
			if oldMetrics.CpuUsageCurrent > 0 {
				// 微秒
				monitor.TimeGap = monitor.MetricsLastTime.Sub(oldMetrics.MetricsLastTime).Microseconds()
			}
		}
		if component == dal.AppLabel_clusterManager {
			err = dal.UpsertContainerMetrics(ctx, m.rdb.Get(), nil, tensorsecMonitorList)
		} else {
			err = dal.UpsertContainerMetrics(ctx, m.rdb.Get(), tensorsecMonitorList, nil)
		}
		if err != nil {
			logging.Get().Err(err).Msgf("refresh :update metrics failed.key:%s,appLabel:%s", key, component)
		} else {
			logging.Get().Err(err).Msgf("refresh  success: appLabel:%s,clusterKey:%s", component, key)
		}
	}
	return returnResult()
}

func (m *MonitorService) getK8sClient(_ context.Context, clusterKey string) (*pkgasserts.Clientset, error) {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, errors.New("get cluster falied")
	}

	// get client
	k8sClient, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return nil, errors.New("get k8s client error")
	}

	return k8sClient, nil
}
