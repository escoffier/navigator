package heartbeat

import (
	"context"
	"encoding/json"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"time"
)

type BeatReceive struct {
	consumer mq.Reader
	topic    string
	groupID  string
	rdb      *databases.RDBInstance
}

func NewWatcher(reader mq.Reader, topic, groupID string, rdb *databases.RDBInstance) *BeatReceive {
	w := &BeatReceive{
		consumer: reader,
		topic:    topic,
		groupID:  groupID,
		rdb:      rdb,
	}
	return w
}

func (b *BeatReceive) Run(stopChan <-chan struct{}) {
	b.consumer.Subscribe(b.topic, b.groupID, b.process)
	<-stopChan
}

func (b *BeatReceive) process(ctx context.Context, message kafka.Message) error {
	rawMessage := json.RawMessage{}
	dataMessage := BeatMessage{
		Data: &rawMessage,
	}
	err := json.Unmarshal(message.Value, &dataMessage)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshal message err")
		return err
	}
	logging.Get().Info().Msgf("process heartbeat topic Action :%s", dataMessage.Action)
	switch dataMessage.Action {
	case ActionTypeBeat:
		var beatMessage DataTypeBeat
		err := json.Unmarshal(rawMessage, &beatMessage)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal message err")
			return err
		}
		db := b.rdb.Get()
		now := time.Now()
		value := &model.TensorsecContainerMonitor{
			TableBase: model.TableBase{
				ID:        util.GenerateUUID(beatMessage.ClusterKey, beatMessage.PodName, beatMessage.ContainerName),
				CreatedAt: beatMessage.BeatTime,
				UpdatedAt: now,
			},
			ClusterKey:      beatMessage.ClusterKey,
			NodeName:        beatMessage.NodeName,
			Namespace:       beatMessage.Namespace,
			PodName:         beatMessage.PodName,
			AppLabel:        beatMessage.AppLabel,
			ContainerName:   beatMessage.ContainerName,
			MetricsLastTime: now,
		}
		if value.NodeName == "" || value.ContainerName == "" { // for case: cluster-manager report heartbeat
			var rawcontainer model.TensorRawContainer
			err = db.Where("cluster_key=? and pod_name=? and status =0", value.ClusterKey, value.PodName).Select("node_name,name").Find(&rawcontainer).Error
			if err != nil || rawcontainer.NodeName == "" || rawcontainer.Name == "" {
				logging.Get().Err(err).Msgf("find nodeName failed. clusterKey:%s,podName:%s", value.ClusterKey, value.PodName)
				return err
			}
			value.NodeName = rawcontainer.NodeName
			value.ContainerName = rawcontainer.Name
			value.ID = util.GenerateUUID(value.ClusterKey, value.PodName, value.ContainerName)
		}
		err = dal.UpsertClusterManagerHeartbeat(ctx, db, value)
		if err != nil {
			logging.Get().Err(err).Msg("save heartbeat to db failed.")
			return err
		}
	case ActionTypeMetrics:
		var metricsList DataTypeConMetricsInNode
		err := json.Unmarshal(rawMessage, &metricsList)
		if err != nil {
			logging.Get().Err(err).Msg("unmarshal message err")
			return err
		}
		var idList []uint32
		var tensorsecMonitorList []*model.TensorsecContainerMonitor
		var tensorsecClusterMnagerList []*model.TensorsecContainerMonitor
		for _, me := range metricsList.ContainerMetricList {
			value := &model.TensorsecContainerMonitor{
				TableBase: model.TableBase{
					ID:        util.GenerateUUID(me.ClusterKey, me.PodName, me.ContainerName),
					CreatedAt: me.CollectTime,
					UpdatedAt: me.CollectTime,
				},
				ClusterKey:            me.ClusterKey,
				NodeName:              me.NodeName,
				Namespace:             me.Namespace,
				PodName:               me.PodName,
				AppLabel:              me.AppLabel,
				ContainerName:         me.ContainerName,
				Version:               me.Version,
				MetricsLastTime:       me.CollectTime,
				CpuUsageCurrent:       me.CpuStats.TotalUsage,
				CpuSystemUsageCurrent: me.CpuStats.SystemUsage,
				OnlineCpus:            me.CpuStats.OnlineCPUs,
				CpuLimit:              me.CpuLimit,
				MemCurrent:            me.MemUsage,
				MemLimit:              me.MemLimit,
				BlockICurrent:         me.BlockITotal,
				BlockOCurrent:         me.BLockOTotal,
			}
			idList = append(idList, value.ID)
			if value.AppLabel == dal.AppLabel_clusterManager {
				tensorsecClusterMnagerList = append(tensorsecClusterMnagerList, value)
			} else {
				tensorsecMonitorList = append(tensorsecMonitorList, value)
			}
		}
		oldMetricsMap, err := dal.GetOldMetricsMap(ctx, b.rdb.Get(), idList)
		if err != nil {
			logging.Get().Err(err).Msgf("get old metrics failed.")
			return err
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
		for _, monitor := range tensorsecClusterMnagerList {
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
		err = dal.UpsertContainerMetrics(ctx, b.rdb.Get(), tensorsecMonitorList, tensorsecClusterMnagerList)
		if err != nil {
			logging.Get().Err(err).Msgf("get old metrics failed.")
			return err
		}
	default:
		logging.Get().Err(err).Msgf("unsupport actionType:%s", dataMessage.Action)
		return err
	}
	return nil
}
