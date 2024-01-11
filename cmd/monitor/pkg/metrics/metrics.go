package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	DockerType     = "docker"
	CrioType       = "cri-o"
	PodmanType     = "podman"
	ContainerdType = "containerd"

	defaultMonitorDuration = "60"
)

var monitorAppLabels []string // 监控容器对象

type MetricsI interface {
	Metrics() (heartbeat.DataTypeConMetricsInNode, error)
	GetMetricsByAppLabel(appLabel string) (heartbeat.DataTypeConMetricsInNode, error)
}

type MetricsWatcher struct {
	metricsImpl MetricsI
	ticker      *time.Ticker
	mqWriter    mq.Writer
	topic       string
	clusterKey  string
}

func NewMetricsWatcher(self *heartbeat.SelfInfo, runtimeVersion string, writer mq.Writer, topic string) (*MetricsWatcher, error) {
	watcher := MetricsWatcher{
		mqWriter:   writer,
		topic:      topic,
		clusterKey: self.ClusterKey,
	}
	appLabels := strings.Split(util.GetEnvWithDefault(env.MonitorLabelApps, env.DefaultMonitorAppLabels), ",")
	var err error
	monitorAppLabels = GetMonitorAppLabels()
	if strings.HasPrefix(runtimeVersion, DockerType) {
		watcher.metricsImpl, err = NewDockerClient(self, appLabels)
	} else if strings.HasPrefix(runtimeVersion, ContainerdType) {
		watcher.metricsImpl, err = NewcontainerdClient(self, appLabels)
	} else if strings.HasPrefix(runtimeVersion, CrioType) {
		watcher.metricsImpl, err = NewcrioClient(self, appLabels)
	} else {
		return nil, errors.New("not support cri type:" + runtimeVersion)
	}
	if err != nil {
		logging.Get().Err(err).Msgf("new  metricsImpl failed.runtimeVersion:%s", runtimeVersion)
		return nil, errors.New("new  metricsImpl failed.runtimeVersion:" + runtimeVersion)
	}

	duration := os.Getenv(env.MonitorDuration)
	if duration == "" {
		duration = defaultMonitorDuration
	}
	durationInt, err := strconv.ParseInt(duration, 10, 32)
	if err != nil {
		return nil, err
	}
	watcher.ticker = time.NewTicker(time.Duration(durationInt) * time.Second)
	return &watcher, nil
}

func (m *MetricsWatcher) Run() {
	defer func() {
		r := recover()
		if r != nil {
			logging.Get().Error().Msgf("get metrics failed. %v,stack:%v", r, string(debug.Stack()))
		}
	}()
	for _ = range m.ticker.C {
		logging.Get().Info().Msgf("begin metrics task")
		metricsResp, err := m.metricsImpl.Metrics()
		if err != nil {
			logging.Get().Err(err).Msgf("run metrics failed.")
		}
		logging.Get().Info().Msgf("get  metrics response length:%d", len(metricsResp.ContainerMetricList))
		if len(metricsResp.ContainerMetricList) == 0 {
			continue
		}

		ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
		msg := heartbeat.BeatMessage{
			Action: heartbeat.ActionTypeMetrics,
			Data:   metricsResp,
		}
		marshal, err := json.Marshal(msg)
		if err != nil {
			logging.Get().Err(err).Msgf(" json.Marshal failed.")
			continue
		}
		logging.Get().Info().Msgf("get  metrics response :%s", string(marshal))
		err = m.mqWriter.Write(ctx, m.topic, kafka.Message{
			Key:   []byte(m.clusterKey),
			Value: marshal,
		})
		if err != nil {
			logging.Get().Err(err).Msgf("send metrics to kafka  failed.")
			continue
		}
		logging.Get().Info().Msgf("finish metrics task")
	}
}

func GetMonitorAppLabels() []string {
	podPrefix := os.Getenv(env.MonitorLabelApps)
	if podPrefix == "" {
		podPrefix = env.DefaultMonitorAppLabels
	}
	logging.Get().Info().Msgf("containerStatus: monitor podPrefix:%v", podPrefix)
	return strings.Split(podPrefix, ",")
}

func IsMonitorAppLabel(appLabels []string, envs []string) (appLabel string, isMatch bool) {
	for _, e := range envs {
		if strings.HasPrefix(e, env.PodAppLabel) {
			appLabel = e[len(env.PodAppLabel)+1:]
			break
		}
	}
	if appLabel == "" {
		return
	}
	for _, label := range appLabels {
		if appLabel == label {
			isMatch = true
			break
		}
	}
	return
}

func (m *MetricsWatcher) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Info().Msgf("monitorHandler 收到 grpc ，开始计算节点metrics信息")
	req := message.(*pb.ContainerMetricsReq)
	logging.Get().Debug().Msg(req.String())
	resp := &pb.ContainerMetricsResp{}
	var err error
	var metrics heartbeat.DataTypeConMetricsInNode
	metrics, err = m.metricsImpl.GetMetricsByAppLabel(req.AppLabel)
	if err != nil {
		resp.ErrMsg = err.Error()
	}
	for _, metric := range metrics.ContainerMetricList {
		item := pb.ContainerMetric{
			Self: &pb.SelfInfo{
				ClusterKey:    metric.ClusterKey,
				NodeName:      metric.NodeName,
				Version:       metric.Version,
				Namespace:     metric.Namespace,
				PodName:       metric.PodName,
				AppLabel:      metric.AppLabel,
				ContainerName: metric.ContainerName,
			},
			MetricsInfo: &pb.MetricsInfo{
				CpuStats: &pb.CpuStats{
					TotalUsage:  metric.CpuStats.TotalUsage,
					SystemUsage: metric.CpuStats.SystemUsage,
					OnlineCPUs:  metric.CpuStats.OnlineCPUs,
				},
				CpuLimit:    metric.CpuLimit,
				MemUsage:    metric.MemUsage,
				MemLimit:    metric.MemLimit,
				BlockITotal: metric.BlockITotal,
				BLockOTotal: metric.BLockOTotal,
				Time:        timestamppb.New(metric.CollectTime),
			},
		}
		resp.Metrics = append(resp.Metrics, &item)
	}
	logging.Get().Info().Msgf("monitorHandler,label:%s response:%s", req.AppLabel, resp.String())
	err = s.SendResponse(reqID, resp)
	if err != nil {
		logging.Get().Err(err).Msgf("monitorHandler grpc send response failed.")
	}
}

func (m *MetricsWatcher) OnRead(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {}

func (m *MetricsWatcher) OnUpdate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
}

func (m *MetricsWatcher) OnDelete(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
}
