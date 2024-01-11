package metrics

import (
	"context"
	"encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"time"
)

type dockerMetrics struct {
	client    *client.Client
	appLabels []string
	self      *heartbeat.SelfInfo
}

func NewDockerClient(sf *heartbeat.SelfInfo, appLabels []string) (*dockerMetrics, error) {
	if sf == nil {
		return nil, errors.New("selfInfo is empty")
	}
	uri := os.Getenv("DOCKER_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/docker.sock"
	}

	// docker client
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(uri), client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errors.Errorf("docker new client failed, %v", err)
	}

	var impl dockerMetrics
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Ping(ctx)
	if err != nil {
		return nil, errors.Errorf("ping docker server failed, %v", err)
	}

	client.NegotiateAPIVersion(ctx)
	impl.client = client
	impl.appLabels = appLabels
	impl.self = sf
	return &impl, nil
}

func (d *dockerMetrics) Metrics() (heartbeat.DataTypeConMetricsInNode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return d.getMetricsByApplabels(ctx, d.appLabels)
}

func (d *dockerMetrics) GetMetricsByAppLabel(appLabel string) (heartbeat.DataTypeConMetricsInNode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	return d.getMetricsByApplabels(ctx, []string{appLabel})
}

func (d *dockerMetrics) getMetricsByApplabels(ctx context.Context, appLabels []string) (heartbeat.DataTypeConMetricsInNode, error) {
	now := time.Now()
	filter := filters.NewArgs()
	filter.Add("status", "running")
	containers, err := d.client.ContainerList(ctx, types.ContainerListOptions{
		Filters: filter,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to list containers")
		return heartbeat.DataTypeConMetricsInNode{}, err
	}
	var result heartbeat.DataTypeConMetricsInNode
	for _, c := range containers {

		logging.Get().Debug().Str("raw-container", "list all  containers").Msgf("%s/%v", c.ID, c.Names)
		if len(c.Labels) == 0 {
			continue
		}
		logging.Get().Info().Msgf("id:%s, labels:%v", c.ID, c.Labels)
		if c.Labels["io.kubernetes.docker.type"] == "podsandbox" {
			continue
		}
		if c.Labels["io.kubernetes.pod.namespace"] != d.self.Namespace {
			continue
		}
		containerJson, err := d.client.ContainerInspect(context.Background(), c.ID)
		if err != nil {
			logging.Get().Err(err).Msgf("get container info: %s err", c.ID)
			return heartbeat.DataTypeConMetricsInNode{}, err
		}
		if containerJson.Config == nil {
			continue
		}
		appLabel, isMatch := IsMonitorAppLabel(appLabels, containerJson.Config.Env)
		if isMatch == false {
			continue
		}
		logging.Get().Info().Msgf("handler container appLabel:%s", appLabel)
		// limit
		containerMetrics := heartbeat.ContainerMetric{
			SelfInfo: &heartbeat.SelfInfo{
				ClusterKey:    d.self.ClusterKey,
				NodeName:      d.self.NodeName,
				Version:       d.self.Version,
				Namespace:     d.self.Namespace,
				PodName:       c.Labels["io.kubernetes.pod.name"],
				ContainerName: c.Labels["io.kubernetes.container.name"],
				AppLabel:      appLabel,
			},
			MetricsInfo: &heartbeat.MetricsInfo{},
		}
		var cpuLimit float32
		var memLimit int64
		if containerJson.HostConfig.CPUPeriod != 0 {
			cpuLimit = float32(containerJson.HostConfig.CPUQuota) / float32(containerJson.HostConfig.CPUPeriod)
		}
		memLimit = containerJson.HostConfig.Memory
		containerMetrics.CpuLimit = cpuLimit
		containerMetrics.MemLimit = uint64(memLimit)
		//usage
		stats, err := d.client.ContainerStats(context.Background(), c.ID, false)
		if err != nil {
			continue
		}
		var v types.Stats
		err = json.NewDecoder(stats.Body).Decode(&v)
		stats.Body.Close()
		containerMetrics.CpuStats = heartbeat.CpuStats{
			TotalUsage:  v.CPUStats.CPUUsage.TotalUsage / 1000,
			SystemUsage: v.CPUStats.SystemUsage / 1000,
			OnlineCPUs:  v.CPUStats.OnlineCPUs,
		}
		containerMetrics.MemUsage = uint64(heartbeat.CalculateMemUsageUnixNoCache(v.MemoryStats))
		containerMetrics.BlockITotal, containerMetrics.BLockOTotal = heartbeat.CalculateBlockIO(v.BlkioStats)
		containerMetrics.CollectTime = now
		result.ContainerMetricList = append(result.ContainerMetricList, &containerMetrics)
	}
	return result, nil

}
