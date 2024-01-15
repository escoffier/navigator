package metrics

import (
	"context"
	"encoding/json"
	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	v11 "github.com/containerd/cgroups/stats/v1"
	statsV1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	v1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/tasks/v1"
	v2 "github.com/containerd/containerd/metrics/types/v2"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl/v2"
	"github.com/docker/docker/api/types"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"strings"
	"time"
)

type containerdMetrics struct {
	client    *containerd.Client
	appLabels []string
	self      *heartbeat.SelfInfo
}

func NewcontainerdClient(sf *heartbeat.SelfInfo, labels []string) (*containerdMetrics, error) {
	if sf == nil {
		return nil, errors.New("selfInfo is empty")
	}
	var containerdImpl containerdMetrics

	uri := os.Getenv("CONTAINERD_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/containerd/containerd.sock"
	}
	client, err := containerd.New(strings.TrimPrefix(uri, "unix://"), containerd.WithTimeout(5*time.Second))
	if err != nil {
		return nil, errors.Errorf("containerd new client failed, %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.IsServing(ctx)
	if err != nil {
		return nil, errors.Errorf("check containerd daemon is serving failed,%v", err)
	}
	version, err := client.Version(ctx)
	if err != nil {
		return nil, errors.Errorf("get containerd version failed,%v", err)
	}
	logging.Get().Info().Str("CRI", ContainerdType).Msgf("containerd version: %v", version)

	containerdImpl.client = client
	containerdImpl.appLabels = labels
	containerdImpl.self = sf
	return &containerdImpl, nil
}

func (d *containerdMetrics) Metrics() (heartbeat.DataTypeConMetricsInNode, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*3)
	defer cancelFunc()
	nsCtx := namespaces.WithNamespace(ctx, "k8s.io")

	return d.getMetricsByAppLabels(nsCtx, d.appLabels)
}

func (d *containerdMetrics) GetMetricsByAppLabel(appLabel string) (heartbeat.DataTypeConMetricsInNode, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*3)
	defer cancelFunc()
	nsCtx := namespaces.WithNamespace(ctx, "k8s.io")
	return d.getMetricsByAppLabels(nsCtx, []string{appLabel})
}

func (d *containerdMetrics) getMetricsByAppLabels(nsCtx context.Context, appLabels []string) (heartbeat.DataTypeConMetricsInNode, error) {
	tasksResponse, err := d.client.TaskService().List(nsCtx, &tasks.ListTasksRequest{})
	if err != nil {
		logging.Get().Err(err).Msg("get taskList failed .")
	}
	var result heartbeat.DataTypeConMetricsInNode
	now := time.Now()
	for _, task := range tasksResponse.Tasks {
		if task.ContainerID == "" {
			task.ContainerID = task.ID
		}
		container, err := d.client.LoadContainer(nsCtx, task.ContainerID)
		if err != nil {
			logging.Get().Err(err).Msg("get container failed .")
			continue
		}
		labels, err := container.Labels(nsCtx)
		if err != nil {
			logging.Get().Err(err).Msgf("get container labels failed.")
			continue
		}
		if labels != nil && labels["io.cri-containerd.kind"] == "sandbox" {
			continue
		}
		spec, err := container.Spec(nsCtx)
		if err != nil {
			logging.Get().Err(err).Msg("get container spec failed.")
			continue
		}
		if spec == nil || spec.Process == nil {
			logging.Get().Err(err).Msg("container's spec is nil.")
			continue
		}
		appLabel, isMatch := IsMonitorAppLabel(appLabels, spec.Process.Env)
		if isMatch == false {
			continue
		}
		containerName := labels["io.kubernetes.container.name"]
		if appLabel == dal.AppLabel_clusterManager && containerName != dal.AppLabel_clusterManager {
			continue
		}
		logging.Get().Info().Msgf("handler container appLabel:%s", appLabel)

		containerMetrics := heartbeat.ContainerMetric{
			SelfInfo: &heartbeat.SelfInfo{
				ClusterKey:    d.self.ClusterKey,
				NodeName:      d.self.NodeName,
				Version:       d.self.Version,
				Namespace:     d.self.Namespace,
				PodName:       labels["io.kubernetes.pod.name"],
				ContainerName: containerName,
				AppLabel:      appLabel,
			},
			MetricsInfo: &heartbeat.MetricsInfo{
				CollectTime: now,
			},
		}
		//	 limit
		if spec.Linux != nil && spec.Linux.Resources != nil {
			if spec.Linux.Resources.CPU != nil && spec.Linux.Resources.CPU.Quota != nil && spec.Linux.Resources.CPU.Period != nil {
				containerMetrics.MetricsInfo.CpuLimit = float32(*spec.Linux.Resources.CPU.Quota) / float32(*spec.Linux.Resources.CPU.Period)
			}
			if spec.Linux.Resources.Memory != nil && spec.Linux.Resources.Memory.Limit != nil {
				containerMetrics.MetricsInfo.MemLimit = uint64(*spec.Linux.Resources.Memory.Limit)
			}
		}
		//metrics
		t, err := container.Task(nsCtx, nil)
		if err != nil {
			logging.Get().Err(err).Msgf("get container's task failed.")
			continue
		}
		metric, err := t.Metrics(nsCtx)
		if err != nil {
			logging.Get().Err(err).Msgf("get task's metric failed.")
			continue
		}
		anydata, err := typeurl.UnmarshalAny(metric.Data)
		if err != nil {
			logging.Get().Err(err).Msgf("typeurl.UnmarshalAny failed.")
			continue
		}

		var (
			data  *v1.Metrics
			data1 *v11.Metrics
			data2 *v2.Metrics
			//windowsStats *wstats.Statistics
		)
		switch v := anydata.(type) {
		case *v1.Metrics:
			data = v
		case *v11.Metrics:
			data1 = v
		case *v2.Metrics:
			data2 = v
		case *wstats.Statistics:
			//windowsStats = v
		default:
			logging.Get().Error().Msg("cannot convert metric data to cgroups.Metrics or windows.Statistics")
			// todo log
			bytes, err := json.Marshal(metric.Data)
			if err != nil {
				logging.Get().Err(err).Msg("cannot json.Marshal metric.Data")
			} else {
				logging.Get().Info().Msgf("metric.Data:%s", string(bytes))
			}
			bytes, err = json.Marshal(anydata)
			if err != nil {
				logging.Get().Err(err).Msg("cannot json.Marshal anydata")
			} else {
				logging.Get().Info().Msgf("anydata:%s", string(bytes))
			}
			continue
		}
		if data != nil {
			if data.CPU != nil && data.CPU.Usage != nil {
				containerMetrics.CpuStats = heartbeat.CpuStats{
					TotalUsage: data.CPU.Usage.Total / 1000,
					//SystemUsage: ,
					OnlineCPUs: uint32(len(data.CPU.Usage.PerCPU)),
				}
			}
			if data.Memory != nil && data.Memory.Usage != nil {
				containerMetrics.MemUsage = data.Memory.Usage.Usage
			}
			if data.Blkio != nil {
				containerMetrics.BlockITotal, containerMetrics.BLockOTotal = heartbeat.CalculateBlockIO(translateToTypesBlkio(data.Blkio))
			}
		} else if data2 != nil {
			if data2.CPU != nil {
				containerMetrics.CpuStats = heartbeat.CpuStats{
					TotalUsage: data2.CPU.UsageUsec,
				}
			}
			if data2.Memory != nil {
				containerMetrics.MemUsage = data2.Memory.Usage
			}
			if data2.Io != nil {
				containerMetrics.BlockITotal, containerMetrics.BLockOTotal = calculateIO(data2.Io)
			}
		} else if data1 != nil {
			if data1.CPU != nil && data1.CPU.Usage != nil {
				containerMetrics.CpuStats = heartbeat.CpuStats{
					TotalUsage: data1.CPU.Usage.Total / 1000,
					//SystemUsage: ,
					OnlineCPUs: uint32(len(data1.CPU.Usage.PerCPU)),
				}
			}
			if data1.Memory != nil && data1.Memory.Usage != nil {
				containerMetrics.MemUsage = data1.Memory.Usage.Usage
			}
			if data1.Blkio != nil {
				containerMetrics.BlockITotal, containerMetrics.BLockOTotal = heartbeat.CalculateBlockIO(translateToTypesBlkioV1(data1.Blkio))
			}
		} else { //windows
		}
		result.ContainerMetricList = append(result.ContainerMetricList, &containerMetrics)
	}
	return result, nil
}

func translateToTypesBlkio(blkio *v1.BlkIOStat) types.BlkioStats {
	var result types.BlkioStats
	if blkio == nil {
		return result
	}
	result = types.BlkioStats{
		IoServiceBytesRecursive: copyBlkioEntry(blkio.IoServiceBytesRecursive),
		IoServicedRecursive:     copyBlkioEntry(blkio.IoServicedRecursive),
		IoQueuedRecursive:       copyBlkioEntry(blkio.IoQueuedRecursive),
		IoServiceTimeRecursive:  copyBlkioEntry(blkio.IoServiceTimeRecursive),
		IoWaitTimeRecursive:     copyBlkioEntry(blkio.IoWaitTimeRecursive),
		IoMergedRecursive:       copyBlkioEntry(blkio.IoMergedRecursive),
		IoTimeRecursive:         copyBlkioEntry(blkio.IoTimeRecursive),
		SectorsRecursive:        copyBlkioEntry(blkio.SectorsRecursive),
	}
	return result
}
func translateToTypesBlkioV1(blkio *v11.BlkIOStat) types.BlkioStats {
	var result types.BlkioStats
	if blkio == nil {
		return result
	}
	result = types.BlkioStats{
		IoServiceBytesRecursive: copyBlkioEntryV1(blkio.IoServiceBytesRecursive),
		IoServicedRecursive:     copyBlkioEntryV1(blkio.IoServicedRecursive),
		IoQueuedRecursive:       copyBlkioEntryV1(blkio.IoQueuedRecursive),
		IoServiceTimeRecursive:  copyBlkioEntryV1(blkio.IoServiceTimeRecursive),
		IoWaitTimeRecursive:     copyBlkioEntryV1(blkio.IoWaitTimeRecursive),
		IoMergedRecursive:       copyBlkioEntryV1(blkio.IoMergedRecursive),
		IoTimeRecursive:         copyBlkioEntryV1(blkio.IoTimeRecursive),
		SectorsRecursive:        copyBlkioEntryV1(blkio.SectorsRecursive),
	}
	return result
}

func copyBlkioEntry(entries []*statsV1.BlkIOEntry) []types.BlkioStatEntry {
	out := make([]types.BlkioStatEntry, len(entries))
	for i, re := range entries {
		out[i] = types.BlkioStatEntry{
			Major: re.Major,
			Minor: re.Minor,
			Op:    re.Op,
			Value: re.Value,
		}
	}
	return out
}
func copyBlkioEntryV1(entries []*v11.BlkIOEntry) []types.BlkioStatEntry {
	out := make([]types.BlkioStatEntry, len(entries))
	for i, re := range entries {
		out[i] = types.BlkioStatEntry{
			Major: re.Major,
			Minor: re.Minor,
			Op:    re.Op,
			Value: re.Value,
		}
	}
	return out
}

func calculateIO(Io *v2.IOStat) (iTotal uint64, oTotal uint64) {
	if Io == nil {
		return
	}
	for _, en := range Io.Usage {
		iTotal += en.Rbytes
		oTotal += en.Wbytes
	}
	return
}
