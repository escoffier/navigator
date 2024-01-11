package metrics

import (
	"encoding/json"
	"github.com/containerd/cgroups"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/security-rd/go-pkg/logging"
	cri "k8s.io/cri-api/pkg/apis"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var cgroupRoot = "/host/sys/fs/cgroup/"
var procRoot = "/host/proc"

type crioMetrics struct {
	client     cri.RuntimeService
	appLabels  []string
	self       *heartbeat.SelfInfo
	cgroupMode cgroups.CGMode
}

func NewcrioClient(sf *heartbeat.SelfInfo, labels []string) (*crioMetrics, error) {
	if sf == nil {
		return nil, errors.New("selfInfo is empty")
	}
	var crioImpl crioMetrics
	uri := os.Getenv("CRIO_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/crio/crio.sock"
	}
	runClient, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteRuntimeService failed, %v", err)
	}
	// cgroupMode
	crioImpl.cgroupMode = cgroups.Mode()
	crioImpl.client = runClient
	crioImpl.appLabels = labels
	crioImpl.self = sf
	return &crioImpl, nil
}

func (d *crioMetrics) Metrics() (heartbeat.DataTypeConMetricsInNode, error) {
	return d.getMetricsByAppLabels(d.appLabels)
}

func (d *crioMetrics) GetMetricsByAppLabel(appLabel string) (heartbeat.DataTypeConMetricsInNode, error) {
	return d.getMetricsByAppLabels([]string{appLabel})
}

func (d *crioMetrics) getMetricsByAppLabels(appLabels []string) (heartbeat.DataTypeConMetricsInNode, error) {
	containers, err := d.client.ListContainers(&runtimeapi.ContainerFilter{
		State: &runtimeapi.ContainerStateValue{
			State: runtimeapi.ContainerState_CONTAINER_RUNNING,
		},
	})
	if err != nil {
		logging.Get().Err(err).Msg("crio ListContainers failed.")
		return heartbeat.DataTypeConMetricsInNode{}, err
	}
	now := time.Now()
	var result heartbeat.DataTypeConMetricsInNode
	for _, container := range containers {
		logging.Get().Info().Msg("containerId:" + container.Id)
		if container == nil {
			continue
		}
		_, info, err := d.getCrioContainerDetail(container.Id, true)
		if err != nil {
			logging.Get().Err(err).Msg("getCrioContainerDetail failed.")
			continue
		}
		if info == nil {
			logging.Get().Warn().Msgf("container info is nil")
			continue
		}
		appLabel, isMatch := IsMonitorAppLabel(appLabels, info.RuntimeSpec.Process.Env)
		if isMatch == false {
			continue
		}
		logging.Get().Info().Msgf("handler container appLabel:%s", appLabel)
		containerMetrics := heartbeat.ContainerMetric{
			SelfInfo: &heartbeat.SelfInfo{
				ClusterKey:    d.self.ClusterKey,
				NodeName:      d.self.NodeName,
				Version:       d.self.Version,
				Namespace:     d.self.Namespace,
				PodName:       container.Labels["io.kubernetes.pod.name"],
				ContainerName: container.Labels["io.kubernetes.container.name"],
				AppLabel:      appLabel,
			},
			MetricsInfo: &heartbeat.MetricsInfo{CollectTime: now},
		}
		//limit
		if info.RuntimeSpec.Linux.Resources.Cpu.Quota > 0 && info.RuntimeSpec.Linux.Resources.Cpu.Period > 0 {
			containerMetrics.CpuLimit = float32(info.RuntimeSpec.Linux.Resources.Cpu.Quota) / float32(info.RuntimeSpec.Linux.Resources.Cpu.Period)
		}
		containerMetrics.MemLimit = uint64(info.RuntimeSpec.Linux.Resources.Memory.Limit)

		containerStats, err := d.client.ContainerStats(container.Id)
		if err != nil {
			logging.Get().Err(err).Msg("crio ListContainers failed.")
			continue
		}
		if containerStats == nil {
			logging.Get().Err(err).Msg("get contaienr's metrics is empty. containerId:" + container.Id)
			continue
		}
		// usage
		if containerStats.Cpu != nil && containerStats.Cpu.UsageCoreNanoSeconds != nil {
			containerMetrics.CpuStats = heartbeat.CpuStats{
				TotalUsage: containerStats.Cpu.UsageCoreNanoSeconds.GetValue() / 1000,
			}
		}
		if containerStats.Memory != nil {
			if containerStats.Memory.UsageBytes != nil {
				containerMetrics.MemUsage = containerStats.Memory.UsageBytes.GetValue()
			} else if containerStats.Memory.WorkingSetBytes != nil {
				containerMetrics.MemUsage = containerStats.Memory.WorkingSetBytes.GetValue()
			}
		}
		// block io
		cgroupPath := parseCgroupPath(info.RuntimeSpec.Linux.CgroupsPath)
		if strings.HasPrefix(cgroupPath, "kubepods-burstable") {
			cgroupPath = filepath.Join("kubepods-burstable.slice", cgroupPath)
		}
		logging.Get().Info().Msgf("cgroupPath:%s", cgroupPath)
		containerMetrics.BlockITotal, containerMetrics.BLockOTotal, err = d.getBlockIO(cgroupPath)
		if err != nil {
			logging.Get().Err(err).Msg("getCrioContainerDetail failed.")
		}
		result.ContainerMetricList = append(result.ContainerMetricList, &containerMetrics)
	}
	return result, nil
}

// kubepods-burstable-podb355056b_83f8_48c5_abd1_f9a39267a8d5.slice:crio:a6d05ff5331cbcdf31e21c68c9e44af06fc702943659288598b0000035bbb149
// kubepods-burstable-podb355056b_83f8_48c5_abd1_f9a39267a8d5.slice/crio-a6d05ff5331cbcdf31e21c68c9e44af06fc702943659288598b0000035bbb149.scope

func parseCgroupPath(path string) (replace string) {
	replace = strings.Replace(path, ":", "/", 1)
	replace = strings.Replace(replace, ":", "-", 1)
	if !strings.HasSuffix(replace, ".scope") {
		replace += ".scope"
	}
	return
}

func (d *crioMetrics) getCrioContainerDetail(containerId string, verbose bool) (*runtimeapi.ContainerStatus, *ContainerInfo, error) {
	containerStatusResponse, err := d.client.ContainerStatus(containerId, verbose)
	if err != nil {
		logging.Get().Err(err).Msg("get ContainerStatus failed.")
		return nil, nil, err
	}

	containerInfo := &ContainerInfo{}
	if verbose {
		err = json.Unmarshal([]byte(containerStatusResponse.Info["info"]), containerInfo)
		if err != nil {
			logging.Get().Err(err).Msg("json unmarshal containerInfoMap failed.")
			return nil, nil, err
		}
	}
	return containerStatusResponse.Status, containerInfo, nil
}

func (d *crioMetrics) getBlockIO(cgroupPath string) (readTotal uint64, writeTotal uint64, err error) {

	if d.cgroupMode == cgroups.Unified {
		// cgroup v2  /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice
		ioStats := readIoStats(filepath.Join(cgroupRoot, "/kubepods.slice/", cgroupPath))
		marshal, _ := json.Marshal(ioStats)
		logging.Get().Info().Msgf("v2 blockio:%s", string(marshal))
		for _, stat := range ioStats {
			if stat.Major != 0 && stat.Minor != 0 {
				readTotal = stat.Rbytes
				writeTotal = stat.Wbytes
				break
			}
		}
	} else {
		// cgroup v1
		blkio := NewBlkio(filepath.Join(cgroupRoot, "blkio/kubepods.slice/"), procRoot)
		blkIOStat, err := blkio.Stat(cgroupPath)
		if err != nil {
			return 0, 0, err
		}
		marshal, _ := json.Marshal(blkIOStat)
		logging.Get().Info().Msgf("v1 blockio:%s", string(marshal))

		for _, bioEntry := range blkIOStat.IoServiceBytesRecursive {
			if len(bioEntry.Op) == 0 {
				continue
			}
			switch bioEntry.Op[0] {
			case 'r', 'R':
				readTotal = readTotal + bioEntry.Value
			case 'w', 'W':
				writeTotal = writeTotal + bioEntry.Value
			}
		}
	}
	return
}

// field may not full
type ContainerInfo struct {
	Pid         int         `json:"pid"`
	Privileged  bool        `json:"privileged"`
	RuntimeSpec RuntimeSpec `json:"runtimeSpec"`
	SandboxID   string      `json:"sandboxID"`
}
type RuntimeSpec struct {
	Annotations map[string]string `json:"annotations"`
	Hostname    string            `json:"hostname"`
	Linux       struct {
		CgroupsPath string   `json:"cgroupsPath"`
		MaskedPaths []string `json:"maskedPaths"`
		Namespaces  []struct {
			Type string `json:"type"`
			Path string `json:"path,omitempty"`
		} `json:"namespaces"`
		ReadonlyPaths []string `json:"readonlyPaths"`
		Resources     struct {
			Cpu struct {
				Period int `json:"period"`
				Quota  int `json:"quota"`
				Shares int `json:"shares"`
			} `json:"cpu"`
			Memory struct {
				Limit int `json:"limit"`
				Swap  int `json:"swap"`
			} `json:"memory"`
			Devices []struct {
				Access string `json:"access"`
				Allow  bool   `json:"allow"`
			} `json:"devices"`
			HugepageLimits []struct {
				Limit    int    `json:"limit"`
				PageSize string `json:"pageSize"`
			} `json:"hugepageLimits"`
			Pids struct {
				Limit int `json:"limit"`
			} `json:"pids"`
		} `json:"resources"`
	} `json:"linux"`
	Mounts []struct {
		Destination string   `json:"destination"`
		Options     []string `json:"options"`
		Source      string   `json:"source"`
		Type        string   `json:"type"`
	} `json:"mounts"`
	OciVersion string `json:"ociVersion"`
	Process    struct {
		Args         []string `json:"args"`
		Capabilities struct {
			Bounding    []string `json:"bounding"`
			Effective   []string `json:"effective"`
			Inheritable []string `json:"inheritable"`
			Permitted   []string `json:"permitted"`
		} `json:"capabilities"`
		Cwd         string   `json:"cwd"`
		Env         []string `json:"env"`
		OomScoreAdj int      `json:"oomScoreAdj"`
		User        struct {
			Gid int `json:"gid"`
			Uid int `json:"uid"`
		} `json:"user"`
	} `json:"process"`
	Root struct {
		Path string `json:"path"`
	} `json:"root"`
}
