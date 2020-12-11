package kuberneteshelper

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	gocache "github.com/patrickmn/go-cache"
)

var (
	// pattern found on microk8s
	kubePattern = regexp.MustCompile(`/kubepods/[^/]+/pod([^/]+)/([0-9a-f]{64})`)
	// E.g. cgroup hierarchy: https://github.com/kubernetes/kubernetes/issues/62896
	// kubelet cgroup v1 schema - guaranteed QoS
	kubePatternCgroupV1Guaranteed = regexp.MustCompile(`/kubepods\.slice/kubepods-[^-]+-pod([^/]+)\.slice/docker-([0-9a-f]{64})`)
	// kubelet cgroup v1 schema - burstable and besteffort QoS
	kubePatternCgroupV1 = regexp.MustCompile(`/kubepods\.slice/[^/]+/kubepods-[^-]+-pod([^/]+)\.slice/docker-([0-9a-f]{64})`)
	// docker pattern
	dockerPattern = regexp.MustCompile(`/docker/pod([^/]+)/([0-9a-f]{64})`)
	// TODO: different cgroup schema: https://stackoverflow.com/questions/49035724/how-do-i-resolve-kubepods-besteffort-poduuid-to-a-pod-name
)

type KubernetesUtil struct {
	containerCache ContainerCache
}

func NewKubernetesUtil() KubernetesUtil {
	return KubernetesUtil{
		NewContainerCache(),
	}
}

func (cu KubernetesUtil) Init() error {
	return cu.containerCache.Init()
}

type SyscallContext struct {
	Namespace     string            `json:"namespace"`
	PodName       string            `json:"podName"`
	PodUID        string            `json:"podUID"`
	PodLabels     map[string]string `json:"podLabels"`
	ContainerID   string            `json:"containerId"`
	ContainerName string            `json:"containerName"`
	ProcessPID    int               `json:"processPid"`
	DockerPID     int               `json:"dockerPid"`
	Syscall       string            `json:"syscall"`
}

func (ku KubernetesUtil) LookupPod(clusterCache *gocache.Cache, dockerPID int, pid int, syscall string) (*SyscallContext, error) {
	cid, kid, err := ku.LookupDockerPodID(dockerPID, pid)
	if err != nil {
		return nil, err
	}

	if cid == "" && kid == "" {
		logging.GetLogger().Debug().Msg("Not found k8s context for given syscall")
		return &SyscallContext{
			Namespace:     "",
			PodName:       "",
			PodUID:        "",
			PodLabels:     map[string]string{},
			ContainerID:   "",
			ContainerName: "",
			DockerPID:     -1,
			ProcessPID:    pid,
			Syscall:       syscall,
		}, fmt.Errorf("Not found k8s context for given syscall")
	}

	logging.GetLogger().Debug().Msg("Finding corresponding pod")

	x, found := clusterCache.Get("docker://" + cid)
	if found {
		logging.GetLogger().Debug().Str("container", cid).Msg("Found docker in k8s\n")
		kubeSelectedInfo := x.(*KubeSelectedInfo)
		return &SyscallContext{
			Namespace:     kubeSelectedInfo.Namespace,
			PodName:       kubeSelectedInfo.PodName,
			PodUID:        kubeSelectedInfo.PodUID,
			PodLabels:     kubeSelectedInfo.PodLabels,
			ContainerID:   cid,
			ContainerName: kubeSelectedInfo.ContainerName,
			DockerPID:     dockerPID,
			ProcessPID:    pid,
			Syscall:       syscall,
		}, nil
	}
	x, found = clusterCache.Get("containerd://" + cid)
	if found {
		logging.GetLogger().Debug().Str("container", cid).Msg("Found docker in k8s\n")
		kubeSelectedInfo := x.(*KubeSelectedInfo)
		return &SyscallContext{
			Namespace:     kubeSelectedInfo.Namespace,
			PodName:       kubeSelectedInfo.PodName,
			PodUID:        kubeSelectedInfo.PodUID,
			PodLabels:     kubeSelectedInfo.PodLabels,
			ContainerID:   cid,
			ContainerName: kubeSelectedInfo.ContainerName,
			DockerPID:     dockerPID,
			ProcessPID:    pid,
			Syscall:       syscall,
		}, nil
	}
	logging.GetLogger().Debug().Str("pod", kid).Str("container", cid).Msg("Cached pod and container doesn't exist in the cluster anymore\n")
	return &SyscallContext{
		Namespace:     "",
		PodName:       "",
		PodUID:        "",
		PodLabels:     map[string]string{},
		ContainerName: "",
		ContainerID:   cid,
		DockerPID:     dockerPID,
		ProcessPID:    pid,
		Syscall:       syscall,
	}, nil
}

func (ku KubernetesUtil) LookupDockerPodID(dockerPID int, pid int) (string, string, error) {
	cid, kid, err := ku.containerCache.Get(dockerPID)
	if err == nil {
		return cid, kid, nil
	}

	f, err := os.Open(fmt.Sprintf("/host/proc/%d/cpuset", pid))
	if err != nil {
		return "", "", fmt.Errorf("Process %d no longer exists", pid)
	}
	defer f.Close()

	logging.GetLogger().Debug().Int("pid", pid).Msg("Scanning cpuset")
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		logging.GetLogger().Debug().Str("line", line).Msg("Currently scanned line")
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			logging.GetLogger().Debug().Int("pid", pid).Str("pattern", dockerPattern.String()).Msg("Found match")
			logging.GetLogger().Debug().Str("cid", parts[2]).Str("kid", parts[1]).Msg("Match")
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		logging.GetLogger().Debug().Str("pattern", dockerPattern.String()).Msg("Match not found")
		parts = kubePattern.FindStringSubmatch(line)
		if parts != nil {
			logging.GetLogger().Debug().Int("pid", pid).Str("pattern", kubePattern.String()).Msg("Found match")
			logging.GetLogger().Debug().Str("cid", parts[2]).Str("kid", parts[1]).Msg("Match")
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		logging.GetLogger().Debug().Str("pattern", kubePattern.String()).Msg("Match not found")
		parts = kubePatternCgroupV1.FindStringSubmatch(line)
		if parts != nil {
			logging.GetLogger().Debug().Int("pid", pid).Str("pattern", kubePatternCgroupV1.String()).Msg("Found match")
			logging.GetLogger().Debug().Str("cid", parts[2]).Str("kid", parts[1]).Msg("Match")
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		logging.GetLogger().Debug().Str("pattern", kubePatternCgroupV1.String()).Msg("Match not found")
		parts = kubePatternCgroupV1Guaranteed.FindStringSubmatch(line)
		if parts != nil {
			logging.GetLogger().Debug().Int("pid", pid).Str("pattern", kubePatternCgroupV1Guaranteed.String()).Msg("Found match")
			logging.GetLogger().Debug().Str("cid", parts[2]).Str("kid", parts[1]).Msg("Match")
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		logging.GetLogger().Debug().Str("pattern", kubePatternCgroupV1Guaranteed.String()).Msg("Match not found")
	}
	logging.GetLogger().Debug().Int("pid", pid).Msg("No match in its cpuset")
	return "", "", nil
}
