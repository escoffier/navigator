package kuberneteshelper

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func (ku KubernetesUtil) LookupPod(dockerPID int, pid int, syscall string) (*SyscallContext, error) {
	cid, kid, err := ku.LookupDockerPodID(dockerPID, pid)
	if err != nil {
		return nil, err
	}

	if cid == "" && kid == "" {
		log.Info("Not found k8s context for given syscall")
		return &SyscallContext{
			Namespace:     "",
			PodName:       "",
			PodUID:        "",
			PodLabels:     map[string]string{},
			ContainerID:   cid,
			ContainerName: "",
			DockerPID:     -1,
			ProcessPID:    pid,
			Syscall:       syscall,
		}, nil
	}

	log.Info("Using incluster config")
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// TODO: filter by namespace?
	// TODO: use https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks and watch?
	log.Info("Searching for pod")
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	log.Info("Iterating over pods")
	for _, item := range pods.Items {
		log.Infof("Checking %s kid", item.ObjectMeta.UID)
		if kid != "" {
			if kid == string(item.ObjectMeta.UID) {
				log.Info("Matching UUID with the one in the process")
				for _, status := range item.Status.ContainerStatuses {
					log.Infof("Checking %s container", status.ContainerID)
					if status.ContainerID == "docker://"+cid || status.ContainerID == "containerd://"+cid {
						return &SyscallContext{
							Namespace:     item.ObjectMeta.Namespace,
							PodName:       item.ObjectMeta.Name,
							PodUID:        string(item.ObjectMeta.UID),
							PodLabels:     item.ObjectMeta.Labels,
							ContainerID:   cid,
							ContainerName: status.Name,
							DockerPID:     dockerPID,
							ProcessPID:    pid,
							Syscall:       syscall,
						}, nil
					}
				}
			}
		}
		for _, status := range item.Status.ContainerStatuses {
			if status.ContainerID == "docker://"+cid || status.ContainerID == "containerd://"+cid {
				return &SyscallContext{
					Namespace:     item.ObjectMeta.Namespace,
					PodName:       item.ObjectMeta.Name,
					PodUID:        string(item.ObjectMeta.UID),
					PodLabels:     item.ObjectMeta.Labels,
					ContainerID:   cid,
					ContainerName: status.Name,
					DockerPID:     dockerPID,
					ProcessPID:    pid,
					Syscall:       syscall,
				}, nil
			}
		}
	}
	log.Infof("Cached pod %s and container %s doesn't exist in the cluster anymore\n", kid, cid)
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

	log.Infof("Scanning %d cpuset", pid)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		log.Infof("Currently scanned line: %s", line)
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			log.Infof("Found match for %d against %s", pid, dockerPattern)
			log.Infof("Cid: %s, kid: %s", parts[2], parts[1])
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		log.Infof("Match not found against %s", dockerPattern)
		parts = kubePattern.FindStringSubmatch(line)
		if parts != nil {
			log.Infof("Found match for %d against %s", pid, kubePattern)
			log.Infof("Cid: %s, kid: %s", parts[2], parts[1])
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		log.Infof("Match not found against %s", kubePatternCgroupV1)
		parts = kubePatternCgroupV1.FindStringSubmatch(line)
		if parts != nil {
			log.Infof("Found match for %d against %s", pid, kubePatternCgroupV1)
			log.Infof("Cid: %s, kid: %s", parts[2], parts[1])
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		log.Infof("Match not found against %s", kubePatternCgroupV1Guaranteed)
		parts = kubePatternCgroupV1Guaranteed.FindStringSubmatch(line)
		if parts != nil {
			log.Infof("Found match for %d against %s", pid, kubePatternCgroupV1Guaranteed)
			log.Infof("Cid: %s, kid: %s", parts[2], parts[1])
			foundKid := strings.ReplaceAll(parts[1], "_", "-")
			ku.containerCache.Set(dockerPID, parts[2], foundKid)
			return parts[2], foundKid, nil
		}
		log.Infof("Match not found against %s", kubePatternCgroupV1Guaranteed)
	}
	log.Infof("No match for %d in its cpuset", pid)
	return "", "", nil
}
