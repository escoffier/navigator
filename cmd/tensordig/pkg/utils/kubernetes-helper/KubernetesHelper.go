package kuberneteshelper

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	// 	kubePattern   = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	// 	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
	kubePattern   = regexp.MustCompile(`/kubepods/[^/]+/pod([^/]+)/([0-9a-f]{64})`)
	dockerPattern = regexp.MustCompile(`/docker/pod([^/]+)/([0-9a-f]{64})`)
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
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, item := range pods.Items {
		if kid != "" {
			if kid == string(item.ObjectMeta.UID) {
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
	// log.Infof("Cached pod %s and container %s don't exist in the cluster anymore\n", kid, cid)
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

	// log.Infof("Scanning %d cpuset", pid)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// log.Infof("Currently scanned line: %s", line)
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			// log.Infof("Found match for %d against %s", pid, dockerPattern)
			return parts[2], parts[1], nil
		}
		// log.Infof("Match not for against %s", dockerPattern)
		parts = kubePattern.FindStringSubmatch(line)
		if parts != nil {
			// log.Infof("Found match for %d against %s", pid, kubePattern)
			return parts[2], parts[1], nil
		}
		// log.Infof("Match not for against %s", kubePattern)
	}
	// log.Infof("No match for %d in its cpuset", pid)
	return "", "", nil
}
