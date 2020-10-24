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

type ID struct {
	Namespace     string
	PodName       string
	PodUID        string
	PodLabels     map[string]string
	ContainerID   string
	ContainerName string
	ProcessPID    int
	DockerPID     int
	Syscall       string
}

func (ku KubernetesUtil) LookupPod(dockerPID int, pid int, syscall string) (*ID, error) {
	cid, kid, err := ku.LookupDockerContainerID(dockerPID, pid)
	fmt.Println(cid)
	fmt.Println(kid)
	if err != nil {
		return nil, err
	}

	if cid == "" && kid == "" {
		return &ID{
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

	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, item := range pods.Items {
		if kid != "" {
			if kid == string(item.ObjectMeta.UID) {
				return &ID{
					Namespace:     item.ObjectMeta.Namespace,
					PodName:       item.ObjectMeta.Name,
					PodUID:        string(item.ObjectMeta.UID),
					PodLabels:     item.ObjectMeta.Labels,
					ContainerID:   cid,
					ContainerName: "",
					DockerPID:     dockerPID,
					ProcessPID:    pid,
					Syscall:       syscall,
				}, nil
			}
		}
		for _, status := range item.Status.ContainerStatuses {
			if status.ContainerID == "docker://"+cid {
				return &ID{
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
	return &ID{
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

func (ku KubernetesUtil) LookupDockerContainerID(dockerPID int, pid int) (string, string, error) {
	cid, kid, err := ku.containerCache.Get(dockerPID)
	fmt.Println("ERROR")
	fmt.Println(err)
	fmt.Println(cid)
	fmt.Println(kid)
	if err == nil {
		return cid, kid, nil
	}

	f, err := os.Open(fmt.Sprintf("/host/proc/%d/cpuset", pid))
	if err != nil {
		// this is normal, it just means the PID no longer exists
		return "", "", nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			return parts[2], parts[1], nil
		}
		parts = kubePattern.FindStringSubmatch(line)
		if parts != nil {
			return parts[2], parts[1], nil
		}
	}
	return "", "", nil
}

var (
	// 	kubePattern   = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	// 	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
	kubePattern   = regexp.MustCompile(`/kubepods/[^/]+/pod([^/]+)/([0-9a-f]{64})`)
	dockerPattern = regexp.MustCompile(`/docker/pod([^/]+)/([0-9a-f]{64})`)
)
