package cleanup

import (
	"bytes"
	"fmt"
	"github.com/mozilla/tls-observatory/logger"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// OnKubeConfigUpdate should be called e.g. when cluster modified or added
// When cluster deleted, set kubeClient to nil.
func (s *Service) OnKubeConfigUpdate(newClient *kubernetes.Clientset, restConfig *rest.Config) {
	s.kubeClient.Store(newClient)
	s.restConfig.Store(restConfig)
}

func (s *Service) GetLogicHotStorageView() (*model.HotStorageView, error) {
	mongoHotStorageView, err := s.getHotStorageView(s.mongoPod)
	if err != nil {
		return nil, err
	}

	postgreHotStorageView, err := s.getHotStorageView(s.postgrePod)
	if err != nil {
		return nil, err
	}

	return &model.HotStorageView{
		Total: mongoHotStorageView.Total + postgreHotStorageView.Total,
		Used:  mongoHotStorageView.Used + postgreHotStorageView.Used}, nil
}

func (s *Service) GetOfflineHotStorageView() (*model.HotStorageView, error) {
	return s.getHotStorageView(s.esPod)
}

func (s *Service) getHotStorageView(pod *PodInfo) (*model.HotStorageView, error) {
	logger.GetLogger().Debugf("getHotStorageView pod:%+v", pod)
	kubeClient := s.kubeClient.Load().(*kubernetes.Clientset)
	restConfig := s.restConfig.Load().(*rest.Config)
	if kubeClient == nil || restConfig == nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("k8s is not ready"))
	}

	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	api := kubeClient.CoreV1()
	pvc, err := api.PersistentVolumeClaims(namespace).Get(pod.PVC, metav1.GetOptions{})
	if err != nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("couldn't get pvc: %w", err))
	}

	resourceStorage := pvc.Spec.Resources.Requests[v1.ResourceStorage]
	hotStorageView := &model.HotStorageView{}
	hotStorageView.Total = resourceStorage.Value()

	cmd := []string{
		"sh",
		"-c",
		fmt.Sprintf("du -sk %s", pod.DataPath),
	}

	req := kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod.Pod).
		Namespace(namespace).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req.VersionedParams(option, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("cannot get kube executor: %w", err))
	}
	var stdOutBuf bytes.Buffer
	var stdErrBuf bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdOutBuf,
		Stderr: &stdErrBuf,
	})
	if err != nil {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("failed to kube execute command: %w", err))
	}

	stdOut := strings.Fields(stdOutBuf.String())
	if len(stdOut) == 0 {
		return nil, apperror.NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("unxpected stdOut: %s", stdOutBuf.String()))
	}

	usedMem, err := strconv.ParseInt(stdOut[0], 10, 64)
	if err != nil {
		return nil, apperror.NewCannotGetDiskUsageError(http.StatusInternalServerError, fmt.Errorf("failed to get pvc used disk space: %w", err))
	}
	hotStorageView.Used = usedMem * 1024

	return hotStorageView, nil
}
