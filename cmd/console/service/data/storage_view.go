package data

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/mozilla/tls-observatory/logger"
	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func (s *Service) GetStorageView(_ context.Context, dataType string) (*model.StorageView, error) {
	switch dataType {
	case model.DataTypeCold:
		return s.GetColdStorageView()
	case model.DataTypeHotLogic:
		return s.GetLogicHotStorageView()
	case model.DataTypeHotOffline:
		return s.GetOfflineHotStorageView()
	default:
		return nil, def.ErrInvalidDataType
	}
}

func (s *Service) GetLogicHotStorageView() (*model.StorageView, error) {
	mongoHotStorageView, err := s.getStorageView(s.mongoPod)
	if err != nil {
		return nil, err
	}

	postgreHotStorageView, err := s.getStorageView(s.postgrePod)
	if err != nil {
		return nil, err
	}

	return &model.StorageView{
		Total: mongoHotStorageView.Total + postgreHotStorageView.Total,
		Used:  mongoHotStorageView.Used + postgreHotStorageView.Used}, nil
}

func (s *Service) GetOfflineHotStorageView() (*model.StorageView, error) {
	return s.getStorageView(s.esPod)
}

func (s *Service) GetColdStorageView() (*model.StorageView, error) {
	return s.getStorageView(s.auditPod)
}

func (s *Service) getStorageView(pod *PodInfo) (*model.StorageView, error) {
	if pod == nil {
		return nil, fmt.Errorf("not support storage view")
	}
	logger.GetLogger().Debugf("getStorageView pod:%+v", pod)
	kubeClient, restConfig, err := k8s.KubeClientFromServiceAccoount()

	if err != nil || kubeClient == nil || restConfig == nil {
		return nil, fmt.Errorf("k8s is not ready")
	}

	namespace := getNamespace()
	api := kubeClient.CoreV1()
	pvc, err := api.PersistentVolumeClaims(namespace).Get(pod.PVC, metaV1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("couldn't get pvc: %w", err)
	}

	resourceStorage := pvc.Spec.Resources.Requests[coreV1.ResourceStorage]
	storageView := &model.StorageView{}
	storageView.Total = resourceStorage.Value()

	cmd := []string{
		"sh",
		"-c",
		fmt.Sprintf("du -sk %s", pod.DataPath),
	}

	option := &coreV1.PodExecOptions{
		Command: cmd,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req := kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod.Pod).
		Namespace(namespace).SubResource("exec").
		VersionedParams(option, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("cannot get kube executor: %w", err)
	}
	var stdOutBuf bytes.Buffer
	var stdErrBuf bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdOutBuf,
		Stderr: &stdErrBuf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to kube execute command: %w", err)
	}

	stdOut := strings.Fields(stdOutBuf.String())
	if len(stdOut) == 0 {
		return nil, fmt.Errorf("unxpected stdOut: %s", stdOutBuf.String())
	}

	usedMem, err := strconv.ParseInt(stdOut[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to get pvc used disk space: %w", err)
	}
	storageView.Used = usedMem * 1024

	return storageView, nil
}
