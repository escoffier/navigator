package data

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (s *Service) GetStorageView(ctx context.Context, dataType string) (*model.StorageView, error) {
	switch dataType {
	case model.DataTypeCold:
		return s.GetColdStorageView(ctx)
	case model.DataTypeHotLogic:
		return s.GetLogicHotStorageView(ctx)
	case model.DataTypeHotOffline:
		return s.GetOfflineHotStorageView(ctx)
	default:
		return nil, def.ErrInvalidDataType
	}
}

func (s *Service) GetLogicHotStorageView(ctx context.Context) (*model.StorageView, error) {
	postgreHotStorageView, err := s.getStorageView(ctx, s.rdbPod)
	if err != nil {
		return nil, err
	}

	return &model.StorageView{
		Total: postgreHotStorageView.Total,
		Used:  postgreHotStorageView.Used}, nil
}

func (s *Service) GetOfflineHotStorageView(ctx context.Context) (*model.StorageView, error) {
	return s.getStorageView(ctx, s.esPod)
}

func (s *Service) GetColdStorageView(_ context.Context) (*model.StorageView, error) {
	// TODO just for test
	const (
		total = 50 * 1024 * 1024 * 1024
		used  = 50 * 1024 * 1024
	)
	return &model.StorageView{
		Total: total,
		Used:  used,
	}, nil
}

func (s *Service) getStorageView(ctx context.Context, pod *PodInfo) (*model.StorageView, error) {
	if pod == nil {
		return nil, fmt.Errorf("not support storage view")
	}
	logging.Get().Debug().Msgf("getStorageView pod:%+v", pod)
	kubeClient, restConfig, err := k8s.KubeClientFromServiceAccoount()

	if err != nil || kubeClient == nil || restConfig == nil {
		return nil, fmt.Errorf("k8s is not ready")
	}

	storageView := &model.StorageView{}
	namespace := getNamespace()
	api := kubeClient.CoreV1()
	pvc, err := api.PersistentVolumeClaims(namespace).Get(ctx, pod.PVC, metaV1.GetOptions{})
	if err != nil {
		logging.Get().Error().Err(err).Msg("couldn't get pvc")
		return storageView, nil
	}

	resourceStorage := pvc.Spec.Resources.Requests[coreV1.ResourceStorage]
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
	if pod.Container != "" {
		req = req.Param("container", pod.Container)
	}
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		logging.Get().Error().Err(err).Msg("cannot get kube executor")
		return storageView, nil
	}
	var stdOutBuf bytes.Buffer
	var stdErrBuf bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdOutBuf,
		Stderr: &stdErrBuf,
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("failed to kube execute command")
		return storageView, nil
	}

	stdOut := strings.Fields(stdOutBuf.String())
	if len(stdOut) == 0 {
		logging.Get().Error().Err(fmt.Errorf("unxpected stdOut: %s", stdOutBuf.String())).Msg("")
		return storageView, nil
	}

	usedMem, err := strconv.ParseInt(stdOut[0], 10, 64)
	if err != nil {
		logging.Get().Error().Err(err).Msg("failed to get pvc used disk space")
		return storageView, nil
	}
	storageView.Used = usedMem * 1024

	return storageView, nil
}
