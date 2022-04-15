package podservice

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sync"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ErrInvalidCluster = errors.New("invalid cluster")
	ErrPodNotFound    = errors.New("pod not found")
	ErrInvalidURL     = errors.New("invalid url")
)

const (
	IsolatePath = "/api/v2/microseg/isolate"
	ReleasePath = "/api/v2/microseg/release"
)

type Service struct {
	clusterManager  *k8s.ClusterManager
	microSegBaseURL string
}

func NewService(clusterManager *k8s.ClusterManager, microSegBaseURL string) *Service {
	return &Service{
		clusterManager:  clusterManager,
		microSegBaseURL: microSegBaseURL,
	}
}

func (s *Service) CheckPodExist(ctx context.Context, pod *model.PodInfo) (bool, error) {
	k8sCli, exist := s.clusterManager.GetClient(pod.Cluster)
	if !exist {
		return false, nil
	}
	_, err := dal.GetPodInfoFromK8sClient(ctx, k8sCli.Clientset, pod.Namespace, pod.PodName)
	if err == nil {
		return true, nil
	} else if k8sErrors.IsNotFound(err) {
		return false, nil
	} else {
		return false, err
	}
}

type PodOpReq struct {
	Pods []*model.PodInfo `json:"pods"`
}

type PodOpRsp struct {
	ApiVersion string `json:"apiVersion"`
	Data       struct {
		LostPods     []*model.PodInfo `json:"lostPods"`
		PassedPods   []*model.PodInfo `json:"passedPods"`
		IsolatedPods []*model.PodInfo `json:"isolatedPods"`
	} `json:"data"`
}

func (s *Service) getRequestURL(relativePath string) (string, error) {
	u, err := url.Parse(s.microSegBaseURL)
	if err != nil {
		return "", ErrInvalidURL
	}
	u.Path = path.Join(u.Path, relativePath)
	return u.String(), nil
}

func (s *Service) IsolatePod(ctx context.Context, pods []*model.PodInfo) (successfulPods, isolatedPods, deletedPods []*model.PodInfo) {
	isolateURL, err := s.getRequestURL(IsolatePath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("getRequestURL fail, microSegBaseURL:%s", s.microSegBaseURL)
		return nil, nil, nil
	}

	rsp, err := s.sendRequestToMicroSeg(ctx, pods, isolateURL)
	if err != nil {
		logging.GetLogger().Err(err).Msg("sendRequestToMicroSeg fail")
		return nil, nil, nil
	}

	return rsp.Data.PassedPods, rsp.Data.IsolatedPods, rsp.Data.LostPods
}

func (s *Service) CancelIsolatePod(ctx context.Context, pods []*model.PodInfo) (successfulPods []*model.PodInfo) {
	isolateURL, err := s.getRequestURL(ReleasePath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("getRequestURL fail, microSegBaseURL:%s", s.microSegBaseURL)
		return nil
	}

	rsp, err := s.sendRequestToMicroSeg(ctx, pods, isolateURL)
	if err != nil {
		logging.GetLogger().Err(err).Msg("sendRequestToMicroSeg fail")
		return nil
	}

	return append(rsp.Data.PassedPods, rsp.Data.LostPods...)
}

func (s *Service) sendRequestToMicroSeg(ctx context.Context, pods []*model.PodInfo, url string) (*PodOpRsp, error) {
	jsonBytes, err := json.Marshal(&PodOpReq{Pods: pods})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(rsp.Body)
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	logging.GetLogger().Debug().Msgf("url:%s, req:%s, rsp:%s", url, string(jsonBytes), string(body))

	var result *PodOpRsp
	err = json.Unmarshal(body, &result)
	return result, err
}

func (s *Service) DeletePods(ctx context.Context, pods []*model.PodInfo) (successfulPods, notFoundPods []*model.PodInfo) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	for _, pod := range pods {
		wg.Add(1)
		go func(pod *model.PodInfo) {
			defer wg.Done()
			err := s.deletePod(ctx, pod)
			if err != nil {
				if err == ErrInvalidCluster || err == ErrPodNotFound {
					logging.GetLogger().Warn().Msgf("pod:%+v not exist", pod)
					lock.Lock()
					notFoundPods = append(notFoundPods, pod)
					lock.Unlock()
				} else {
					logging.GetLogger().Err(err).Msgf("delete pod:%+v fail", pod)
				}
			} else {
				lock.Lock()
				successfulPods = append(successfulPods, pod)
				lock.Unlock()
			}
		}(pod)
	}
	wg.Wait()
	return
}

func (s *Service) deletePod(ctx context.Context, pod *model.PodInfo) error {
	manager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("k8s cluster manager not init")
	}
	cli, ok := manager.GetClient(pod.Cluster)
	if !ok {
		return ErrInvalidCluster
	}

	err := cli.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.PodName, metav1.DeleteOptions{})
	if err != nil && isPodNotFoundErr(err) {
		return ErrPodNotFound
	}

	return err
}

const (
	podNotFoundErrRegex = "pods .* not found"
)

func isPodNotFoundErr(err error) bool {
	ok, _err := regexp.MatchString(podNotFoundErrRegex, err.Error())
	return _err == nil && ok
}
