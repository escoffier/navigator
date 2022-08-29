package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	instance  *TensorContainerService
	rlOnce    sync.Once
	nodeInfos = sync.Map{}
)

func InitContainersService(rdb *databases.RDBInstance, scannerURL string) error {
	rlOnce.Do(func() {
		instance = newTensorContainersService(rdb, scannerURL)
		instance.loopGetNodeInfo()
	})
	return nil
}

func GetContainersService(_ context.Context) (*TensorContainerService, bool) {
	return instance, instance != nil
}

type TensorContainerService struct {
	rdb        *databases.RDBInstance
	scannerURL string
}

type NodeInfo struct {
	NodeOS string
}

func newTensorContainersService(rdb *databases.RDBInstance, scannerURL string) *TensorContainerService {
	return &TensorContainerService{
		rdb:        rdb,
		scannerURL: scannerURL,
	}
}

func (s *TensorContainerService) loopGetNodeInfo() {
	wait.PollImmediateInfinite(time.Second*60, func() (done bool, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		nodes, err := dal.GetNodes(ctx, s.rdb.GetReadDB(), dal.NodeQuery(), -1, -1)
		if err != nil {
			logging.Get().Err(err).Msgf("get nodes error")
			return false, nil
		}
		for i := range nodes {
			nodeInfos.Store(nodes[i].HostName, nodes[i].OsInfo)
		}
		return true, nil
	})
}
func (s *TensorContainerService) GetContainerInfo(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offsetID int64, offset int, limit int) ([]*assets.ContainerInfo, int64, error) {
	containers, err := dal.GetContainerRelation(ctx, s.rdb.GetReadDB(), queryOptions, offsetID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	totalCnt, err := dal.CountContainerRelation(ctx, s.rdb.GetReadDB(), queryOptions)

	imageRisks, err := s.getImageOverviewFromScanner(ctx, containers)
	if err != nil {
		return nil, 0, err
	}
	registryRisks, err := s.getRegistryRiskFromScanner(ctx, containers)
	if err != nil {
		return nil, 0, err
	}

	var cnts []*assets.ContainerInfo
	for i := range containers {
		var cntInfo = &assets.ContainerInfo{}
		cnts = append(cnts, cntInfo)

		cntInfo.ClusterKey = containers[i].ClusterKey
		cntInfo.Namespace = containers[i].Namespace
		cntInfo.ContainerID = containers[i].ContainerID
		cntInfo.ID = containers[i].ID
		cntInfo.Name = containers[i].Name
		cntInfo.Status = containers[i].Status
		cntInfo.CreatedAt = containers[i].CreatedAt
		cntInfo.UpdatedAt = containers[i].UpdatedAt
		cntInfo.PodIP = containers[i].PodIP
		cntInfo.PodUID = containers[i].PodUID
		cntInfo.PodName = containers[i].PodName
		cntInfo.NodeIP = containers[i].HostIP
		cntInfo.Image = containers[i].Image
		cntInfo.Library = containers[i].Library
		cntInfo.Environment = containers[i].Environment
		cntInfo.Cmd = containers[i].Cmd
		cntInfo.Arguments = containers[i].Arguments
		cntInfo.Privileged = containers[i].Privileged
		cntInfo.HostNetwork = containers[i].HostNetwork
		imageUUID := util.ImageUUID(containers[i].Library + "/" + containers[i].Image)
		cntInfo.ImageRiskInfo = imageRisks[imageUUID]
		cntInfo.RegistryRiskInfo = registryRisks[containers[i].Library]
		cntInfo.ContainerInfo = containers[i].ContainerInfo
		v, ok := nodeInfos.Load(containers[i].NodeName)
		if ok {
			cntInfo.NodeOS = v.(string)
		}
		cntInfo.PoolUID = containers[i].PoolUID
		cntInfo.PoolName = containers[i].PoolName
		cntInfo.PoolPodUID = containers[i].PoolPodUID
		cntInfo.PoolPodName = containers[i].PoolPodName
		cntInfo.OffsetID = containers[i].TimeStamp
	}

	return cnts, totalCnt, nil
}

func (s *TensorContainerService) CountContainerInfo(ctx context.Context, queryOptions *dal.ResContainersQueryOption) (int64, error) {
	return dal.CountContainerRelation(ctx, s.rdb.GetReadDB(), queryOptions)
}

func (s *TensorContainerService) getImageOverviewFromScanner(ctx context.Context, tcs []*model.TensorContainerRelation) (map[uint32]*assets.ImageRiskOverview, error) {
	var uuids []uint32
	for _, c := range tcs {
		id := util.ImageUUID(c.Library + "/" + c.Image)
		uuids = append(uuids, id)
	}
	uuids = getUniqueUUIDs(uuids)

	url := fmt.Sprintf("%s%s", s.scannerURL, assets.ImageRiskPath)
	logging.Get().Debug().Msgf("url: %s", url)

	data := map[string][]uint32{"uuids": uuids}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	logging.Get().Debug().Msgf("request boyd: %s", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil, err
	}
	var imageRisks = make(map[uint32]*assets.ImageRiskOverview, len(tcs))
	var items []*assets.ImageRiskOverview
	err = util.HTTPRequest(ctx, httputil.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}
		if resp.StatusCode >= http.StatusBadRequest {
			body, _ := ioutil.ReadAll(resp.Body)
			return fmt.Errorf("request err: %d, detail: %s", resp.StatusCode, body)
		}

		if resp.Body == nil {
			return fmt.Errorf("reponse body is empty")
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			logging.Get().Err(err).Msgf("message format err: %s", body)
			return err
		}
		if len(rawResp.Data.Items) > 0 {
			err = json.Unmarshal(rawResp.Data.Items, &items)
			if err != nil {
				logging.Get().Err(err).Msgf("message item format err: %s", rawResp.Data.Items)
				return err
			}
			for _, item := range items {
				imageRisks[item.Uuid] = item
				logging.Get().Debug().Msgf("%+v", *item)
			}
		}
		return nil
	})
	if err != nil {
		logging.Get().Err(err).Msg("get image risk from scanner err")
		return nil, err
	}

	return imageRisks, nil
}

func (s *TensorContainerService) getRegistryRiskFromScanner(ctx context.Context, tcs []*model.TensorContainerRelation) (map[string]*assets.RegistryRisks, error) {
	var libraries []string
	for _, c := range tcs {
		newUrl, err := fullUrl(c.Library)
		if err != nil {
			logging.Get().Warn().Msgf("invalid image path: %s", newUrl)
			continue
		}
		libraries = append(libraries, newUrl)
	}
	libraries = getUniqueUrls(libraries)

	url := fmt.Sprintf("%s%s", s.scannerURL, assets.RegistryRiskPath)
	logging.Get().Debug().Msgf("url: %s", url)
	data := map[string][]string{"libraries": libraries}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	logging.Get().Debug().Msgf("request boyd: %s", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil, err
	}
	var imageRisks = make(map[string]*assets.RegistryRisks, len(tcs))
	var items []*assets.RegistryRisks
	err = util.HTTPRequest(ctx, httputil.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}
		if resp.StatusCode >= http.StatusBadRequest {
			body, _ := ioutil.ReadAll(resp.Body)
			return fmt.Errorf("request err: %d, detail: %s", resp.StatusCode, body)
		}

		if resp.Body == nil {
			return fmt.Errorf("reponse body is empty")
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			logging.Get().Err(err).Msgf("message format err: %s", body)
			return err
		}
		if len(rawResp.Data.Items) > 0 {
			err = json.Unmarshal(rawResp.Data.Items, &items)
			if err != nil {
				logging.Get().Err(err).Msgf("message item format err: %s", rawResp.Data.Items)
				return err
			}
			for _, item := range items {
				library := strings.TrimPrefix(item.RegistryUrl, "https://")
				imageRisks[library] = item
				logging.Get().Debug().Msgf("%+v", *item)
			}
		}
		return nil
	})
	if err != nil {
		logging.Get().Err(err).Msg("get registry risk from scanner err")
		return nil, err
	}

	return imageRisks, nil
}

func getUniqueUUIDs(uids []uint32) []uint32 {
	set := make(map[uint32]struct{}, len(uids))
	j := 0
	for _, uid := range uids {
		_, ok := set[uid]
		if ok {
			continue
		}
		set[uid] = struct{}{}
		uids[j] = uid
		j++
	}
	return uids[:j]
}
func getUniqueUrls(urls []string) []string {
	set := make(map[string]struct{}, len(urls))
	j := 0
	for _, url := range urls {
		if url == "" {
			continue
		}
		_, ok := set[url]
		if ok {
			continue
		}
		set[url] = struct{}{}
		urls[j] = url
		j++
	}
	return urls[:j]
}

func getImageUrl(image string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", err
	}
	url := ref.Context().RegistryStr()
	return url, nil
}

func fullUrl(rawUrl string) (string, error) {
	newUrl := rawUrl
	u, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		newUrl = "https://" + rawUrl
	}
	return newUrl, nil
}
