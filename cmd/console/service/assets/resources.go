package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
)

const (
	ImageListPath = "/api/v1/scan/reportsByImageList"
)

var (
	instance *TensorResourcesService
	rlOnce   sync.Once
)

func InitResourcesService(rdb *databases.RDBInstance, scannerURL string) error {
	rlOnce.Do(func() {
		instance = newTensorResourcesService(rdb, scannerURL)
	})
	return nil
}

func GetResourcesService(_ context.Context) (*TensorResourcesService, bool) {
	return instance, instance != nil
}

type TensorResourcesService struct {
	rdb        *databases.RDBInstance
	scannerURL string
}

func newTensorResourcesService(rdb *databases.RDBInstance, scannerURL string) *TensorResourcesService {
	return &TensorResourcesService{
		rdb:        rdb,
		scannerURL: scannerURL,
	}
}

func (rl *TensorResourcesService) GetClusters(ctx context.Context, offset, limit int) ([]*model.TensorCluster, int64, error) {
	return dal.GetClusters(ctx, rl.rdb.GetReadDB(), offset, limit)
}

func (rl *TensorResourcesService) GetClusterByKey(ctx context.Context, key string) *model.TensorCluster {
	return dal.GetClustersByKey(ctx, rl.rdb.GetReadDB(), key)
}

func (rl *TensorResourcesService) AddCluster(ctx context.Context, cluster *model.TensorCluster) error {
	// TODO create the k8s client and so on
	return dal.AddCluster(ctx, rl.rdb.Get(), cluster)
}

func (rl *TensorResourcesService) UpdateCluster(ctx context.Context, clusterKey, newClusterName, newDescription string) error {
	return dal.UpdateCluster(ctx, rl.rdb.Get(), clusterKey, newClusterName, newDescription)
}

func (rl *TensorResourcesService) DeleteCluster(ctx context.Context, clusterKey string) error {
	return dal.DeleteCluster(ctx, rl.rdb.Get(), clusterKey)
}

func (rl *TensorResourcesService) GetResources(ctx context.Context, queryOptions *dal.ResourcesQueryOption, offset, limit int) ([]*model.TensorResource, int64, error) {
	resources, err := dal.GetResources(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	resCnt, err := dal.CountResources(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return resources, resCnt, nil
}

func (rl *TensorResourcesService) CountResource(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (int64, error) {
	resCnt, err := dal.CountResources(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return 0, err
	}

	return resCnt, nil
}

func (rl *TensorResourcesService) UpdateResourceUserData(ctx context.Context, res *model.TensorResource) error {
	return dal.UpdateResourceUserData(ctx, rl.rdb.Get(), res)
}

func (rl *TensorResourcesService) GetResourceMap(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (map[dal.ResourceKey]*model.TensorResource, error) {
	res, err := dal.GetResources(ctx, rl.rdb.Get(), queryOptions, -1, -1)
	if err != nil {
		return nil, err
	}

	resMap := make(map[dal.ResourceKey]*model.TensorResource)
	for _, r := range res {
		resMap[dal.ResourceKey{
			ClusterKey:   r.ClusterKey,
			Namespace:    r.Namespace,
			ResourceKind: r.Kind,
			ResourceName: r.Name,
		}] = r
	}
	return resMap, nil
}

func (rl *TensorResourcesService) GetNamespaces(ctx context.Context, clusterKey, nameQuery string, offset, limit int) ([]*model.TensorNamespace, int64, error) {
	ns, err := dal.GetNamespacesByCluster(ctx, rl.rdb.GetReadDB(), clusterKey, nameQuery, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountNamespaces(ctx, rl.rdb.GetReadDB(), clusterKey, nameQuery)
	if err != nil {
		return nil, 0, err
	}
	return ns, cnt, nil
}

func (rl *TensorResourcesService) CountNamespaces(ctx context.Context, clusterKey, nameQuery string) (int64, error) {
	cnt, err := dal.CountNamespaces(ctx, rl.rdb.GetReadDB(), clusterKey, nameQuery)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) UpdateNamespaces(ctx context.Context, clusterKey, name, alias string, manager []string, authority string) error {
	err := dal.UpdateNamespace(ctx, rl.rdb.Get(), clusterKey, name, alias, manager, authority)
	return err
}

func (rl *TensorResourcesService) GetResourcePods(ctx context.Context, queryOptions *dal.ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, int64, error) {
	pods, err := dal.GetResourcePodsList(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountPods(ctx, rl.rdb.GetReadDB(), queryOptions, 0, 0)
	return pods, cnt, err
}

func (rl *TensorResourcesService) CountPods(ctx context.Context, queryOptions *dal.ResPodsQueryOption) (int64, error) {
	cnt, err := dal.CountPods(ctx, rl.rdb.GetReadDB(), queryOptions, 0, -1)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) GetResourceContainers(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]*model.TensorContainer, int64, error) {
	containers, err := dal.GetResourceContainers(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	cnt, err := dal.CountResourceContainers(ctx, rl.rdb.GetReadDB(), queryOptions)
	return containers, cnt, err
}

func (rl *TensorResourcesService) CountContainer(ctx context.Context, queryOptions *dal.ResContainersQueryOption) (int64, error) {
	cnt, err := dal.CountResourceContainers(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) GetNodes(ctx context.Context, queryOptions *dal.NodeQueryOption, offset, limit int) ([]*model.TensorNode, error) {
	return dal.GetNodes(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountNodes(ctx context.Context, queryOptions *dal.NodeQueryOption) (int64, error) {
	return dal.CountNodes(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) GetImagesWithGivenVuln(ctx context.Context, vulnName string) ([]*model.ImageInfo, error) {
	return dal.GetImagesWithGivenVuln(ctx, rl.scannerURL, vulnName)
}

func getImageIDFrom(m *model.ImageInfo) string {
	lib := m.Library
	if strings.Index(m.Library, "http://") == 0 {
		lib = m.Library[7:]
	} else if strings.Index(m.Library, "https://") == 0 {
		lib = m.Library[8:]
	}
	return fmt.Sprintf("%s/%s:%s", lib, m.FullRepoName, m.Tags)
}
func (rl *TensorResourcesService) GetResourceContainersWithGivenVuln(ctx context.Context, vulnName string, offset, limit int) ([]*model.TensorContainer, int64, error) {
	images, err := rl.GetImagesWithGivenVuln(ctx, vulnName)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "GetImagesWithGivenVuln %s error", vulnName)
		return nil, 0, err
	}

	imageIDs := make([]string, 0, len(images))
	for _, image := range images {
		imageIDs = append(imageIDs, getImageIDFrom(image))
	}

	containers, totalCnt, err := rl.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithInConditionCustom("image", imageIDs), offset, limit)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "GetResourceContainers %s error. imageList: %v", vulnName, imageIDs)
		return nil, 0, err
	}

	return containers, totalCnt, nil
}

func (rl *TensorResourcesService) GetArguments(r *http.Request, dataType string) (*ArgumentDetails, error) {
	var arg ArgumentDetails

	arg.ClusterKey = chi.URLParam(r, "clusterKey")
	if arg.ClusterKey == "" {
		return nil, errors.Errorf("cluster key is error")
	}

	arg.Namespace = chi.URLParam(r, "namespace")
	if arg.Namespace == "" {
		return nil, errors.Errorf("namespace is error")
	}

	arg.ResourceName = chi.URLParam(r, "resourceName")
	if arg.ResourceName == "" {
		return nil, errors.Errorf("resourceName is error")
	}

	arg.ResourceKind = chi.URLParam(r, "resourceKind")
	if arg.ResourceKind == "" {
		return nil, errors.Errorf("resourceKind is error")
	}

	if dataType == "process_list" {
		return &arg, nil
	}

	arg.Route = chi.URLParam(r, "route")
	if arg.Route == "" {
		return nil, errors.Errorf("route is error")
	}

	if arg.Route != typeIngress && arg.Route != typeEgress {
		return nil, errors.Errorf("route is error, ingress or egress")
	}

	if dataType == "container" {
		arg.ContainerName = chi.URLParam(r, "containerName")
		if arg.ContainerName == "" {
			return nil, errors.Errorf("container name is error")
		}
	}

	if dataType == "process" {
		arg.ContainerName = chi.URLParam(r, "containerName")
		if arg.ContainerName == "" {
			return nil, errors.Errorf("container name is error")
		}

		arg.ProcessName = chi.URLParam(r, "processName")
		if arg.ProcessName == "" {
			return nil, errors.Errorf("process name is error")
		}
	}

	return &arg, nil
}

func (rl *TensorResourcesService) GetResourceRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_name = ? and dst_kind = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_name = ? and src_kind = ?"
	}

	netflows := make([]model.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]struct{})
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
		}
		res.DstPort = netflows[i].DstPort

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetContainerRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_name = ? and dst_kind = ? and dst_container_name = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_name = ? and src_kind = ? and src_container_name = ?"
	}

	netflows := make([]model.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerName).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]struct{})
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		if netflows[i].SrcContainerName == valueUnknown || netflows[i].DstContainerName == valueUnknown {
			continue
		}

		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.ContainerName = netflows[i].SrcContainerName
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerName = netflows[i].DstContainerName
		}
		res.DstPort = netflows[i].DstPort

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetProcessRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_name = ? and dst_kind = ? and dst_container_name = ? and dst_process = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_name = ? and src_kind = ? and src_container_name = ? and src_process = ?"
	}

	netflows := make([]model.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerName, arg.ProcessName).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]struct{})
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		if netflows[i].SrcProcess == valueUnknown || netflows[i].DstProcess == valueUnknown {
			continue
		}

		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.ContainerName = netflows[i].SrcContainerName
			res.ProcessName = netflows[i].SrcProcess
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerName = netflows[i].DstContainerName
			res.ProcessName = netflows[i].DstProcess
		}
		res.DstPort = netflows[i].DstPort

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetAllProcessList(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	defProcess := valueUnknown
	var dstQuery, srcQuery string
	dstQuery = "dst_cluster = ? and dst_namespace = ? and dst_name = ? and dst_kind = ? and not dst_process = ?"
	srcQuery = "src_cluster = ? and src_namespace = ? and src_name = ? and src_kind = ? and not src_process = ?"

	netflows := make([]model.TensorNetworkFlow, 0, 5)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, dstQuery, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, defProcess).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed with dst info, %v", err)
	}

	tmpflows := make([]model.TensorNetworkFlow, 0, len(netflows))
	uuid := make(map[uint32]struct{}, len(netflows))
	resource := make([]ProcessInfo, 0, len(netflows))
	for i := 0; i < len(netflows); i++ {
		if netflows[i].DstProcess == "" {
			continue
		}
		var res ProcessInfo
		res.ResourceName = netflows[i].DstOwnerName
		res.ResourceKind = netflows[i].DstKind
		res.Namespace = netflows[i].DstNamespace
		res.ContainerName = netflows[i].DstContainerName
		res.ProcessName = netflows[i].DstProcess

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}

	err = rl.rdb.GetReadDB().WithContext(ctx).Find(&tmpflows, srcQuery, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, defProcess).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed with src info, %v", err)
	}

	for i := 0; i < len(tmpflows); i++ {
		if tmpflows[i].SrcProcess == "" {
			continue
		}

		var res ProcessInfo
		res.ResourceName = tmpflows[i].SrcOwnerName
		res.ResourceKind = tmpflows[i].SrcKind
		res.Namespace = tmpflows[i].SrcNamespace
		res.ContainerName = tmpflows[i].SrcContainerName
		res.ProcessName = tmpflows[i].SrcProcess

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetFramework(ctx context.Context, imageID uint32) (*model.WebFrameScan, error) {
	return dal.GetFramework(ctx, rl.rdb.GetReadDB(), imageID)
}

func (rl *TensorResourcesService) GetFrameworks(ctx context.Context) ([]*model.WebFrameScan, error) {
	return dal.GetFrameworks(ctx, rl.rdb.GetReadDB())
}

func (rl *TensorResourcesService) CountImages(ctx context.Context, queryOptions *dal.ResContainersQueryOption) (int64, error) {
	cnt, err := dal.CountContainer(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) GetImageInfos(ctx context.Context, queryOptions *dal.ResContainersQueryOption) ([]*ImageInfo, error) {
	containers, err := dal.GetResourceContainersUnique(ctx, rl.rdb.GetReadDB(), queryOptions, -1, -1)
	if err != nil {
		return nil, err
	}
	var images []*ImageInfo
	for _, c := range containers {
		id := util.ImageUUID(c.Image)
		images = append(images, &ImageInfo{
			Name: c.Image,
			UUID: id,
		})
	}
	return images, nil
}

func (rl *TensorResourcesService) GetImages(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]*ImageResponse, error) {
	containers, err := dal.GetResourceContainersUnique(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, err
	}
	return rl.getImageFromScanner(ctx, containers)
}

func (rl *TensorResourcesService) getImageFromScanner(ctx context.Context, tcs []*model.TensorContainer) ([]*ImageResponse, error) {
	uuids := ""
	for i, c := range tcs {
		id := util.ImageUUID(c.Image)
		imageID := ""
		if i != 0 {
			imageID = fmt.Sprintf(",%d", id)
		} else {
			imageID = fmt.Sprintf("%d", id)
		}
		uuids += imageID
	}
	url := fmt.Sprintf("%s%s%s%s", rl.scannerURL, ImageListPath, "?uuids=", uuids)
	logging.GetLogger().Debug().Msgf("url: %s", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create request failed")
		return nil, err
	}
	var images []*ImageResponse
	err = util.HTTPRequest(ctx, http.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}
		if resp.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("request err")
		}

		if resp.Body == nil {
			return err
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			return err
		}
		if len(rawResp.Data.Items) > 0 {
			err = json.Unmarshal(rawResp.Data.Items, &images)
			if err != nil {
				return err
			}

			for _, item := range images {
				logging.GetLogger().Debug().Msgf("%+v", *item)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return images, nil
}
