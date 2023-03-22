package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	param "github.com/oceanicdev/chi-param"

	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
	pmodel "gitlab.com/security-rd/go-pkg/model"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	ImageListPath    = "/api/v1/images/list?limit=100000&offset=0"
	ImageRiskPath    = "/api/v1/internal/overview/image"
	RegistryRiskPath = "/api/v1/internal/overview/registry"
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

func (rl *TensorResourcesService) GetClusters(ctx context.Context, query *dal.ClusterQueryOption, offset, limit int) ([]*model.TensorCluster, int64, error) {
	clusters, err := dal.GetClusters(ctx, rl.rdb.GetReadDB(), query, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	totalCnt, err := dal.CountClusters(ctx, rl.rdb.GetReadDB(), query)
	if err != nil {
		return nil, 0, err
	}
	return clusters, totalCnt, nil
}

func (rl *TensorResourcesService) GetClusterByKey(ctx context.Context, key string) *model.TensorCluster {
	return dal.GetClustersByKey(ctx, rl.rdb.GetReadDB(), key)
}

func (rl *TensorResourcesService) AddCluster(ctx context.Context, cluster *model.TensorCluster) error {
	// TODO create the k8s client and so on
	return dal.AddCluster(ctx, rl.rdb.Get(), cluster)
}

func (rl *TensorResourcesService) UpdateCluster(ctx context.Context, clusterKey, clusterName, description, ruleVersion string) error {
	return dal.UpdateCluster(ctx, rl.rdb.Get(), clusterKey, clusterName, description, ruleVersion)
}

func (rl *TensorResourcesService) DeleteCluster(ctx context.Context, clusterKey string) error {
	return dal.DeleteClusterAll(ctx, rl.rdb.Get(), clusterKey)
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

func (rl *TensorResourcesService) GetNamespacesWithOption(ctx context.Context, query *dal.NamespacesQueryOption, offset, limit int) ([]*model.TensorNamespace, int64, error) {
	ns, err := dal.GetNamespaceWithOption(ctx, rl.rdb.GetReadDB(), query, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountNamespacesWithOption(ctx, rl.rdb.GetReadDB(), query)
	if err != nil {
		return nil, 0, err
	}
	return ns, cnt, nil
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
	cnt, err := dal.CountPods(ctx, rl.rdb.GetReadDB(), queryOptions, -1, -1)
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

func (rl *TensorResourcesService) GetImagesWithGivenVuln(ctx context.Context, vulnName, pkgName, pkgVersion string) ([]*model.ImageInfo, error) {
	return dal.GetImagesWithGivenVuln(ctx, rl.scannerURL, vulnName, pkgName, pkgVersion)
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
func (rl *TensorResourcesService) GetResourceContainersWithGivenVuln(ctx context.Context, vulnName, pkgName, pkgVersion string, offset, limit int) ([]*model.TensorContainer, int64, error) {
	images, err := rl.GetImagesWithGivenVuln(ctx, vulnName, pkgName, pkgVersion)
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "GetImagesWithGivenVuln %s error", vulnName)
		return nil, 0, err
	}

	imageIDs := make([]string, 0, len(images))
	for _, image := range images {
		imageIDs = append(imageIDs, getImageIDFrom(image))
	}
	logging.Get().Debug().Msgf("imageIDs: %+v", imageIDs)

	containers, totalCnt, err := rl.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithInConditionCustom("image", imageIDs), offset, limit)
	if err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "GetResourceContainers %s error. imageList: %v", vulnName, imageIDs)
		return nil, 0, err
	}

	return containers, totalCnt, nil
}

func (rl *TensorResourcesService) GetArguments(r *http.Request) (*ArgumentDetails, error) {
	var arg ArgumentDetails
	// cluster key
	arg.ClusterKey, _ = param.QueryString(r, "cluster_key")
	if len(arg.ClusterKey) == 0 {
		return nil, errors.Errorf("cluster_key is nil, please input cluster_key")
	}
	// namespace
	arg.Namespace, _ = param.QueryString(r, "namespace")
	// resource name
	arg.ResourceName, _ = param.QueryString(r, "res_name")
	// resource kind
	arg.ResourceKind, _ = param.QueryString(r, "res_kind")
	// net flow route
	arg.Route, _ = param.QueryString(r, "route")
	// day time
	arg.Day, _ = param.QueryInt(r, "day")
	// container id
	arg.ContainerId, _ = param.QueryString(r, "container_id")
	// process name
	arg.ProcessName, _ = param.QueryString(r, "proc_name")

	return &arg, nil
}

func (rl *TensorResourcesService) GetResourceRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ?"
	}

	netflows := make([]pmodel.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]*ProcessInfo)
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ClusterID = netflows[i].DstCluster
		}
		res.DstPort = netflows[i].DstPort
		res.CreateAt = netflows[i].CreatedAt
		res.UpdateAt = netflows[i].UpdatedAt

		key := res.CreateUUID()
		value, ok := uuid[key]
		if !ok {
			res.LinkCount = netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			uuid[key] = &res
		} else {
			value.LinkCount += netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			if res.CreateAt.Before(value.CreateAt) {
				value.CreateAt = res.CreateAt
			}
			//
			if res.UpdateAt.After(value.UpdateAt) {
				value.UpdateAt = res.UpdateAt
			}
		}
	}

	for _, value := range uuid {
		resource = append(resource, *value)
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetContainerRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ? and dst_container_id = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ? and src_container_id = ?"
	}

	netflows := make([]pmodel.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerId).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]*ProcessInfo)
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.ContainerId = netflows[i].SrcContainerID
			res.ContainerName = netflows[i].SrcContainerName
			res.PodName = netflows[i].SrcPodName
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerId = netflows[i].DstContainerID
			res.ContainerName = netflows[i].DstContainerName
			res.PodName = netflows[i].DstPodName
			res.ClusterID = netflows[i].DstCluster
		}
		res.DstPort = netflows[i].DstPort
		res.CreateAt = netflows[i].CreatedAt
		res.UpdateAt = netflows[i].UpdatedAt

		key := res.CreateUUID()
		value, ok := uuid[key]
		if !ok {
			res.LinkCount = netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			uuid[key] = &res
		} else {
			value.LinkCount += netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			if res.CreateAt.Before(value.CreateAt) {
				value.CreateAt = res.CreateAt
			}
			//
			if res.UpdateAt.After(value.UpdateAt) {
				value.UpdateAt = res.UpdateAt
			}
		}
	}

	for _, value := range uuid {
		resource = append(resource, *value)
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetProcessRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ? and dst_container_id = ? and dst_process = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ? and src_container_id = ? and src_process = ?"
	}

	netflows := make([]pmodel.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerId, arg.ProcessName).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed, %v", err)
	}

	uuid := make(map[uint32]*ProcessInfo)
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.ContainerId = netflows[i].SrcContainerID
			res.ContainerName = netflows[i].SrcContainerName
			res.ProcessName = netflows[i].SrcProcess
			res.PodName = netflows[i].SrcPodName
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerId = netflows[i].DstContainerID
			res.ContainerName = netflows[i].DstContainerName
			res.ProcessName = netflows[i].DstProcess
			res.PodName = netflows[i].DstPodName
			res.ClusterID = netflows[i].DstCluster
		}
		res.DstPort = netflows[i].DstPort
		res.CreateAt = netflows[i].CreatedAt
		res.UpdateAt = netflows[i].UpdatedAt

		key := res.CreateUUID()
		value, ok := uuid[key]
		if !ok {
			res.LinkCount = netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			uuid[key] = &res
		} else {
			value.LinkCount += netflows[i].Bucket.CalculteCurrentCountBucketSum(arg.Day)
			if res.CreateAt.Before(value.CreateAt) {
				value.CreateAt = res.CreateAt
			}
			//
			if res.UpdateAt.After(value.UpdateAt) {
				value.UpdateAt = res.UpdateAt
			}
		}
	}

	for _, value := range uuid {
		resource = append(resource, *value)
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetContainerProcessList(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	//
	var dstQuery, srcQuery string
	dstQuery = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ? and dst_container_id = ?"
	srcQuery = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ? and src_container_id = ?"
	if arg.ContainerId == "" {
		dstQuery = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ? and not dst_container_id = ?"
		srcQuery = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ? and not src_container_id = ?"
	}
	//
	netflows := make([]pmodel.TensorNetworkFlow, 0, 5)
	// query data
	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, dstQuery, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerId).Error
	if err != nil {
		return nil, errors.Errorf("find resource from db failed with dst info, %v", err)
	}

	tmpflows := make([]pmodel.TensorNetworkFlow, 0, len(netflows))
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
		res.ContainerId = netflows[i].DstContainerID
		res.ContainerName = netflows[i].DstContainerName
		res.ProcessName = netflows[i].DstProcess

		key := res.CreateUUID()
		_, ok := uuid[key]
		if !ok {
			uuid[key] = struct{}{}
			resource = append(resource, res)
		}
	}
	// query data
	err = rl.rdb.GetReadDB().WithContext(ctx).Find(&tmpflows, srcQuery, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.ContainerId).Error
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
		res.ContainerId = tmpflows[i].SrcContainerID
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

func (rl *TensorResourcesService) GetImages(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]model.ImageBaseResponse, error) {
	containers, err := dal.GetResourceContainersUnique(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, err
	}
	return rl.getImageFromScanner(ctx, containers)
}

func (rl *TensorResourcesService) getImageFromScanner(ctx context.Context, tcs []*model.TensorContainer) ([]model.ImageBaseResponse, error) {
	uuids := make([]uint32, 0)
	for _, c := range tcs {
		if uuid := util.ImageUUID(c.Image); uuid > 0 {
			uuids = append(uuids, uuid)
		}
	}
	if len(uuids) == 0 {
		return nil, fmt.Errorf("not find image uuids")
	}

	url := fmt.Sprintf("%s%s", rl.scannerURL, ImageListPath)

	bodyParam := model.ImageListParam{UUIDs: uuids}

	bys, err := json.Marshal(bodyParam)

	if err != nil {
		logging.Get().Err(err).Msg("getImageFromScanner")
		return nil, err
	}

	logging.Get().Debug().Msgf("url: %s", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bys))
	if err != nil {
		logging.Get().Err(err).Msg("create request failed")
		return nil, err
	}
	var images []model.ImageBaseResponse
	err = util.HTTPRequest(ctx, httputil.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}
		if resp.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("request err")
		}

		if resp.Body == nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
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
				logging.Get().Debug().Msgf("%+v", item)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return images, nil
}

func (rl *TensorResourcesService) GetContainer(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]model.ImageBaseResponse, error) {
	containers, err := dal.GetResourceContainersUnique(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, err
	}
	return rl.getImageFromScanner(ctx, containers)
}

func (rl *TensorResourcesService) GetRawContainer(ctx context.Context, queryOptions *dal.RawContainersQueryOption, offset, limit int) ([]*model.TensorRawContainer, error) {
	return dal.GetRawContainers(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountRawContainer(ctx context.Context, queryOptions *dal.RawContainersQueryOption) (int64, error) {
	return dal.CountRawContainer(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) GetRuleVersions(ctx context.Context, offset, limit int) ([]string, int64, error) {
	ruleVersions, err := dal.GetRuleVersions(ctx, rl.rdb.GetReadDB(), offset, limit)
	if err != nil {
		return nil, 0, err
	}
	totalCnt, err := dal.CountRuleVersions(ctx, rl.rdb.GetReadDB())
	if err != nil {
		return nil, 0, err
	}
	return ruleVersions, totalCnt, nil

}

func (rl *TensorResourcesService) CountRuleVersions(ctx context.Context) (int64, error) {
	return dal.CountRuleVersions(ctx, rl.rdb.GetReadDB())
}

type ClustertHandler struct {
	DB *databases.RDBInstance
}

func (ch *ClustertHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	cluster := message.(*pb.ClusterRegister)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	resp := &pb.CommonReponse{
		Status: 0,
	}
	logging.Get().Info().Msgf("received cluster: %s", cluster.String())

	tCluster := &model.TensorCluster{
		Key:                 cluster.Key,
		Name:                cluster.Name,
		ClusterType:         model.ClusterType(cluster.ClusterType),
		Description:         cluster.Description,
		APIServerAddr:       cluster.APIServerAddr,
		CertificateAuthData: string(cluster.CertificateAuthData),
		SecretToken:         string(cluster.SecretToken),
		ClientCertData:      string(cluster.ClientCertData),
		ClientKeyData:       string(cluster.ClientKeyData),
		WorkerNamespace:     cluster.WorkerNamespace,
		Status:              0,
		Platform:            cluster.Platform,
		Version:             cluster.Version,
	}
	err := dal.AddCluster(ctx, ch.DB.Get(), tCluster)
	if err != nil {
		logging.Get().Err(err).Msgf("add cluster : %s-%s err", cluster.Key, cluster.Name)
		resp.Status = 1
		resp.StatusMessage = err.Error()
	}
	clusterManager, ok := k8s.GetClusterManager()
	if ok {
		clusterManager.UpdateCluster(ctx, tCluster)
	} else {
		resp.Status = 1
		resp.StatusMessage = "failed to get cluster manager"
	}
	err = s.SendResponse(reqID, resp)
	if err != nil {
		logging.Get().Err(err).Msg("send reponse err")
	}
}
func (ch *ClustertHandler) OnRead(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
}
func (ch *ClustertHandler) OnUpdate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
}
func (ch *ClustertHandler) OnDelete(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
}
