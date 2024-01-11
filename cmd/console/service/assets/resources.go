package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	param "github.com/oceanicdev/chi-param"
	"gorm.io/gorm"

	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/logging"
	pmodel "gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/redisearch"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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

// TODO:直接传入rsearchClient，在查询时判断rsearchClient实例是否为nil不是一种好的方式，如有必要，考虑将dal的操作抽象为接口
func InitResourcesService(rdb *databases.RDBInstance, rsearchClient *redisearch.Client, scannerURL string, stream rpcstream.MessageStream) error {
	rlOnce.Do(func() {
		instance = newTensorResourcesService(rdb, rsearchClient, scannerURL, stream)
	})
	return nil
}

func GetResourcesService(_ context.Context) (*TensorResourcesService, bool) {
	return instance, instance != nil
}

type TensorResourcesService struct {
	rdb           *databases.RDBInstance
	rsearchClient *redisearch.Client
	scannerURL    string
	stream        rpcstream.MessageStream
}

func newTensorResourcesService(rdb *databases.RDBInstance, rsearchClient *redisearch.Client, scannerURL string, stream rpcstream.MessageStream) *TensorResourcesService {
	return &TensorResourcesService{
		rdb:           rdb,
		rsearchClient: rsearchClient,
		scannerURL:    scannerURL,
		stream:        stream,
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

type TensorResourceView struct {
	*model.TensorResource
	Managers []*dal.UserNameAccount
}

// 由 queryOptions.WithUserAccount 决定
func (rl *TensorResourcesService) GetResourcesWithUserAccount(ctx context.Context, queryOptions *dal.ResourcesQueryOption, offset, limit int) ([]*TensorResourceView, int64, error) {
	resources, total, err := rl.GetResources(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	var result []*TensorResourceView
	if queryOptions.WithUserAccount {
		result = getResourceViewByResources(ctx, resources, rl.rdb.GetReadDB())
	} else {
		for _, r := range resources {
			result = append(result, &TensorResourceView{TensorResource: r})
		}
	}
	return result, total, nil
}

func (rl *TensorResourcesService) GetUserAccountByResource(ctx context.Context, clusterKey, namespace, resourceKind, resourceName string) []*dal.UserNameAccount {
	if clusterKey == "" || namespace == "" || resourceKind == "" || resourceName == "" {
		return nil
	}

	resource := &model.TensorResource{}
	err := rl.rdb.GetReadDB().WithContext(ctx).Model(resource).Select("managers").
		Where("cluster_key = ? and namespace = ? and kind= ? and name = ?", clusterKey, namespace, resourceKind, resourceName).Scan(resource).Error
	if err == gorm.ErrRecordNotFound {
		return nil
	}
	if err != nil {
		return nil
	}

	ok, resultMap, err := dal.SelectUserAccountByNames(ctx, rl.rdb.GetReadDB(), resource.Managers)
	if !ok || err != nil {
		return nil
	}
	var result []*dal.UserNameAccount
	for _, account := range resultMap {
		result = append(result, account)
	}
	return result
}

func getResourceViewByResources(ctx context.Context, resources []*model.TensorResource, db *gorm.DB) []*TensorResourceView {
	nameAccountMap := make(map[string]*dal.UserNameAccount)
	var names []string
	nameMap := make(map[string]struct{})
	for _, namespace := range resources {
		for _, manager := range namespace.Managers {
			_, isOk := nameMap[manager]
			if !isOk {
				nameMap[manager] = struct{}{}
				names = append(names, manager)
			}
		}
	}
	if len(names) > 0 {
		ok, resultMap, err := dal.SelectUserAccountByNames(ctx, db, names)
		if ok {
			nameAccountMap = resultMap
		} else {
			logging.Get().Warn().Err(err).Msg("SelectUserAccountByNames failed.")
		}
	}
	result := make([]*TensorResourceView, len(resources))
	for i, resource := range resources {
		result[i] = &TensorResourceView{TensorResource: resource}
		for _, manager := range resource.Managers {
			if manager == "" {
				continue
			}
			tmp := nameAccountMap[manager]
			if tmp == nil {
				tmp = &dal.UserNameAccount{
					UserName: manager,
					Account:  manager,
				}
			}
			result[i].Managers = append(result[i].Managers, tmp)
		}
	}
	return result
}

// GetResourceWithRedis will send query to redis only if redisearch client is ready and queryOptions meet with redisearch.
func (rl *TensorResourcesService) GetResourceWithRedis(ctx context.Context, queryOptions *dal.ResourcesQueryOption, offset, limit int) ([]*TensorResourceView, int64, error) {
	if rl.rsearchClient == nil {
		return rl.GetResourcesWithUserAccount(ctx, queryOptions, offset, limit)
	}

	ic, err := rl.rsearchClient.GetIndexClient("resource")
	if err != nil {
		return nil, 0, err
	}

	resources, err := dal.GetResourcesWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	var result []*TensorResourceView
	if queryOptions.WithUserAccount {
		result = getResourceViewByResources(ctx, resources, rl.rdb.GetReadDB())
	} else {
		for _, r := range resources {
			result = append(result, &TensorResourceView{TensorResource: r})
		}
	}

	resCnt, err := dal.CountResourcesWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return result, resCnt, nil
}

func (rl *TensorResourcesService) CountResource(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (int64, error) {
	resCnt, err := dal.CountResources(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return 0, err
	}

	return resCnt, nil
}

func (rl *TensorResourcesService) CountResourceWithRedis(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (int64, error) {
	if rl.rsearchClient == nil {
		return rl.CountResource(ctx, queryOptions)
	}

	ic, err := rl.rsearchClient.GetIndexClient("resource")
	if err != nil {
		return 0, err
	}

	resCnt, err := dal.CountResourcesWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions)
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

type NamespaceView struct {
	*model.TensorNamespace
	Managers []*dal.UserNameAccount
	Tags     []string
}

func (rl *TensorResourcesService) GetNamespacesWithOption(ctx context.Context, query *dal.NamespacesQueryOption, offset, limit int) ([]*NamespaceView, int64, error) {
	ns, err := dal.GetNamespaceWithOption(ctx, rl.rdb.GetReadDB(), query, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountNamespacesWithOption(ctx, rl.rdb.GetReadDB(), query)
	if err != nil {
		return nil, 0, err
	}
	nameAccountMap := make(map[string]*dal.UserNameAccount)
	var names []string
	nameMap := make(map[string]struct{})
	for _, namespace := range ns {
		for _, manager := range namespace.Managers {
			_, isOk := nameMap[manager]
			if !isOk {
				nameMap[manager] = struct{}{}
				names = append(names, manager)
			}
		}
	}
	if len(names) > 0 {
		ok, resultMap, err := dal.SelectUserAccountByNames(ctx, rl.rdb.GetReadDB(), names)
		if ok {
			nameAccountMap = resultMap
		} else {
			logging.Get().Warn().Err(err).Msg("SelectUserAccountByNames failed.")
		}
	}
	view := make([]*NamespaceView, len(ns))
	for i, n := range ns {
		view[i] = &NamespaceView{TensorNamespace: n}
		for _, manager := range n.Managers {
			tmp := nameAccountMap[manager]
			if tmp == nil {
				tmp = &dal.UserNameAccount{
					UserName: manager,
					Account:  manager,
				}
			}
			view[i].Managers = append(view[i].Managers, tmp)
		}
	}
	return view, cnt, nil
}

func (rl *TensorResourcesService) UpdateNamespaces(ctx context.Context, clusterKey, name, alias string, manager []string, authority string) error {
	err := dal.UpdateNamespace(ctx, rl.rdb.Get(), clusterKey, name, alias, manager, authority)
	return err
}

func (rl *TensorResourcesService) GetResourcePodsWithRedis(ctx context.Context, queryOptions *dal.ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, int64, error) {
	if rl.rsearchClient == nil {
		return rl.GetResourcePods(ctx, queryOptions, offset, limit)
	}

	ic, err := rl.rsearchClient.GetIndexClient("pod")
	if err != nil {
		return nil, 0, err
	}

	cnt, err := dal.CountPodsWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions)

	if err != nil {
		return nil, 0, err
	}

	if cnt == 0 {
		return nil, 0, err
	}

	pods, err := dal.GetResourcePodListWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions, offset, limit)

	return pods, cnt, err

}

func (rl *TensorResourcesService) GetResourcePods(ctx context.Context, queryOptions *dal.ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, int64, error) {
	pods, err := dal.GetResourcePodsList(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountPods(ctx, rl.rdb.GetReadDB(), queryOptions)
	return pods, cnt, err
}

type PodsBySvcReq struct {
	Namespace  string
	ClusterKey string
	SvcName    string
	Query      string //pod_name
	Limit      int
	Offset     int
	UseRedis   bool
}

func (rl *TensorResourcesService) GetPodsBySvc(ctx context.Context, req PodsBySvcReq, offset, limit int) ([]*model.PodResourceRelation, int64, error) {
	podNameList, err := dal.GetPodNameListBySvc(ctx, rl.rdb.GetReadDB(), req.ClusterKey, req.Namespace, req.SvcName)
	if err != nil {
		return nil, 0, err
	}
	if len(podNameList) == 0 {
		return nil, 0, nil
	}
	query := dal.ResourcePodssQuery()
	if req.ClusterKey != "" {
		query.WithCluster(req.ClusterKey)
	}
	if req.Namespace != "" {
		query.WithNamespace(req.Namespace)
	}
	if req.Query != "" {
		query.WithMulColumnQuery([]string{"pod_name"}, req.Query)
	}
	if len(podNameList) > 0 {
		query.WithInPodNameList(podNameList)
	}
	return rl.GetResourcePods(ctx, query, offset, limit)
}

func (rl *TensorResourcesService) CountPods(ctx context.Context, queryOptions *dal.ResPodsQueryOption) (int64, error) {
	cnt, err := dal.CountPods(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}
func (rl *TensorResourcesService) GetResourceContainersWithoutCount(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]*dal.ResContainerBase, error) {
	containers, err := dal.GetResourceContainerBases(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, err
	}
	return containers, nil
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

type NodeExtraCount struct {
	ImageCount     int64
	ContainerCount int64
	PodCount       int64
	Cpu            string
	Memory         string
	Disk           string
}

func (rl *TensorResourcesService) GetNodeCount(ctx context.Context, clusterKey string, nodeName string, ip string) *NodeExtraCount {
	var nodeExtra NodeExtraCount
	wg := sync.WaitGroup{}
	wg.Add(2)
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*8)
	defer cancelFunc()
	go func() {
		logging.Get().WithContext(ctx).Infof("GetNodeCount begin grcp")
		// 	grpc
		defer func() {
			wg.Done()
		}()

		logging.Get().WithContext(ctx).Infof("GetNodeCount nodeKey:%s ", clusterKey)
		resp, err := rl.stream.GetNodeLoadInfo(ctx, clusterKey, &pb.NodeLoadReq{
			ClusterKey: clusterKey,
			NodeName:   nodeName,
		})
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "GetNodeCount %s error", clusterKey)
			return
		}
		if resp.ErrMsg != "" {
			logging.Get().WithContext(ctx).Errorf(nil, "GetNodeCount %s errMsg:%s", clusterKey, resp.ErrMsg)
			return
		}
		nodeExtra.Cpu = resp.Cpu
		nodeExtra.Disk = resp.DiskUsed
		if resp.MemoryUsed != "" {
			parseInt, err := strconv.ParseFloat(resp.MemoryUsed, 10)
			if err != nil {
				nodeExtra.Memory = resp.MemoryUsed
				return
			}
			nodeExtra.Memory = fmt.Sprintf("%0.2fG", parseInt/(1024*1024))
		}
	}()
	go func() {
		logging.Get().WithContext(ctx).Infof("GetNodeCount begin sqlCount ")
		defer func() {
			wg.Done()
		}()
		// 	container count
		err := rl.rdb.GetReadDB().WithContext(ctx).Model(&model.TensorRawContainer{}).Where("cluster_key=? and node_name=? and status<5", clusterKey, nodeName).Count(&nodeExtra.ContainerCount).Error
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "GetNodeCount calculate ContainerCount err")
		}
		// pod count
		err = rl.rdb.GetReadDB().WithContext(ctx).Model(&model.PodResourceRelation{}).Where("cluster_key=? and node_name=? and status<5", clusterKey, nodeName).Count(&nodeExtra.PodCount).Error
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "GetNodeCount calculate PodCount err")
		}
		// image count
		nodeInfo := &imagesec.NodeInfo{
			IP:         ip,
			Hostname:   nodeName,
			ClusterKey: clusterKey,
		}
		uniqueID := nodeInfo.GenUniqueID()
		err = rl.rdb.GetReadDB().WithContext(ctx).Model(&imagesec.Image{}).Where("node_id =  ?", uniqueID).Count(&nodeExtra.ImageCount).Error
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "GetNodeCount calculate NodeCount err")
		}
	}()
	wg.Wait()
	return &nodeExtra
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
	// pod name
	arg.PodName, _ = param.QueryString(r, "pod_name")
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
		if value.LinkCount == 0 {
			continue
		}
		resource = append(resource, *value)
	}

	return resource, nil
}

func (rl *TensorResourcesService) GetPodRelation(arg *ArgumentDetails) ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var query string
	if arg.Route == typeIngress {
		query = "dst_cluster = ? and dst_namespace = ? and dst_owner_name = ? and dst_kind = ? and dst_pod_name = ?"
	} else {
		query = "src_cluster = ? and src_namespace = ? and src_owner_name = ? and src_kind = ? and src_pod_name = ?"
	}

	netflows := make([]pmodel.TensorNetworkFlow, 0)

	err := rl.rdb.GetReadDB().WithContext(ctx).Find(&netflows, query, arg.ClusterKey, arg.Namespace, arg.ResourceName, arg.ResourceKind, arg.PodName).Error
	if err != nil {
		return nil, errors.Errorf("find pod info from db failed, %v", err)
	}

	uuid := make(map[uint32]*ProcessInfo)
	resource := make([]ProcessInfo, 0)
	for i := 0; i < len(netflows); i++ {
		var res ProcessInfo
		if arg.Route == typeIngress {
			res.ResourceName = netflows[i].SrcOwnerName
			res.ResourceKind = netflows[i].SrcKind
			res.Namespace = netflows[i].SrcNamespace
			res.PodName = netflows[i].SrcPodName
			res.PodUid = netflows[i].SrcPodUid
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.PodName = netflows[i].DstPodName
			res.PodUid = netflows[i].DstPodUid
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
		if value.LinkCount == 0 {
			continue
		}
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
			res.PodUid = netflows[i].SrcPodUid
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerId = netflows[i].DstContainerID
			res.ContainerName = netflows[i].DstContainerName
			res.PodName = netflows[i].DstPodName
			res.PodUid = netflows[i].DstPodUid
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
		if value.LinkCount == 0 {
			continue
		}
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
			res.PodUid = netflows[i].SrcPodUid
			res.ClusterID = netflows[i].SrcCluster
		} else {
			res.ResourceName = netflows[i].DstOwnerName
			res.ResourceKind = netflows[i].DstKind
			res.Namespace = netflows[i].DstNamespace
			res.ContainerId = netflows[i].DstContainerID
			res.ContainerName = netflows[i].DstContainerName
			res.ProcessName = netflows[i].DstProcess
			res.PodName = netflows[i].DstPodName
			res.PodUid = netflows[i].DstPodUid
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
		if value.LinkCount == 0 {
			continue
		}
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
		images = append(images, &ImageInfo{
			Name: c.Image,
			UUID: c.ImageUUID,
		})
	}
	return images, nil
}

func (rl *TensorResourcesService) GetImageInfosV2(ctx context.Context, queryOptions *dal.ResContainersQueryOption) ([]*ImageInfo, error) {
	containers, err := dal.GetResourceContainersUniqueV2(ctx, rl.rdb.GetReadDB(), queryOptions, -1, -1)
	if err != nil {
		return nil, err
	}
	var images []*ImageInfo
	for _, c := range containers {
		images = append(images, &ImageInfo{
			Name: c.ImageName,
			UUID: c.ImageUUID,
		})
	}
	return images, nil
}

func (rl *TensorResourcesService) GetImages(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]imagesec.ImageBaseResponse, error) {
	containers, err := dal.GetResourceContainersUnique(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, err
	}
	return rl.getImageFromScanner(ctx, containers)
}

func (rl *TensorResourcesService) getImageFromScanner(ctx context.Context, tcs []*model.TensorContainer) ([]imagesec.ImageBaseResponse, error) {
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

	bodyParam := imagesec.ImageSearchApiParam{UUIDs: uuids}

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
	var images []imagesec.ImageBaseResponse
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

func (rl *TensorResourcesService) GetContainer(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]imagesec.ImageBaseResponse, error) {
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

func (rl *TensorResourcesService) ListRawContainer(ctx context.Context, queryOptions *dal.RawContainersQueryOption, offset, limit int) ([]*model.TensorRawContainer, int64, error) {
	cnt, err := rl.CountRawContainer(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	containers, err := rl.GetRawContainer(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return containers, cnt, nil
}

func (rl *TensorResourcesService) ListRawContainerWithRedis(ctx context.Context, queryOptions *dal.RawContainersQueryOption, offset, limit int) ([]*model.TensorRawContainer, int64, error) {
	if rl.rsearchClient == nil {
		return rl.ListRawContainer(ctx, queryOptions, offset, limit)
	}
	ic, err := rl.rsearchClient.GetIndexClient("rawContainer")
	if err != nil {
		return nil, 0, err
	}

	cnt, err := dal.CountRawContainerWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	containers, err := dal.GetRawContainersWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return containers, cnt, nil

}

func (rl *TensorResourcesService) ListRawContainerWithFrameworkWithRedis(ctx context.Context, queryOptions *dal.RawContainersWithFrameworkQueryOption, offset, limit int) ([]*dal.RawContainerWithFrameworkStr, int64, error) {
	var rawContainerQuery *dal.RawContainersQueryOption
	if rl.rsearchClient == nil {
		return rl.ListRawContainerWithFramework(ctx, queryOptions, offset, limit)
	}
	if len(queryOptions.WhereFrameworkLikeCondition) == 0 {
		rawContainerQuery = queryOptions.RawContainersQueryOption
	}
	ic, err := rl.rsearchClient.GetIndexClient("rawContainer")
	if err != nil {
		return nil, 0, err
	}
	var cnt int64

	if rawContainerQuery != nil {
		cnt, err = dal.CountRawContainerWithRedis(ctx, rl.rdb.GetReadDB(), ic, rawContainerQuery)
	} else {
		cnt, err = dal.CountRawContainerWithFramework(ctx, rl.rdb.GetReadDB(), queryOptions)
	}
	if err != nil {
		return nil, 0, err
	}
	containers, err := dal.GetRawContainersWithFrameworkWithRedis(ctx, rl.rdb.GetReadDB(), ic, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return containers, cnt, nil
}

func (rl *TensorResourcesService) ListRawContainerWithFramework(ctx context.Context, queryOptions *dal.RawContainersWithFrameworkQueryOption, offset, limit int) ([]*dal.RawContainerWithFrameworkStr, int64, error) {
	cnt, err := dal.CountRawContainerWithFramework(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	containers, err := dal.GetRawContainersWithFramework(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return containers, cnt, nil
}

func (rl *TensorResourcesService) GetRawContainerWithFramework(ctx context.Context, clusterKey string, rawContainerId string, containerIdIsPrefix bool) (*dal.RawContainerWithFrameworkStr, error) {
	query := dal.RawContainersWithFrameworkQuery()
	if rawContainerId == "" {
		return nil, errors.New("rawContainerId is empty.")
	}
	if !containerIdIsPrefix {
		query.WithID(rawContainerId)
	} else {
		query.WithPrefixID(rawContainerId)
	}
	if clusterKey != "" {
		query.WithCluster(clusterKey)
	}
	containers, err := dal.GetRawContainersWithFramework(ctx, rl.rdb.GetReadDB(), query, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(containers) > 0 {
		return containers[0], nil
	}
	return nil, nil
}

func (rl *TensorResourcesService) CountIngress(ctx context.Context, queryOptions *dal.IngressesQueryOption) (int64, error) {
	return dal.CountIngress(ctx, rl.rdb.GetReadDB(), queryOptions)
}
func (rl *TensorResourcesService) GetIngressBase(ctx context.Context, option *dal.IngressesQueryOption, offset int, limit int) ([]*model.TensorIngress, error) {
	return dal.GetIngresses(ctx, rl.rdb.GetReadDB(), option, offset, limit)
}

func (rl *TensorResourcesService) ListIngress(ctx context.Context, queryOptions *dal.IngressesQueryOption, offset, limit int) ([]*model.TensorIngress, int64, error) {
	cnt, err := rl.CountIngress(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	ingresses, err := rl.GetIngressBase(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return ingresses, cnt, nil
}

func (rl *TensorResourcesService) GetIngressBackendKinds(ctx context.Context) ([]string, error) {
	return dal.GetIngressBackendKinds(ctx, rl.rdb.GetReadDB())
}

func (rl *TensorResourcesService) GetIngressRules(ctx context.Context, queryOptions *dal.IngressesRuleQueryOption, offset, limit int) ([]*model.TensorIngressRule, error) {
	return dal.GetIngressRules(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountIngressRule(ctx context.Context, queryOptions *dal.IngressesRuleQueryOption) (int64, error) {
	return dal.CountIngressRule(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) ListIngressRule(ctx context.Context, queryOptions *dal.IngressesRuleQueryOption, offset, limit int) ([]*model.TensorIngressRule, int64, error) {
	cnt, err := rl.CountIngressRule(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	ingresses, err := rl.GetIngressRules(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return ingresses, cnt, nil
}

func (rl *TensorResourcesService) ListService(ctx context.Context, queryOptions *dal.ServicesQueryOption, offset, limit int) ([]*model.TensorService, int64, error) {
	cnt, err := dal.CountService(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	services, err := dal.GetService(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return services, cnt, nil
}
func (rl *TensorResourcesService) GetService(ctx context.Context, queryOptions *dal.ServicesQueryOption, offset, limit int) ([]*model.TensorService, error) {
	return dal.GetService(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountEndpoint(ctx context.Context, queryOptions *dal.EndpointsQueryOption) (int64, error) {
	return dal.CountEndpoints(ctx, rl.rdb.GetReadDB(), queryOptions)
}
func (rl *TensorResourcesService) GetEndpointBase(ctx context.Context, option *dal.EndpointsQueryOption, offset int, limit int) ([]*model.TensorEndpoints, error) {
	return dal.GetEndpoints(ctx, rl.rdb.GetReadDB(), option, offset, limit)
}

func (rl *TensorResourcesService) ListEndpoint(ctx context.Context, queryOptions *dal.EndpointsQueryOption, offset, limit int) ([]*model.TensorEndpoints, int64, error) {
	cnt, err := rl.CountEndpoint(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	endpoints, err := rl.GetEndpointBase(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return endpoints, cnt, nil
}

func (rl *TensorResourcesService) GetEndpointSubsetKinds(ctx context.Context) ([]string, error) {
	return dal.GetEndpointSubsetKinds(ctx, rl.rdb.GetReadDB())
}

func (rl *TensorResourcesService) GetEndpointSubsets(ctx context.Context, queryOptions *dal.EndpointsSubsetsQueryOption, offset, limit int) ([]*model.TensorEndpointsSubset, error) {
	return dal.GetEndpointSubsets(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountEndpointSubsets(ctx context.Context, queryOptions *dal.EndpointsSubsetsQueryOption) (int64, error) {
	return dal.CountEndpointsSubsets(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) ListEndpointsSubset(ctx context.Context, queryOptions *dal.EndpointsSubsetsQueryOption, offset, limit int) ([]*model.TensorEndpointsSubset, int64, error) {
	cnt, err := rl.CountEndpointSubsets(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	ingresses, err := rl.GetEndpointSubsets(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return ingresses, cnt, nil
}

func (rl *TensorResourcesService) GetSecrets(ctx context.Context, queryOptions *dal.SecretsQueryOption, offset, limit int) ([]*model.TensorSecret, error) {
	return dal.GetSecrets(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountSecrets(ctx context.Context, queryOptions *dal.SecretsQueryOption) (int64, error) {
	return dal.CountSecrets(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) ListSecret(ctx context.Context, queryOptions *dal.SecretsQueryOption, offset, limit int) ([]*model.TensorSecret, int64, error) {
	cnt, err := rl.CountSecrets(ctx, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	ingresses, err := rl.GetSecrets(ctx, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return ingresses, cnt, nil
}

func (rl *TensorResourcesService) ListPV(ctx context.Context, queryOptions *dal.PVQueryOption, offset, limit int) ([]*model.TensorPV, int64, error) {
	cnt, err := dal.CountPVs(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	pvs, err := dal.GetPVs(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return pvs, cnt, nil
}

func (rl *TensorResourcesService) ListPVC(ctx context.Context, queryOptions *dal.PVCQueryOption, offset, limit int) ([]*model.TensorPVC, int64, error) {
	cnt, err := dal.CountPVCs(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	pvcs, err := dal.GetPVCs(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return pvcs, cnt, nil
}

func (rl *TensorResourcesService) ListNamespaceLabel(ctx context.Context, queryOptions *dal.NamespaceLabelQueryOption, offset int, limit int) ([]*model.TensorNamespaceLabel, int64, error) {

	cnt, err := dal.CountNamespaceLabels(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	labels, err := dal.GetNamespaceLabels(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return labels, cnt, nil
}

func (rl *TensorResourcesService) ListBusiSvc(ctx context.Context, queryOptions *dal.BusiSvcQueryOption, offset int, limit int) ([]*dal.PodBusiSvcBase, int64, error) {
	cnt, err := dal.CountBusiSvcs(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, 0, err
	}
	svcs, err := dal.GetBusiSvcs(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return svcs, cnt, nil
}

func (rl *TensorResourcesService) GetBusiStartUser(ctx context.Context, busiTyep string) ([]string, error) {
	user, err := dal.GetBusiStartUser(ctx, rl.rdb.GetReadDB(), busiTyep)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (rl *TensorResourcesService) GetBusiSvcDetail(ctx context.Context, id uint32) (*dal.PodBusiSvcBaseDetail, error) {
	return dal.GetBusiSvcDetail(ctx, rl.rdb.GetReadDB(), id)
}

func (rl *TensorResourcesService) ListExposeHost(ctx context.Context, webDesc string, protocol, hosts []string, offset, limit int) ([]*dal.ExposeHostItem, int64, error) {
	cnt, err := dal.CountExposeHost(ctx, rl.rdb.GetReadDB(), webDesc, protocol, hosts)
	if err != nil {
		return nil, 0, err
	}
	svcs, err := dal.GetExposeHosts(ctx, rl.rdb.GetReadDB(), webDesc, protocol, hosts, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return svcs, cnt, nil
}

func (rl *TensorResourcesService) GetExposeHostDetail(ctx context.Context, id int64) (*dal.ExposeHostDetail, error) {
	return dal.GetExposeHostDetail(ctx, rl.rdb.GetReadDB(), id)
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

func (rl *TensorResourcesService) GetAppWithType(ctx context.Context, queryOptions *dal.AppQueryOption, offset, limit int) ([]*model.ResourceApp, int64, error) {
	apps, err := dal.GetResourceApp(ctx, rl.rdb.GetReadDB(), queryOptions, offset, limit)
	if err != nil {
		return nil, -1, err
	}

	cnt, err := dal.CountResourceApp(ctx, rl.rdb.GetReadDB(), queryOptions)
	if err != nil {
		return nil, -1, err
	}

	return apps, cnt, nil
}

func (rl *TensorResourcesService) CountAppWithType(ctx context.Context, queryOptions *dal.AppQueryOption) (int64, error) {
	return dal.CountResourceApp(ctx, rl.rdb.GetReadDB(), queryOptions)
}

func (rl *TensorResourcesService) GetAppTypes(ctx context.Context, clusterKey string) ([]string, error) {
	db := rl.rdb.GetReadDB().WithContext(ctx)
	results := []*model.TensorContainer{}
	if clusterKey != "" {
		db = db.Where("cluster_key = ?", clusterKey)
	}
	err := db.Distinct("app_type").Find(&results).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	appTypes := []string{}
	for _, r := range results {
		if r.AppType != nil {
			appTypes = append(appTypes, *r.AppType)
		}

	}
	return appTypes, nil
}

func (rl *TensorResourcesService) GetAppVersions(ctx context.Context, clusterKey, appType string) ([]string, error) {
	db := rl.rdb.GetReadDB().WithContext(ctx)
	results := []*model.TensorContainer{}
	if clusterKey != "" {
		db = db.Where("cluster_key = ?", clusterKey)
	}
	if appType != "" {
		db = db.Where("app_type = ?", appType)
	}
	err := db.Distinct("app_target_version").Find(&results).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	appVers := []string{}
	for _, r := range results {
		if r.AppTargetVersion != nil {
			appVers = append(appVers, *r.AppTargetVersion)
		}
	}
	return appVers, nil
}

func (rl *TensorResourcesService) GetAppTargets(ctx context.Context, clusterKey, appType string) ([]string, error) {
	db := rl.rdb.GetReadDB().WithContext(ctx)
	results := []*model.TensorContainer{}
	if clusterKey != "" {
		db = db.Where("cluster_key = ?", clusterKey)
	}
	if appType != "" {
		db = db.Where("app_type = ?", appType)
	}
	err := db.Distinct("app_target_name").Find(&results).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	appTargets := []string{}
	for _, r := range results {
		if r.AppTargetName != nil {
			appTargets = append(appTargets, *r.AppTargetName)
		}
	}
	return appTargets, nil
}

type NamespaceLabel struct {
	Namespace  string `json:"namespace"`
	ClusterKey string `json:"cluster_key"`
	LabelName  string `json:"label_name"`
	LabelValue string `json:"label_value"`
}

func (rl *TensorResourcesService) AddNamespaceLabel(ctx context.Context, data NamespaceLabel) error {
	if dal.IsBlockLabel(data.LabelName) {
		return errors.New("该标签名已被锁定，不允许添加")
	}
	labelId := util.GenerateUUID(data.ClusterKey, data.Namespace, data.LabelName)
	var label model.TensorNamespaceLabel
	err := rl.rdb.GetReadDB().Find(&label, labelId).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		return err
	}
	if label.ID > 0 {
		return errors.New("标签名重复")
	}
	// 	grpc
	rCtx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	errResp, err := rl.stream.SetNamespaceLabel(rCtx, data.ClusterKey, &pb.NamespaceLabelSetReq{
		Namespace:  data.Namespace,
		ClusterKey: data.ClusterKey,
		Name:       data.LabelName,
		Value:      data.LabelValue,
	})
	if err != nil {
		logging.Get().Error().Msgf("add ns's label failed. grpc err:%w ", err)
		return fmt.Errorf("新增失败")
	}
	if errResp.GetErrMsg() != "" {
		logging.Get().Error().Msgf("add ns's label failed. ErrMsg :%w ", errResp.GetErrMsg())
		return fmt.Errorf("新增失败")
	}
	// check
	for true {
		select {
		case <-ctx.Done():
			return errors.New("检测超时，请稍后查看")
		default:
			time.Sleep(time.Millisecond * 500)
			isOk := rl.checkNamespaceLabelUntil(ctx, CheckNsLabel{
				Action:     "add",
				ClusterKey: data.ClusterKey,
				Namespace:  data.Namespace,
				LabelName:  data.LabelName,
				LabelValue: data.LabelValue,
			})
			if isOk {
				return nil
			}
		}
	}
	return nil
}

func (rl *TensorResourcesService) UpdateNamespaceLabel(ctx context.Context, labelId int64, newValue string) error {
	var label model.TensorNamespaceLabel
	err := rl.rdb.GetReadDB().Find(&label, labelId).Error
	if err != nil {
		return err
	}
	if label.ID == 0 {
		return errors.New("标签不存在")
	}
	if dal.IsBlockLabel(label.Name) {
		return errors.New("该标签名已被锁定，不允许修改")
	}
	// 	grpc
	rCtx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	errResp, err := rl.stream.SetNamespaceLabel(rCtx, label.ClusterKey, &pb.NamespaceLabelSetReq{
		Namespace:  label.Namespace,
		ClusterKey: label.ClusterKey,
		Name:       label.Name,
		Value:      newValue,
	})
	if err != nil {
		logging.Get().Error().Msgf("update ns's label failed. grpc err:%w ", err)
		return fmt.Errorf("更新失败")
	}
	if errResp.GetErrMsg() != "" {
		logging.Get().Error().Msgf("update ns's label failed. ErrMsg:%w ", errResp.GetErrMsg())
		return fmt.Errorf("更新失败")
	}
	// check
	for true {
		select {
		case <-ctx.Done():
			return errors.New("检测超时，请稍后查看")
		default:
			time.Sleep(time.Millisecond * 500)
			isOk := rl.checkNamespaceLabelUntil(ctx, CheckNsLabel{
				Action:     "update",
				ClusterKey: label.ClusterKey,
				Namespace:  label.Namespace,
				LabelName:  label.Name,
				LabelValue: newValue,
			})
			if isOk {
				return nil
			}
		}
	}
	return nil
}

func (rl *TensorResourcesService) DeleteNamespaceLabel(ctx context.Context, labelId int64) error {
	var label model.TensorNamespaceLabel
	err := rl.rdb.GetReadDB().Find(&label, labelId).Error
	if err != nil {
		return err
	}
	if label.ID == 0 {
		return nil
	}
	if dal.IsBlockLabel(label.Name) {
		return errors.New("该标签名已被锁定，不允许删除")
	}
	// 	grpc
	rCtx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	errResp, err := rl.stream.DeleteNamespaceLabel(rCtx, label.ClusterKey, &pb.NamespaceLabelSetReq{
		Namespace:  label.Namespace,
		ClusterKey: label.ClusterKey,
		Name:       label.Name,
	})
	if err != nil {
		logging.Get().Error().Msgf("delete ns's label failed. grpc err:%w ", err)
		return fmt.Errorf("删除失败")
	}
	if errResp.GetErrMsg() != "" {
		logging.Get().Error().Msgf("delete ns's label failed. ErrMsg:%w ", errResp.GetErrMsg())
		return fmt.Errorf("删除失败")
	}
	// check
	for true {
		select {
		case <-ctx.Done():
			return errors.New("检测超时，请稍后查看")
		default:
			time.Sleep(time.Millisecond * 500)
			isOk := rl.checkNamespaceLabelUntil(ctx, CheckNsLabel{
				Action:     "delete",
				ClusterKey: label.ClusterKey,
				Namespace:  label.Namespace,
				LabelName:  label.Name,
				LabelValue: label.Value,
			})
			if isOk {
				return nil
			}
		}
	}
	return nil
}

type CheckNsLabel struct {
	Action     string
	ClusterKey string `json:"cluster_key"`
	Namespace  string `json:"namespace"`
	LabelName  string `json:"label_name"`
	LabelValue string `json:"label_value"`
}

func (rl *TensorResourcesService) checkNamespaceLabelUntil(ctx context.Context, check CheckNsLabel) bool {
	if check.Action == "" {
		return false
	}
	var label model.TensorNamespaceLabel
	rl.rdb.GetReadDB().WithContext(ctx).Where("cluster_key = ? and namespace = ? and name =? and value=?", check.ClusterKey, check.Namespace, check.LabelName, check.LabelValue).
		Take(&label)
	if check.Action == "delete" {
		if label.ID == 0 {
			return true
		}
		return false
	}
	// add ,update
	if label.ID != 0 {
		return true
	}
	return false
}

func (rl *TensorResourcesService) GetEnableAssetsTagList(ctx context.Context) ([]*model.TensorAssetsTag, error) {
	apps, err := dal.GetEnableAssetsTagList(ctx, rl.rdb.Get())
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (rl *TensorResourcesService) GetAssetsTagListWithCount(ctx context.Context, tagName string, offset int, limit int) ([]*dal.TensorAssetsTagWithRelCounts, int64, error) {
	apps, err := dal.GetAssetsTagList(ctx, rl.rdb.Get(), tagName, offset, limit)
	if err != nil {
		return nil, -1, err
	}

	cnt, err := dal.CountAssetsTag(ctx, rl.rdb.Get(), tagName)
	if err != nil {
		return nil, -1, err
	}

	return apps, cnt, nil
}

type ChangeAssetsTagStatus struct {
	EnableTagIds  []string `json:"enableTagIds"`
	DisableTagIds []string `json:"disableTagIds"`
}

func (rl *TensorResourcesService) ChangeAssetsTagStatus(ctx context.Context, request ChangeAssetsTagStatus) error {
	return dal.ChangeAssetsTagStatus(ctx, rl.rdb.Get(), request.EnableTagIds, request.DisableTagIds)
}

func (rl *TensorResourcesService) GetAssetsTagRelCounts(ctx context.Context, tagId string) (detail *dal.AssetsTagWithIdsCounts, err error) {
	return dal.GetAssetsTagRelIdsCounts(ctx, rl.rdb.Get(), tagId)
}

func (rl *TensorResourcesService) SaveAssetsTagRel(ctx context.Context, detail *dal.AssetsTagRelDetail) (err error) {
	return dal.SaveAssetsTagRel(ctx, rl.rdb.Get(), detail)
}

func (rl *TensorResourcesService) DeleteAssetsTag(ctx context.Context, tagId string) (err error) {
	return dal.DeleteAssetsTag(ctx, rl.rdb.Get(), tagId)
}

func (rl *TensorResourcesService) AssetsChangeTags(ctx context.Context, req *dal.AssetsChangeTagsReq) (err error) {
	return dal.AssetsChangeTags(ctx, rl.rdb.Get(), req)
}

func (rl *TensorResourcesService) GetAssetsCustomTags(ctx context.Context) ([]*model.TensorAssetsTag, error) {
	return dal.GetAssetsCustomTags(ctx, rl.rdb.Get())
}

// 查询资产对应的tag列表
func (rl *TensorResourcesService) GetTagsMapByAssetsIds(ctx context.Context, objType model.TagRelObjType, objIds []string) (map[string][]string, error) {
	relOnes, err := dal.GetTagsByAssetsIds(ctx, rl.rdb.Get(), objType, objIds)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string)
	for _, rel := range relOnes {
		tags := result[rel.ObjId]
		tags = append(tags, rel.TagName)
		result[rel.ObjId] = tags
	}
	return result, nil
}

// 查询 某个tag下的 各种类型资产的数量
func (rl *TensorResourcesService) GetAssetsCountInTag(ctx context.Context, tagId string) (*dal.AssetsTagWithCounts, error) {
	return dal.GetAssetsTagRelCounts(ctx, rl.rdb.Get(), tagId)
}
