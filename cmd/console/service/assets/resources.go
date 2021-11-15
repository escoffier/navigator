package assets

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

var (
	instance *TensorResourcesService
	rlOnce   sync.Once
)

func InitResourcesService(postgre *rdbtools.GormWrapper, scannerURL string) error {
	rlOnce.Do(func() {
		instance = newTensorResourcesService(postgre, scannerURL)
	})
	return nil
}

func GetResourcesService(ctx context.Context) (*TensorResourcesService, bool) {
	return instance, instance != nil
}

type TensorResourcesService struct {
	rdb        *rdbtools.GormWrapper
	scannerURL string
}

func newTensorResourcesService(rdb *rdbtools.GormWrapper, scannerURL string) *TensorResourcesService {
	return &TensorResourcesService{
		rdb:        rdb,
		scannerURL: scannerURL,
	}
}

func (rl *TensorResourcesService) GetClusters(ctx context.Context, offset, limit int) ([]*model.TensorCluster, int64, error) {
	return dal.GetClusters(ctx, rl.rdb, offset, limit)
}

func (rl *TensorResourcesService) GetClusterByKey(ctx context.Context, key string) *model.TensorCluster {
	return dal.GetClustersByKey(ctx, rl.rdb, key)
}

func (rl *TensorResourcesService) AddCluster(ctx context.Context, cluster *model.TensorCluster) error {
	// TODO create the k8s client and so on
	return dal.AddCluster(ctx, rl.rdb, cluster)
}

func (rl *TensorResourcesService) UpdateCluster(ctx context.Context, clusterKey, newClusterName, newDescription string) error {
	return dal.UpdateCluster(ctx, rl.rdb, clusterKey, newClusterName, newDescription)
}

func (rl *TensorResourcesService) DeleteCluster(ctx context.Context, clusterKey string) error {
	return dal.DeleteCluster(ctx, rl.rdb, clusterKey)
}

func (rl *TensorResourcesService) GetResources(ctx context.Context, queryOptions *dal.ResourcesQueryOption, offset, limit int) ([]*model.TensorResource, int64, error) {
	resources, err := dal.GetResources(ctx, rl.rdb, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	resCnt, err := dal.CountResources(ctx, rl.rdb, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return resources, resCnt, nil
}

func (rl *TensorResourcesService) CountResource(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (int64, error) {
	resCnt, err := dal.CountResources(ctx, rl.rdb, queryOptions)
	if err != nil {
		return 0, err
	}

	return resCnt, nil
}

func (rl *TensorResourcesService) UpdateResourceUserData(ctx context.Context, res *model.TensorResource) error {
	return dal.UpdateResourceUserData(ctx, rl.rdb, res)
}

func (rl *TensorResourcesService) GetResourceMap(ctx context.Context, queryOptions *dal.ResourcesQueryOption) (map[dal.ResourceKey]*model.TensorResource, error) {
	res, err := dal.GetResources(ctx, rl.rdb, queryOptions, -1, -1)
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
	ns, err := dal.GetNamespacesByCluster(ctx, rl.rdb, clusterKey, nameQuery, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountNamespaces(ctx, rl.rdb, clusterKey, nameQuery)
	if err != nil {
		return nil, 0, err
	}
	return ns, cnt, nil
}

func (rl *TensorResourcesService) CountNamespaces(ctx context.Context, clusterKey, nameQuery string) (int64, error) {
	cnt, err := dal.CountNamespaces(ctx, rl.rdb, clusterKey, nameQuery)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) UpdateNamespaces(ctx context.Context, clusterKey, name, alias string, manager []string, authority string) error {
	err := dal.UpdateNamespace(ctx, rl.rdb, clusterKey, name, alias, manager, authority)
	return err
}

func (rl *TensorResourcesService) GetResourcePods(ctx context.Context, queryOptions *dal.ResPodsQueryOption, offset, limit int) ([]*model.PodResourceRelation, int64, error) {
	pods, err := dal.GetResourcePodsList(ctx, rl.rdb, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountPods(ctx, rl.rdb, queryOptions, offset, limit)
	return pods, cnt, err
}

func (rl *TensorResourcesService) CountPods(ctx context.Context, queryOptions *dal.ResPodsQueryOption) (int64, error) {
	cnt, err := dal.CountPods(ctx, rl.rdb, queryOptions, 0, -1)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) GetResourceContainers(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]*model.TensorContainer, int64, error) {
	containers, err := dal.GetResourceContainers(ctx, rl.rdb, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	cnt, err := dal.CountResourceContainers(ctx, rl.rdb, queryOptions)
	return containers, cnt, err
}

func (rl *TensorResourcesService) CountContainer(ctx context.Context, queryOptions *dal.ResContainersQueryOption) (int64, error) {
	cnt, err := dal.CountResourceContainers(ctx, rl.rdb, queryOptions)
	if err != nil {
		return 0, err
	}
	return cnt, nil
}

func (rl *TensorResourcesService) GetNodes(ctx context.Context, queryOptions *dal.NodeQueryOption, offset, limit int) ([]*model.TensorNode, error) {
	return dal.GetNodes(ctx, rl.rdb.Get(), queryOptions, offset, limit)
}

func (rl *TensorResourcesService) CountNodes(ctx context.Context, queryOptions *dal.NodeQueryOption) (int64, error) {
	return dal.CountNodes(ctx, rl.rdb.Get(), queryOptions)
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

func (rl *TensorResourcesService) GetFramework(ctx context.Context, imageId uint32) (*model.WebFrameScan, error) {
	return dal.GetFramework(ctx, rl.rdb.Get(), imageId)
}

func (rl *TensorResourcesService) GetFrameworks(ctx context.Context) ([]*model.WebFrameScan, error) {
	return dal.GetFrameworks(ctx, rl.rdb.Get())
}
