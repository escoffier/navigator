package reporter

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func LoadAssetsReport(ctx context.Context, db *rdbtools.GormWrapper, clusterItems []*model.ClusterItem, endTimestamp int64) *model.AssetsReport {
	var result = &model.AssetsReport{Clusters: clusterItems}
	clusterHash := GenerateClusterKeyHash(clusterItems)
	var clusters = make([]string, 0, len(clusterHash))
	for clusterKey := range clusterHash {
		clusters = append(clusters, clusterKey)
	}

	timeFilter := util.GetTimeByMillisecondTimestamp(endTimestamp)
	result.Nodes = getNodes(ctx, db, clusters, timeFilter, clusterHash)
	result.Containers = getContainers(ctx, db, clusters, timeFilter, clusterHash)

	return result
}

func GenerateClusterKeyHash(clusters []*model.ClusterItem) map[string]string {
	result := make(map[string]string)
	for _, cluster := range clusters {
		result[cluster.Key] = cluster.Name
	}

	return result
}

func GetClusters(ctx context.Context, db *rdbtools.GormWrapper, clusterFilter []string, timeFilter time.Time) []*model.ClusterItem {
	var clusters []*model.TensorCluster
	get := func() error {
		oneCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		return db.Get().WithContext(oneCtx).
			Where("id in (?) and created_at <= ? and status = 0", clusterFilter, timeFilter).
			Select("name, id, created_at").Find(&clusters).Error
	}

	if err := util.RetryWithBackoff(ctx, get); err != nil {
		logrus.Errorf("getClusters fail, err:%s", err)
		return nil
	}

	var result = make([]*model.ClusterItem, len(clusters))
	for i := range clusters {
		result[i] = &model.ClusterItem{}
		result[i].Name = clusters[i].Name
		result[i].Key = clusters[i].Key
		result[i].CreatedAt = util.GetMillisecondTimestampByTime(clusters[i].CreatedAt)
	}

	return result
}

func getNodes(ctx context.Context, db *rdbtools.GormWrapper, clusterFilter []string, timeFilter time.Time, clusterNameHash map[string]string) []*model.NodeItem {
	var nodes []*model.TensorNode
	get := func() error {
		oneCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return db.Get().WithContext(oneCtx).
			Where("cluster_key in (?) and created_at <= ? and status = 0", clusterFilter, timeFilter).
			Select("host_name, cluster_key").Find(&nodes).Error
	}

	if err := util.RetryWithBackoff(ctx, get); err != nil {
		logrus.Errorf("getNodes fail, err:%s", err)
		return nil
	}

	var result = make([]*model.NodeItem, 0, len(nodes))
	for i := range nodes {
		clusterName := clusterNameHash[nodes[i].ClusterKey]
		if clusterName == "" {
			continue
		}
		result = append(result, &model.NodeItem{
			Name:    nodes[i].HostName,
			Cluster: clusterName,
		})
	}

	return result
}

func getContainers(ctx context.Context, db *rdbtools.GormWrapper, clusterFilter []string, timeFilter time.Time, clusterNameHash map[string]string) []*model.ContainerItem {
	var containers []*model.TensorContainer
	get := func() error {
		oneCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return db.Get().WithContext(oneCtx).Where("cluster_key in (?) and created_at <= ? and status = 0", clusterFilter, timeFilter).
			Select("name, type, resource_name, namespace, cluster_key, created_at").Find(&containers).Error
	}

	if err := util.RetryWithBackoff(ctx, get); err != nil {
		logrus.Errorf("getContainers fail, err:%s", err)
		return nil
	}

	var result = make([]*model.ContainerItem, 0, len(containers))
	for i := range containers {
		clusterName := clusterNameHash[containers[i].ClusterKey]
		if clusterName == "" {
			continue
		}
		result = append(result, &model.ContainerItem{
			Name:         containers[i].Name,
			Type:         containers[i].Type,
			ResourceName: containers[i].ResourceName,
			Namespace:    containers[i].Namespace,
			Cluster:      clusterName,
			CreatedAt:    util.GetMillisecondTimestampByTime(containers[i].CreatedAt),
		})
	}

	return result
}
