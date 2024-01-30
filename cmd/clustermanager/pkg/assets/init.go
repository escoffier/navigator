package assets

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/monitor"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	rsearch "github.com/March-deng/godisearch/redisearch"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/cast"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/redisearch"
)

var (
	initOnce sync.Once
	initErr  error
	// wInstance *assets.Watcher
	wInstance *pkgassets.Watcher

	disableKubeMonitor = false

	redisSynchronizationFunc = map[string]func(*databases.RDBInstance, *redisearch.Client, int) error{
		"resource":     SyncResourceToRedis,
		"pod":          SyncPodToRedis,
		"rawContainer": SyncRawContainerToRedis,
	}
)

func init() {
	disableFlag := os.Getenv("DISABLE_KUBE_MONITOR")
	if disableFlag == "1" {
		disableKubeMonitor = true
	}
}

// Watcher singleton
func Watcher(rdb *databases.RDBInstance,
	redisCli *redis.Client,
	searchClient *redisearch.Client,
	scannerURL string,
	reader mq.Reader,
	topic, groupID string,
) (*pkgassets.Watcher, error) {
	if rdb == nil || redisCli == nil || scannerURL == "" {
		return nil, errors.New("illegal argument")
	}
	initOnce.Do(func() {
		if searchClient == nil {
			return
		}
		wg := sync.WaitGroup{}
		startSync := time.Now()
		for _, index := range AssetIndices {
			wg.Add(1)
			go func(indexS redisearch.RedisIndexSchema) {
				defer wg.Done()
				logging.Get().Info().Msgf("checking %s index from redis", indexS.Name)
				ctx := context.Background()
				needSync := false
				_, err := searchClient.Info(ctx, indexS.Name)
				if err != nil && err != redisearch.ErrIndexNotFound {
					initErr = err
					return
				}

				if err == redisearch.ErrIndexNotFound {
					needSync = true
				}

				err = searchClient.CreateIndex(ctx, &indexS)
				if err != nil {
					logging.Get().Info().Msgf("CreateIndex err")
					initErr = err
					return
				}
				if needSync && redisSynchronizationFunc[indexS.Name] != nil {
					logging.Get().Info().Msgf("%s need to sync to redis", indexS.Name)
					if syncErr := redisSynchronizationFunc[indexS.Name](rdb, searchClient, 1000); syncErr != nil {
						initErr = syncErr
						return
					}
				}
			}(*index)
		}
		wg.Wait()
		logging.Get().Info().Msgf("sync assets to redis costs: %d ms", time.Now().Sub(startSync).Milliseconds())
		if initErr != nil {
			logging.Get().Err(initErr).Msgf("sync assets to redis failed.")
			return
		}

		logging.Get().Info().Msgf("Init assets.Watcher: stack = %s", debug.Stack())
		wInstance = pkgassets.NewWatcher(reader, topic, groupID)
		wInstance.AddCallback(newPodResourcesService(redisCli, rdb, searchClient))
		wInstance.AddCallback(microseg.NewResourcesListener(rdb))
		if !disableKubeMonitor {
			kbm, err := kubemonitor.NewService()
			if err == nil {
				wInstance.AddCallback(kbm.RiskMonitor())
			} else {
				logging.Get().Err(err).Msg("init kube monitor error")
			}
		} else {
			logging.Get().Warn().Msg("Kube Monitor is disabled according to the enviroment var")
		}

		wInstance.AddCallback(newResourcesWatcher(rdb, scannerURL, searchClient))
		wInstance.AddCallback(newHoneyspotService(rdb))
		wInstance.AddCallback(newRawContainerWatcher(rdb, searchClient))
		wInstance.AddCallback(monitor.NewContainerStatusWatch(rdb))
		exportContainers := os.Getenv("EXPORT_CONTAINERS")
		if exportContainers == "true" {
			wInstance.AddCallback(newPodContainerWatcher(rdb))
		}
	})
	return wInstance, initErr
}

func SyncResourceToRedis(rdb *databases.RDBInstance, redisearchClis *redisearch.Client, size int) error {
	db := rdb.Get()
	ic, err := redisearchClis.GetIndexClient("resource")
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("sync resource to redis, size: %d", size)

	var (
		minID    uint32
		cursor   uint32
		total    int64
		finished int64
	)

	m := &model.TensorResource{}

	// 首选查询出总数
	err = db.Model(m).Where("status = ? ", 0).Count(&total).Error
	if err != nil {
		return err
	}

	resources := make([]*model.TensorResource, 0)

	// 查询最小的id
	err = db.Model(m).Where("status = ?", 0).Order("id asc").Limit(1).Find(&resources).Error
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return nil
	}

	minID = resources[0].ID

	logging.Get().Info().Msgf("got %d resources, min resource id: %d \n", total, minID)

	ctx := context.Background()
	cursor = minID - 1

	docList := make([]rsearch.Document, size)
	for finished < total {
		resources = resources[:0]
		tmpDb := db.Model(m).Select("id", "name", "namespace", "cluster_key", "kind", "generation", "updated_at", "pod_template").
			Where("status = ? ", 0).Limit(size).Order("id asc")
		err = tmpDb.Where("id > ?", cursor).Find(&resources).Error
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return nil
		}
		for i, resource := range resources {
			imageList := make([]string, 0)
			for _, image := range resource.Images() {
				imageList = append(imageList, cast.ToString(image))
			}

			docList[i] = rsearch.NewDocument(fmt.Sprintf("resource:%d", resource.ID), 1).
				Set("id", resource.ID).
				Set("name", resource.Name).
				Set("namespace", resource.Namespace).
				Set("cluster_key", resource.ClusterKey).
				Set("kind", resource.Kind).
				Set("generation", resource.Generation).
				Set("updated_at", resource.UpdatedAt.UnixMilli()).
				Set("images", strings.Join(imageList, ","))
			err = addResourceImages(ctx, ic, resource.ID, resource.Images())
			if err != nil {
				logging.Get().Fatal().Msgf("err occured when add %d resource images to redis, err: %v", resource.ID, err)
			}
		}

		err = ic.AddDoc(ctx, docList[:len(resources)]...)
		if err != nil {
			logging.Get().Fatal().Msgf("err occured when sync resource to redis, err: %v", err)
		}
		cursor = resources[len(resources)-1].ID
		finished += int64(len(resources))

		logging.Get().Info().Msgf("finished: %d, total: %d, %d/%d, percentage: %.2f, next start point: %d \n", finished, total, finished, total, float64(finished)/float64(total), cursor)
	}

	return nil
}

func addResourceImages(ctx context.Context, redisClient *rsearch.Client, resourceID uint32, images []uint32) error {
	if len(images) == 0 {
		return nil
	}
	conn, err := redisClient.GetConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	args := make([]interface{}, 0)
	args = append(args, "container_images")

	for _, image := range images {
		args = append(args, image, fmt.Sprintf("%d/%d", resourceID, image))
	}

	_, err = conn.Do("ZADD", args...)

	return err
}

func SyncPodToRedis(rdb *databases.RDBInstance, redisearchClis *redisearch.Client, size int) error {
	db := rdb.Get()
	ic, err := redisearchClis.GetIndexClient("pod")
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("sync pods to redis, size: %d", size)

	var (
		minID    uint32
		cursor   uint32
		total    int64
		finished int64
	)

	m := &model.PodResourceRelation{}

	// 首选查询出总数
	err = db.Model(m).Where("status = ? ", 0).Count(&total).Error
	if err != nil {
		return err
	}

	pods := make([]*model.PodResourceRelation, 0)

	// 查询最小的id
	err = db.Model(m).Where("status = ?", 0).Order("id asc").Limit(1).Find(&pods).Error
	if err != nil {
		return err
	}

	if len(pods) == 0 {
		panic("no resources found")
	}

	minID = pods[0].ID
	logging.Get().Info().Msgf("got %d pods, min pod id: %d \n", total, minID)

	ctx := context.Background()
	cursor = minID - 1

	docList := make([]rsearch.Document, size)
	for finished < total {
		pods = pods[:0]
		tmpDb := db.Model(m).Select("id", "pod_name", "cluster_key", "node_name", "resource_kind", "resource_name", "namespace", "pod_ip", "updated_at", "created_at").
			Where("status = ? ", 0).Limit(size).Order("id asc")
		err = tmpDb.Where("id > ?", cursor).Find(&pods).Error
		if err != nil {
			return err
		}
		if len(pods) == 0 {
			return nil
		}

		for i, rel := range pods {
			docID := fmt.Sprintf("pod:%d", rel.ID)

			docList[i] = rsearch.NewDocument(docID, 1).
				Set("id", rel.ID).
				Set("pod_name", rel.PodName).
				Set("cluster_key", rel.ClusterKey).
				Set("node_name", rel.NodeName).
				Set("resource_kind", rel.ResourceKind).
				Set("resource_name", rel.ResourceName).
				Set("namespace", rel.Namespace).
				Set("pod_ip", rel.PodIP).
				Set("updated_at", rel.UpdatedAt.UnixMilli()).
				Set("created_at", rel.CreatedAt.UnixMilli())
		}

		err = ic.AddDoc(ctx, docList[:len(pods)]...)
		if err != nil {
			panic(fmt.Sprintf("err occured when sync pod to redis, err: %v", err))
		}
		cursor = pods[len(pods)-1].ID
		finished += int64(len(pods))

		logging.Get().Info().Msgf("finished: %d, total: %d, %d/%d, percentage: %.2f, next start point: %d \n", finished, total, finished, total, float64(finished)/float64(total), cursor)
	}
	return nil
}

func SyncRawContainerToRedis(rdb *databases.RDBInstance, redisearchClis *redisearch.Client, size int) error {
	db := rdb.Get()
	ic, err := redisearchClis.GetIndexClient("rawContainer")
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("sync rawContainer to redis, size: %d", size)
	var (
		minID    string
		cursor   string
		total    int64
		finished int64
	)

	m := &model.TensorRawContainer{}

	// 首选查询出总数
	err = db.Model(m).Where("status < ? ", 5).Count(&total).Error
	if err != nil {
		return err
	}

	containers := make([]*model.TensorRawContainer, 0)

	// 查询最小的id
	err = db.Model(m).Where("status < ?", 5).Order("id asc").Limit(1).Find(&containers).Error
	if err != nil {
		return err
	}

	if len(containers) == 0 {
		panic("no resources found")
	}

	minID = containers[0].ContainerID

	logging.Get().Info().Msgf("got %d raw containers, min container id: %s \n", total, minID)

	var include = true
	cursor = minID

	ctx := context.Background()

	docList := make([]rsearch.Document, size)
	for finished < total {
		tmpDb := db.Model(m).Where("status < ?", 5).Limit(size).Order("id asc").
			Select("id", "status", "cluster_key", "k8s_managed", "node_name", "namespace", "pod_name", "name", "resource_name", "updated_at")
		containers = containers[:0]
		if include {
			err = tmpDb.Where("id >= ?", cursor).Find(&containers).Error
		} else {
			err = tmpDb.Where("id > ?", cursor).Find(&containers).Error
		}

		if err != nil {
			return err
		}
		if len(containers) == 0 {
			return nil
		}

		for i, container := range containers {
			docList[i] = rsearch.NewDocument(fmt.Sprintf("rawContainer:%s", container.ContainerID), 1).
				Set("id", container.ContainerID).
				Set("status", pkgassets.GetRawContainerStatus(int(container.Status))).
				Set("cluster_key", container.ClusterKey).
				Set("k8s_managed", strconv.FormatBool(container.K8sManaged)).
				Set("node_name", container.NodeName).
				Set("namespace", container.Namespace).
				Set("pod_name", container.PodName).
				Set("name", container.Name).
				Set("resource_name", container.ResourceName).
				Set("updated_at", container.UpdatedAt.UnixMilli())
		}
		err = ic.AddDoc(ctx, docList[:len(containers)]...)
		if err != nil {
			panic(fmt.Sprintf("err occured when sync  raw container to redis, err: %v", err))
		}
		cursor = containers[len(containers)-1].ContainerID
		finished += int64(len(containers))
		include = false
		logging.Get().Info().Msgf("finished: %d, total: %d, %d/%d, percentage: %.2f, next start point: %s \n", finished, total, finished, total, float64(finished)/float64(total), cursor)
	}

	return nil
}
