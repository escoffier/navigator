package behaviorallearn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/ws"

	"time"

	es "github.com/olivere/elastic/v7"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/id"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	configMapSize     = 5e3
	inModelConfigSize = 5e3
	wlsConfigSize     = 5e3
)

var (
	instance             *BehavioralLearn
	rlOnce               sync.Once
	globalConfig         *model.BehavioralLearnGlobalConfig
	globalResourceStatus = make(map[uint32]int)
)

type BehavioralLearn struct {
	taskLock sync.Mutex
	es       *elastic.ESClient
	// taskQueue                    []model.BehavioralLearnTaskItem
	learningConfigmapLock        sync.Mutex
	updateResourceConfigmapLock  sync.Mutex
	updateWhitelistConfigmapLock sync.Mutex
	rdb                          *databases.RDBInstance
}

func InitBLService(rdb *databases.RDBInstance, mqReader mq.Reader, es *elastic.ESClient) error {
	rlOnce.Do(func() {
		instance = NewBehavioralLearn(rdb, es)

		config, err := dal.BehavioralLearnGetGlobalConfig(context.Background(), rdb.GetReadDB())
		if err != nil {
			logging.GetLogger().Error().Msgf("get global config fail, err: %v", err)
			config = &model.BehavioralLearnGlobalConfig{
				IgnoreKnownAttack: true,
				AutoLearnNewRes:   false,
				LearnTime:         300,
				ShowUnrelatedRes:  true,
			}
		}
		initResourceStatus(context.Background(), rdb)
		globalConfig = config
		err = mqReader.Subscribe(
			model.SubjectOfBehavioralLearnEvent,
			"behavioral-learn",
			handleEvent,
		)
		if err != nil {
			logging.GetLogger().Err(err).Msg("subscribe behavioral learn event fail")
		}

		go instance.updateLearningConfigmapStatusLoop(context.Background())
	})
	return nil
}

func initResourceStatus(ctx context.Context, rdb *databases.RDBInstance) error {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
		return errors.New("get resource service fail")
	}
	res, _, err := resSvc.GetResources(ctx, dal.ResourcesQuery(), 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources fail, err: %v", err)
		return err
	}
	for _, r := range res {
		globalResourceStatus[r.ID] = int(r.BehavioralLearnStatus)
		if r.BehavioralLearnStatus == model.BehavioralLearningStatusEnabled {
			fileModel, commandModel, networkModel, err := dal.BehavioralLearnGetModelMix(context.Background(), instance.rdb.Get(), r.ID)
			if err != nil {
				logging.GetLogger().Error().Msgf("get model mix fail, err: %v", err)
			}

			// sync model to configmap
			err = instance.updateBehavioralLearnModelConfigMap(context.Background(), model.BehavioralLearnTaskItem{ResourceUUID: r.ID},
				fileModel, commandModel, networkModel)
			if err != nil {
				logging.GetLogger().Error().Msgf("update model config map fail, err: %v", err)
			}

		}
	}
	return nil
}
func handleEvent(ctx context.Context, m kafka.Message) error {
	var data model.BehavioralKafkaEvent
	// drop message tmp
	// logging.GetLogger().Debug().Str("receive msg:", fmt.Sprintf("%+v", m)).Msg("BehavioralLearn handleEvent")
	// return nil
	err := json.Unmarshal(m.Value, &data)
	if err != nil {
		logging.GetLogger().Err(err).Msg("json decode fail")
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	logging.GetLogger().Debug().Str("receive msg:", fmt.Sprintf("%+v", data)).Msg("BehavioralLearn handleEvent")
	err = dealEvent(ctx, data)
	if err != nil {
		logging.GetLogger().Err(err).Msg("update fail")
	}
	return err
}

func addModelFileModelFromEventToDB(ctx context.Context, data model.BehavioralKafkaEvent) error {
	inModel := false
	if data.LearningStatus == model.BehavioralLearningStatusRunning {
		inModel = true
	}

	fileModel := model.BehavioralLearnFileModel{
		ResourceUUID:  data.ResourceUUID,
		Name:          data.Name,
		Path:          data.Path,
		Permission:    data.Permission,
		IsInModel:     inModel,
		UpdatedAt:     data.CreatedAt,
		ContainerID:   data.ContainerID,
		ContainerName: data.ContainerName,
		Id:            data.SonyFlakeID,
	}
	_, err := dal.BehavioralLearnInsertFileModel(ctx, instance.rdb.Get(), fileModel)

	return err
}

func addModelNetworkModelFromEventToDB(ctx context.Context, data model.BehavioralKafkaEvent) error {
	inModel := false
	if data.LearningStatus == model.BehavioralLearningStatusRunning {
		inModel = true
	}
	networkModel := model.BehavioralLearnNetworkModel{
		ResourceUUID:      data.ResourceUUID,
		StreamDirection:   data.StreamDirection,
		ProcessName:       data.ProcessName,
		SourceResource:    data.SourceResource,
		DestResource:      data.DestResource,
		ClusterKey:        data.ClusterKey,
		ResourceNamespace: data.Namespace,
		ResourceKind:      data.Kind,
		ResourceName:      data.ResourceName,
		Port:              data.Port,
		IsInModel:         inModel,
		UpdatedAt:         data.CreatedAt,
		ContainerID:       data.ContainerID,
		ContainerName:     data.ContainerName,
		Id:                data.SonyFlakeID,
	}
	logging.GetLogger().Info().Msgf("add network model: %+v", networkModel)
	_, err := dal.BehavioralLearnInsertNetworkModel(ctx, instance.rdb.Get(), networkModel)
	return err

}

func addModelCommandModelFromEventToDB(ctx context.Context, data model.BehavioralKafkaEvent) error {
	inModel := false
	if data.LearningStatus == model.BehavioralLearningStatusRunning {
		inModel = true
	}

	commandModel := model.BehavioralLearnCommandModel{
		ResourceUUID:  data.ResourceUUID,
		Command:       data.Command,
		User:          data.User,
		Path:          data.Path,
		IsInModel:     inModel,
		UpdatedAt:     data.CreatedAt,
		ContainerID:   data.ContainerID,
		ContainerName: data.ContainerName,
		Id:            data.SonyFlakeID,
	}
	_, err := dal.BehavioralLearnInsertCommandModel(ctx, instance.rdb.Get(), commandModel)
	return err
}

// 监听学习事件
func dealEvent(ctx context.Context, data model.BehavioralKafkaEvent) error {
	bd, _ := json.Marshal(data)
	logging.GetLogger().Debug().Msgf("dealEvent BehavioralKafkaEvent: %d, %s", data.ResourceUUID, string(bd))
	data.SonyFlakeID = id.UInt64()
	updatedAt := time.Unix(data.CreatedAt, 0)
	now := time.Now()
	fmt.Println("---------------- send ----------------", updatedAt, now, now.Sub(updatedAt))
	syncEventToWS(data)
	switch data.EventType {
	case model.BehavioralLearnKafkaFileEvent:
		return addModelFileModelFromEventToDB(ctx, data)
	case model.BehavioralLearnKafkaCommandEvent:
		return addModelCommandModelFromEventToDB(ctx, data)
	case model.BehavioralLearnKafkaNetworkEvent:
		return addModelNetworkModelFromEventToDB(ctx, data)
	default:
		logging.GetLogger().Error().Msgf("unknown event type: %d", data.EventType)
	}
	return nil
}

// 同步学习事件给长链接
func syncEventToWS(data model.BehavioralKafkaEvent) {
	go ws.SendToWS(ws.BehaviorEvent{
		Type:                 ws.BehaviorLearnEventTypeAction,
		ResourceUUID:         data.ResourceUUID,
		BehavioralKafkaEvent: data,
	})
}

func NewBehavioralLearn(rdb *databases.RDBInstance, es *elastic.ESClient) *BehavioralLearn {
	return &BehavioralLearn{
		// taskQueue: make([]model.BehavioralLearnTaskItem, 0),
		rdb: rdb,
		es:  es,
	}
}

func GetBehavioralLearnService() (*BehavioralLearn, bool) {
	return instance, instance != nil
}

func (b *BehavioralLearn) GetResourcesStatus(ctx context.Context,
	namespace, resourceName, imageName string, clusterKey, resourceKind []string,
	startTime, endTime int64,
	limit, offset int, learnStatus []int8) ([]model.BehavioralLearnStatusMix, int64, error) {
	// sTime := time.Now().UnixMicro()
	var retRes []model.BehavioralLearnStatusMix
	res, n, err := dal.BehavioralLearnGetResourceStatus(ctx, b.rdb.GetReadDB(), namespace, resourceName, imageName, clusterKey, resourceKind, startTime, endTime, limit, offset, learnStatus, globalConfig.ShowUnrelatedRes)
	if err != nil {
		return nil, 0, err
	}

	// logging.GetLogger().Debug().Msgf("rets: %+v", res)

	for _, r := range res {
		tmpRes := model.BehavioralLearnStatusMix{
			ResourceUUID:             r.ID,
			BehavioralLearnStatus:    r.BehavioralLearnStatus,
			BehavioralLearnStartTime: r.BehavioralLearnStartTime,
			ClusterKey:               r.ClusterKey,
			Namespace:                r.Namespace,
			Kind:                     r.Kind,
			Name:                     r.Name,
		}
		containers, err := dal.BehavioralLearnRawContainers(ctx, b.rdb.GetReadDB(), r.ClusterKey, r.Namespace, r.Kind, r.Name, 0, 0)
		if err != nil {
			logging.GetLogger().Error().Msgf("get containers by uuid fail, uuid: %d", r.ID)
		}
		images := make([]string, 0)
		imageMap := make(map[string]struct{})
		for _, c := range containers {
			image := c.ImageName
			if _, ok := imageMap[image]; ok {
				continue
			}
			images = append(images, image)
			imageMap[image] = struct{}{}
		}
		tmpRes.Images = images
		notInModelCount, err := dal.BehavioralLearnGetAbnormalCount(ctx, b.rdb.GetReadDB(), r.ID)
		if err != nil {
			logging.GetLogger().Error().Msgf("get abnormal count fail, uuid: %d", r.ID)
		}
		tmpRes.NotInModelCount = notInModelCount
		retRes = append(retRes, tmpRes)
	}

	// logging.GetLogger().Debug().Msgf("get resources time: %v", time.Now().UnixMicro()-sTime)
	return retRes, n, nil
}

func (b *BehavioralLearn) GetResourcesFileModel(ctx context.Context, uuid uint32, searchStr string, permission int, isInModel bool,
	limit, offset int, startID uint64, cNames []string) ([]*model.BehavioralLearnFileModel, int64, error) {
	res, n, err := dal.BehavioralLearnFileModelQuery(ctx, b.rdb.GetReadDB(), uuid, searchStr, permission, isInModel, offset, limit, startID, cNames)
	return res, n, err
}

func (b *BehavioralLearn) GetResourcesCommandModel(ctx context.Context, uuid uint32, searchStr string, isInModel bool,
	limit, offset int, startID uint64, cNames []string) ([]*model.BehavioralLearnCommandModel, int64, error) {

	return dal.BehavioralLearnCommandModelQuery(ctx, b.rdb.GetReadDB(), uuid, searchStr, isInModel, offset, limit, startID, cNames)
}

func (b *BehavioralLearn) GetResourcesNetworkModel(ctx context.Context, uuid uint32, streamDirection, port int,
	searchStr string, isInModel bool, limit, offset int, startID uint64, cNames []string) ([]*model.BehavioralLearnNetworkModel, int64, error) {

	return dal.BehavioralLearnNetworkModelQuery(ctx, b.rdb.GetReadDB(), uuid, streamDirection, port, searchStr, isInModel, offset, limit, startID, cNames)
}

func (b *BehavioralLearn) UpdateResourcesFileModel(ctx context.Context, data model.BehavioralLearnFileModel) (model.TensorResource, error) {
	res, err := dal.BehavioralLearnUpdateFileModel(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update file model fail, err: %v", err)
		return model.TensorResource{}, err
	}

	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(data.Id)),
		fmt.Sprintf(model.BehavioralLearnFileModelValueTemplate, data.Path, data.Permission, res.ContainerName))
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}

	query := dal.ResourcesQuery()
	query = query.WithID(res.ResourceUUID)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
	}

	resources, _, err := resSvc.GetResources(ctx, query, 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources by uuid fail, uuid: %d", res.ResourceUUID)
		return model.TensorResource{}, err
	}
	return *resources[0], nil
}

func (b *BehavioralLearn) UpdateResourcesCommandModel(ctx context.Context, data model.BehavioralLearnCommandModel) (model.TensorResource, error) {
	res, err := dal.BehavioralLearnUpdateCommandModel(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update command model fail, err: %v", err)
		return model.TensorResource{}, err
	}

	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(data.Id)),
		fmt.Sprintf(model.BehavioralLearnCommandModelValueTemplate, data.Command, data.User, res.ContainerName))
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}

	query := dal.ResourcesQuery()
	query = query.WithID(res.ResourceUUID)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
	}

	resources, _, err := resSvc.GetResources(ctx, query, 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources by uuid fail, uuid: %d", res.ResourceUUID)
		return model.TensorResource{}, err
	}

	return *resources[0], nil
}

func (b *BehavioralLearn) UpdateResourcesNetworkModel(ctx context.Context, data model.BehavioralLearnNetworkModel) (model.TensorResource, error) {
	res, err := dal.BehavioralLearnUpdateNetworkModel(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update network model fail, err: %v", err)
		return model.TensorResource{}, err
	}

	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(data.Id)),
		fmt.Sprintf(model.BehavioralLearnNetworkModelValueTemplate, data.ClusterKey, data.ResourceKind,
			data.ResourceNamespace, data.ResourceName, data.Port, data.StreamDirection, res.ContainerName, res.ProcessName))
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}

	query := dal.ResourcesQuery()
	query = query.WithID(res.ResourceUUID)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
	}

	resources, _, err := resSvc.GetResources(ctx, query, 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources by uuid fail, uuid: %d", res.ResourceUUID)
		return model.TensorResource{}, err
	}
	return *resources[0], nil
}

func (b *BehavioralLearn) InsertResourcesFileModels(ctx context.Context, data []model.BehavioralLearnFileModel) ([]model.BehavioralLearnFileModel, error) {
	for index, _ := range data {
		data[index].Id = id.UInt64()
	}
	res, err := dal.BehavioralLearnInsertFileModels(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert file model fail, err: %v", err)
		return res, err
	}

	// sync config map
	if len(res) > 0 {
		uuid := data[0].ResourceUUID
		keysMap := make(map[string]string)
		for _, r := range res {
			keysMap[fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(r.Id))] =
				fmt.Sprintf(model.BehavioralLearnFileModelValueTemplate, r.Path, r.Permission, r.ContainerName)
		}
		err = b.BehavioralLearnModelUpdateKeyMaps(ctx, uuid, keysMap)
		if err != nil {
			logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
		}
	}

	return res, nil
}

func (b *BehavioralLearn) InsertResourcesCommandModels(ctx context.Context, data []model.BehavioralLearnCommandModel) ([]model.BehavioralLearnCommandModel, error) {

	for index, _ := range data {
		data[index].Id = id.UInt64()
	}

	res, err := dal.BehavioralLearnInsertCommandModels(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert command model fail, err: %v", err)
		return res, err
	}

	//sync config map
	if len(res) > 0 {
		uuid := data[0].ResourceUUID

		keysMap := make(map[string]string)
		for _, r := range res {
			keysMap[fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(r.Id))] =
				fmt.Sprintf(model.BehavioralLearnCommandModelValueTemplate, r.Command, r.User, r.ContainerName)
		}
		err = b.BehavioralLearnModelUpdateKeyMaps(ctx, uuid, keysMap)

		if err != nil {
			logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
		}
	}
	return res, nil
}

func (b *BehavioralLearn) InsertResourcesNetworkModels(ctx context.Context, data []model.BehavioralLearnNetworkModel) ([]model.BehavioralLearnNetworkModel, error) {

	for index, _ := range data {
		data[index].Id = id.UInt64()
	}

	res, err := dal.BehavioralLearnInsertNetworkModels(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert network model fail, err: %v", err)
		return res, err
	}
	// sync config map
	if len(res) > 0 {
		uuid := data[0].ResourceUUID
		keysMap := make(map[string]string)
		for _, r := range res {
			keysMap[fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(r.Id))] =
				fmt.Sprintf(model.BehavioralLearnNetworkModelValueTemplate, r.ClusterKey, r.ResourceKind, r.ResourceNamespace, r.ResourceName, r.Port, r.StreamDirection, r.ContainerName, r.ProcessName)
		}

		err = b.BehavioralLearnModelUpdateKeyMaps(ctx, uuid, keysMap)
		if err != nil {
			logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
		}
	}
	return res, nil
}

func (b *BehavioralLearn) DeleteResourcesFileModel(ctx context.Context, resourceUUID uint32, id uint64) error {
	// update configmap
	err := b.BehavioralLearnModelDeleteModelKeys(ctx, resourceUUID, []string{fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(id))})
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}
	return dal.BehavioralLearnDeleteFileModel(ctx, b.rdb.Get(), resourceUUID, id)
}

func (b *BehavioralLearn) DeleteResourcesCommandModel(ctx context.Context, resourceUUID uint32, id uint64) error {
	// update configmap
	err := b.BehavioralLearnModelDeleteModelKeys(ctx, resourceUUID, []string{fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(id))})
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}
	return dal.BehavioralLearnDeleteCommandModel(ctx, b.rdb.Get(), resourceUUID, id)
}

func (b *BehavioralLearn) DeleteResourcesNetworkModel(ctx context.Context, resourceUUID uint32, id uint64) error {
	// update configmap
	err := b.BehavioralLearnModelDeleteModelKeys(ctx, resourceUUID, []string{fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(id))})
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}
	return dal.BehavioralLearnDeleteNetworkModel(ctx, b.rdb.Get(), resourceUUID, id)
}

func (b *BehavioralLearn) SetGlobalConfig(ctx context.Context, config *model.BehavioralLearnGlobalConfig) error {

	err := dal.BehavioralLearnUpdateGlobalConfig(ctx, b.rdb.Get(), *config)
	if err != nil {
		logging.GetLogger().Error().Msgf("update global config fail, err: %v", err)
		return err
	}

	globalConfig = config

	// update configmap
	err = b.UpdateGlobalConfigMap(ctx)
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}

	return nil
}

func (b *BehavioralLearn) UpdateGlobalConfigMap(ctx context.Context) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock learning-config configmap
	b.learningConfigmapLock.Lock()
	defer b.learningConfigmapLock.Unlock()

	updateMap := make(map[string]string)
	updateMap["global"] = fmt.Sprintf(
		model.BehavioralLearnGlobalConfigMapValueTemplate,
		globalConfig.IgnoreKnownAttack,
		globalConfig.LearnTime,
		globalConfig.ShowUnrelatedRes,
		globalConfig.AutoLearnNewRes,
	)

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnGlobalConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.BehavioralLearnGlobalConfigMapName,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
					},
				},
				Data: updateMap,
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
				return true
			}
		} else {
			currentConfigMap.Data = updateMap
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
		}
		return true
	})

	return nil
}

func (b *BehavioralLearn) BehavioralLearnStart(ctx context.Context, tasks []model.BehavioralLearnTaskItem) ([]model.TensorResource, error) {
	// add task to queue

	res, err := b.doBehavioralLearnStart(ctx, tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("doBehavioralLearnStart fail, err: %v", err)
		return res, err
	}

	// update configmap
	err = b.learningConfigMapUpdate(ctx, tasks, 1)
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}

	// sync status to ws
	b.BehavioralLearnStartStatusSendToWS(ctx, tasks)

	return res, err
}

func (b *BehavioralLearn) BehavioralLearnStartStatusSendToWS(ctx context.Context, tasks []model.BehavioralLearnTaskItem) error {

	for _, task := range tasks {
		go ws.SendToWS(ws.BehaviorEvent{
			Type:         ws.BehaviorLearnEventTypeStatus,
			ResourceUUID: task.ResourceUUID,
			BehavioralStatusEvent: ws.BehavioralStatusEvent{
				ResourceUUID: task.ResourceUUID,
				Status:       model.BehavioralLearningStatusRunning,
			},
		})
	}
	return nil

}

func setDefaultLearnTime(tasks []model.BehavioralLearnTaskItem) []model.BehavioralLearnTaskItem {
	for index, task := range tasks {
		if task.LearnTime == 0 {
			tasks[index].LearnTime = int64(globalConfig.LearnTime)
		}
	}
	return tasks

}

func (bl *BehavioralLearn) learningConfigMapDelete(ctx context.Context, tasks []model.BehavioralLearnTaskItem) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	logging.GetLogger().Debug().Interface("tasks", tasks).Msg("update tasks config map")
	deleteKeys := make([]string, 0, len(tasks))
	for _, t := range tasks {
		deleteKeys = append(deleteKeys, fmt.Sprintf(model.BehavioralLearnConfigMapKeyTemplate, t.ResourceUUID))
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock learning-config configmap
	bl.learningConfigmapLock.Lock()
	defer bl.learningConfigmapLock.Unlock()

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {

		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get drift config map error")
			return true
		}

		for _, key := range deleteKeys {
			if _, ok := currentConfigMap.Data[key]; ok {
				delete(currentConfigMap.Data, key)
				_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
				if err != nil {
					logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update drift config map error")
					return true
				}
			} else {
				logging.GetLogger().Warn().Str("key", key).Msg("delete drift config map key not exist")
			}
		}
		return true
	})
	return nil
}

func (bl *BehavioralLearn) learningConfigMapUpdate(ctx context.Context, tasks []model.BehavioralLearnTaskItem, op int) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock learning-config configmap
	bl.learningConfigmapLock.Lock()
	defer bl.learningConfigmapLock.Unlock()

	updateMap := make(map[string]string)

	for _, t := range tasks {
		updateMap[fmt.Sprintf(model.BehavioralLearnConfigMapKeyTemplate, t.ResourceUUID)] = fmt.Sprintf(model.BehavioralLearnConfigMapValueTemplate,
			t.Cluster, t.Namespace, t.Kind, t.Name, op, t.StartTime, t.LearnTime+t.StartTime)
	}
	if len(updateMap) > configMapSize {
		return errors.New("update map size is too large")
	}

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.BehavioralLearnConfigMapName,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
					},
				},
				Data: updateMap,
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
				return true
			}
		} else {
			if len(currentConfigMap.Data)+len(updateMap) > configMapSize {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true // continue
			}
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string, len(updateMap))
			}
			for key, value := range updateMap {
				currentConfigMap.Data[key] = value
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
		}
		return true
	})

	return nil
}

func (bl *BehavioralLearn) BehavioralLearnAutoLearnNewResource(ctx context.Context) error {
	if !globalConfig.AutoLearnNewRes {
		return nil
	}
	tasks := make([]model.BehavioralLearnTaskItem, 0)
	resouceQuery := dal.ResourcesQuery()
	resouceQuery = resouceQuery.WithCustom("behavioral_learn_status", 0)
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
		return errors.New("get resource service fail")
	}
	resources, n, err := resSvc.GetResources(ctx, resouceQuery, 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources fail, err: %v", err)
	}
	logging.GetLogger().Debug().Msgf("resources: %+v n: %d", resources, n)
	uuids := make([]uint32, 0)
	for _, res := range resources {
		rawCNum, err := dal.BehavioralLearnCountRawContainers(ctx, bl.rdb.GetReadDB(), res.ClusterKey, res.Namespace, res.Kind, res.Name)
		if err != nil {
			logging.GetLogger().Error().Msgf("get raw containers count fail, err: %v", err)
			continue
		}
		if rawCNum == 0 {
			continue
		}

		tasks = append(tasks, model.BehavioralLearnTaskItem{
			ResourceUUID: res.ID,
			LearnTime:    int64(globalConfig.LearnTime),
		})
		uuids = append(uuids, res.ID)
	}
	_, err = bl.BehavioralLearnStart(ctx, tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("doBehavioralLearnStart fail, err: %v", err)
	}
	bl.LogModelOperations(ctx, uuids, "system", "START", "learn")

	return err
}

func (bl *BehavioralLearn) checkConfigmapAndUpdateConfigmap(ctx context.Context) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock learning-config configmap
	bl.learningConfigmapLock.Lock()
	defer bl.learningConfigmapLock.Unlock()
	configMap, err := clusterManager.HostClient.CoreV1().ConfigMaps(namespace).Get(context.Background(), model.BehavioralLearnConfigMapName, metav1.GetOptions{})
	if err != nil {
		logging.GetLogger().Warn().Msg("get config map error")
		return err
	}
	datas := configMap.Data

	stopResourceUUIDs := make([]uint32, 0)
	for key, value := range datas {
		var resourceUUID uint32
		var endTime int64
		var op int
		keyList := strings.Split(key, "-")
		valueList := strings.Split(value, model.BehavioralLearnConfigMapValueDelimiter)

		endTimeStr := valueList[len(valueList)-1]
		endTime, err = strconv.ParseInt(endTimeStr, 10, 64)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", value)
			continue
		}

		opStr := valueList[len(valueList)-3]
		op, err = strconv.Atoi(opStr)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", value)
			continue
		}

		resourceUUIDStr := keyList[len(keyList)-1]

		uuid, err := strconv.ParseUint(resourceUUIDStr, 10, 32)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap key error, key: %s", key)
			continue
		}
		resourceUUID = uint32(uuid)

		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", value)
			continue
		}
		// 学习完成
		if endTime != 0 && endTime < time.Now().Unix() && op != 3 {
			logging.GetLogger().Debug().Msgf("resourceUUID: %d, endTime: %d, op: %d", resourceUUID, endTime, op)
			go ws.SendToWS(ws.BehaviorEvent{
				Type:         ws.BehaviorLearnEventTypeStatus,
				ResourceUUID: resourceUUID,
				BehavioralStatusEvent: ws.BehavioralStatusEvent{
					ResourceUUID: resourceUUID,
					Status:       model.BehavioralLearningStatusReady,
				},
			})
			delete(datas, key)
			if op == model.BehavioralLearningStatusRunning {
				globalResourceStatus[resourceUUID] = model.BehavioralLearningStatusReady
			}
			stopResourceUUIDs = append(stopResourceUUIDs, resourceUUID)
		}
	}

	// update db
	tasks := make([]model.BehavioralLearnTaskItem, 0)
	for _, uuid := range stopResourceUUIDs {
		tasks = append(tasks, model.BehavioralLearnTaskItem{
			ResourceUUID: uuid,
		})
	}
	_, err = bl.doBehavioralLearnStop(context.Background(), tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("do behavioral learn stop fail, err: %v", err)
	}
	// update configmap
	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			return true
		}
		currentConfigMap.Data = datas
		_, err = client.CoreV1().ConfigMaps(namespace).Update(context.Background(), currentConfigMap, metav1.UpdateOptions{})
		if err != nil {
			logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
			return true
		}
		return true
	})

	return nil
}

// 监听学习状态
func (bl *BehavioralLearn) updateLearningConfigmapStatusLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 30):
			err := bl.checkConfigmapAndUpdateConfigmap(ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("check configmap and update configmap error")
			}

			err = bl.BehavioralLearnAutoLearnNewResource(ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("auto learn new resource error")
			}
		}
	}
}

func (b *BehavioralLearn) doBehavioralLearnStart(ctx context.Context, tasks []model.BehavioralLearnTaskItem) ([]model.TensorResource, error) {
	b.taskLock.Lock()
	defer b.taskLock.Unlock()

	res, err := dal.BehavioralLearnUpdateResourceStatus(ctx, b.rdb.Get(), tasks, 1)
	if err != nil {
		logging.GetLogger().Error().Msgf("update resource status fail, err: %v", err)
		return res, err
	}

	tasks = setDefaultLearnTime(tasks)
	err = dal.BehavioralLearnUpdateResourceLearnTime(ctx, b.rdb.Get(), tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("update resource learn time fail, err: %v", err)
		return res, err
	}

	for i, _ := range tasks {
		tasks[i].StartTime = time.Now().Unix()
	}

	err = dal.BehavioralLearnUpdateResourceStartLearnTime(ctx, b.rdb.Get(), tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("update resource start learn time fail, err: %v", err)
		return res, err
	}

	err = b.deleteBehavioralLearnModelConfigMap(ctx, tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("delete configmap fail, err: %v", err)
	}

	return res, err
}

func (b *BehavioralLearn) BehavioralLearnStop(ctx context.Context, task model.BehavioralLearnTaskItem) ([]model.TensorResource, error) {
	// remove task from queue
	res, err := b.doBehavioralLearnStop(ctx, []model.BehavioralLearnTaskItem{task})
	if err != nil {
		logging.GetLogger().Error().Msgf("do behavioral learn stop fail, err: %v", err)
		return res, err
	}
	// sync configmap to all nodes
	err = b.learningConfigMapDelete(ctx, []model.BehavioralLearnTaskItem{task})
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}

	return res, nil
}

func (b *BehavioralLearn) doBehavioralLearnStop(ctx context.Context, tasks []model.BehavioralLearnTaskItem) ([]model.TensorResource, error) {
	b.taskLock.Lock()
	defer b.taskLock.Unlock()
	if len(tasks) == 0 {
		logging.GetLogger().Error().Msg("task is empty")
		return nil, nil
	}
	res, err := dal.BehavioralLearnUpdateResourceStatus(ctx, b.rdb.Get(), tasks, 2)
	if err != nil {
		logging.GetLogger().Error().Msgf("update resource status fail, err: %v", err)
	}
	for _, t := range tasks {
		fileModel, commandModel, networkModel, err := dal.BehavioralLearnGetModelMix(ctx, b.rdb.Get(), t.ResourceUUID)
		if err != nil {
			logging.GetLogger().Error().Msgf("get model mix fail, err: %v", err)
		}

		// sync model to configmap
		err = b.updateBehavioralLearnModelConfigMap(ctx, t, fileModel, commandModel, networkModel)
		if err != nil {
			logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
		}
	}

	return res, err
}

func (bl *BehavioralLearn) updateBehavioralLearnModelConfigMap(ctx context.Context, task model.BehavioralLearnTaskItem,
	fileModel []model.BehavioralLearnFileModel, commandModel []model.BehavioralLearnCommandModel,
	networkModel []model.BehavioralLearnNetworkModel,
) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	logging.GetLogger().Debug().Interface("task", task).Msg("update behavioral learn model config map")

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	bl.updateResourceConfigmapLock.Lock()
	defer bl.updateResourceConfigmapLock.Unlock()

	updateMap := make(map[string]string)

	configMapName := fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, task.ResourceUUID)

	for _, f := range fileModel {
		updateMap[fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(f.Id))] = fmt.Sprintf(model.BehavioralLearnFileModelValueTemplate, f.Path, f.Permission, f.ContainerName)
	}
	for _, c := range commandModel {
		updateMap[fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(c.Id))] = fmt.Sprintf(model.BehavioralLearnCommandModelValueTemplate, c.Command, c.User, c.ContainerName)
	}
	logging.GetLogger().Debug().Interface("networkModel", networkModel).Msg("networkModel")
	for _, n := range networkModel {
		updateMap[fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(n.Id))] = fmt.Sprintf(model.BehavioralLearnNetworkModelValueTemplate, n.ClusterKey, n.ResourceKind, n.ResourceNamespace, n.ResourceName, n.Port, n.StreamDirection, n.ContainerName, n.ProcessName)
	}
	logging.GetLogger().Debug().Interface("updateMap", updateMap).Msg("updateMap")

	if len(updateMap) > configMapSize {
		return errors.New("update map size is too large")
	}

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		err := client.CoreV1().ConfigMaps(namespace).Delete(ctx, configMapName, metav1.DeleteOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("delete config map error")
		}
		configmap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: namespace,
				Labels: map[string]string{
					strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
				},
			},
			Data: updateMap,
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
		if err != nil {
			logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
			return true
		}
		return true
	})

	return nil
}

func (b *BehavioralLearn) deleteBehavioralLearnModelConfigMap(ctx context.Context, tasks []model.BehavioralLearnTaskItem) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	deleteConfigMap := make(map[string]struct{})
	for _, task := range tasks {
		deleteConfigMap[fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, task.ResourceUUID)] = struct{}{}
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateResourceConfigmapLock.Lock()
	defer b.updateResourceConfigmapLock.Unlock()

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		for configMapName, _ := range deleteConfigMap {
			err := client.CoreV1().ConfigMaps(namespace).Delete(ctx, configMapName, metav1.DeleteOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Msg("delete config map error")
			}
		}
		return true
	})

	return nil
}

func (b *BehavioralLearn) BehavioralLearnModelDeleteModelKeys(ctx context.Context, uuid uint32, keys []string) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	resConfigmap := fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, uuid)

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateResourceConfigmapLock.Lock()
	defer b.updateResourceConfigmapLock.Unlock()

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, resConfigmap, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			return true
		}
		for _, key := range keys {
			if _, ok := currentConfigMap.Data[key]; ok {
				delete(currentConfigMap.Data, key)

			} else {
				logging.GetLogger().Warn().Str("key", key).Msg("delete config map key not exist")
			}
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
		if err != nil {
			logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("delete config map error")
			return true
		}
		return true
	})
	return nil
}

func (b *BehavioralLearn) BehavioralLearnModelUpdateKeyMaps(ctx context.Context, uuid uint32, keyMaps map[string]string) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	resConfigmap := fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, uuid)

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateResourceConfigmapLock.Lock()
	defer b.updateResourceConfigmapLock.Unlock()

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, resConfigmap, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			// create configmap
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resConfigmap,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
					},
				},
				Data: keyMaps,
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
				return true
			}

		}
		if currentConfigMap.Data == nil {
			currentConfigMap.Data = make(map[string]string)
		}
		for key, value := range keyMaps {
			currentConfigMap.Data[key] = value
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
		if err != nil {
			logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
			return true
		}
		return true
	})
	return nil
}

func (b *BehavioralLearn) BehavioralLearnModelUpdateModelKey(ctx context.Context, uuid uint32, modelKey, modelValue string) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	resConfigmap := fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, uuid)

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateResourceConfigmapLock.Lock()
	defer b.updateResourceConfigmapLock.Unlock()

	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, resConfigmap, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resConfigmap,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
					},
				},
				Data: map[string]string{
					modelKey: modelValue,
				},
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
				return true
			}
		} else {
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string)
			}
			if len(currentConfigMap.Data)+1 > inModelConfigSize {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
			currentConfigMap.Data[modelKey] = modelValue
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
		}

		return true
	})

	return nil
}

func (b *BehavioralLearn) BehavioralLearnModelConfig(ctx context.Context, data []model.BehavioralLearnModelConfig, userName string) ([]model.TensorResource, int, error) {
	// update model config
	ress, resMap, n, err := dal.BehavioralLearnUpdateModelConfig(ctx, b.rdb.Get(), data)
	if err != nil {
		return nil, 0, err
	}

	uuids := make([]uint32, 0)

	for _, d := range data {
		t := model.BehavioralLearnTaskItem{
			ResourceUUID: d.ResourceUUID,
		}
		if _, ok := resMap[d.ResourceUUID]; !ok {
			logging.GetLogger().Error().Msgf("resource not ready, uuid: %d", d.ResourceUUID)
			continue
		}

		// update configmap
		if d.Enabled {
			err = b.learningConfigMapUpdate(ctx, []model.BehavioralLearnTaskItem{t}, 3)
		} else {
			err = b.learningConfigMapDelete(ctx, []model.BehavioralLearnTaskItem{t})
		}
		if err != nil {
			logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
		}
		uuids = append(uuids, d.ResourceUUID)
	}
	if len(uuids) > 0 {
		if data[0].Enabled {
			b.LogModelOperations(ctx, uuids, userName, "TRUE", "enabled")
		} else {
			b.LogModelOperations(ctx, uuids, userName, "FALSE", "enabled")
		}
	}

	return ress, n, err
}

func (b *BehavioralLearn) BehavioralLearnOneKeyLearn(ctx context.Context, userName string) ([]model.TensorResource, int64, error) {
	resourceSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
		return nil, 0, nil
	}

	query := dal.ResourcesQuery()

	res, n, err := resourceSvc.GetResources(ctx, query, 0, 0)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resources fail, err: %v", err)
		return nil, 0, err
	}

	uuids := make([]uint32, 0)
	tasks := make([]model.BehavioralLearnTaskItem, 0)
	for _, r := range res {
		tasks = append(tasks, model.BehavioralLearnTaskItem{
			ResourceUUID: r.ID,
			LearnTime:    int64(globalConfig.LearnTime),
		})
		uuids = append(uuids, r.ID)
	}
	b.LogModelOperations(ctx, uuids, userName, "START", "learn")

	ress, err := b.doBehavioralLearnStart(ctx, tasks)
	if err != nil {
		logging.GetLogger().Error().Msgf("do behavioral learn start fail, err: %v", err)
		return ress, 0, err
	}
	// update configmap
	err = b.learningConfigMapUpdate(ctx, tasks, 1)
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}

	// sync status to ws
	b.BehavioralLearnStartStatusSendToWS(ctx, tasks)

	return ress, n, nil
}

func (b *BehavioralLearn) BehavioralLearnOneKeyEnabled(ctx context.Context, enabled bool, userName string) (int64, error) {
	resourceUUIDs, n, err := dal.BehavioralLearnModelOneKeyConfig(ctx, b.rdb.Get(), enabled)
	if err != nil {
		logging.GetLogger().Error().Msgf("update resource status fail, err: %v", err)
		return 0, err
	}
	uuids := make([]uint32, 0)
	for uuid, _ := range resourceUUIDs {
		uuids = append(uuids, uuid)
	}
	if enabled {
		b.LogModelOperations(ctx, uuids, userName, "TRUE", "enabled")
	} else {
		b.LogModelOperations(ctx, uuids, userName, "FALSE", "enabled")
	}

	return n, err
}

func (b *BehavioralLearn) LogModelOperation(ctx context.Context, resourceUUID uint32,
	user, action, modelType string, modelID uint64) error {
	operator := model.BehavioralLearnModelOperationLog{
		ResourceUUID: resourceUUID,
		User:         user,
		Action:       action,
		ModelType:    modelType,
		ID:           modelID,
	}
	return dal.BehavioralLearnLogModelOperations(ctx, b.rdb.Get(), []model.BehavioralLearnModelOperationLog{operator})
}

func (b *BehavioralLearn) LogModelOperationsWithID(ctx context.Context, resourceUUID uint32,
	user, action, modelType string, modelIDs []uint64) error {
	operators := make([]model.BehavioralLearnModelOperationLog, 0)
	for _, id := range modelIDs {
		operator := model.BehavioralLearnModelOperationLog{
			ResourceUUID: resourceUUID,
			User:         user,
			Action:       action,
			ModelType:    modelType,
			ID:           id,
		}
		operators = append(operators, operator)
	}

	return dal.BehavioralLearnLogModelOperations(ctx, b.rdb.Get(), operators)
}

func (b *BehavioralLearn) LogModelOperations(ctx context.Context, resourceUUID []uint32,
	user, action, modelType string) error {
	operators := make([]model.BehavioralLearnModelOperationLog, 0)
	for _, uuid := range resourceUUID {
		operator := model.BehavioralLearnModelOperationLog{
			ResourceUUID: uuid,
			User:         user,
			Action:       action,
			ModelType:    modelType,
		}
		operators = append(operators, operator)
	}

	return dal.BehavioralLearnLogModelOperations(ctx, b.rdb.Get(), operators)
}

func (b *BehavioralLearn) GetModelOperationLog(ctx context.Context, resourceUUID uint32, limit, offset int) ([]model.BehavioralLearnModelOperationLog, int64, error) {
	return dal.BehavioralLearnGetModelOperationLog(ctx, b.rdb.GetReadDB(), resourceUUID, limit, offset)
}

func (b *BehavioralLearn) GetGlobalConfig(ctx context.Context) (*model.BehavioralLearnGlobalConfig, error) {
	config, err := dal.BehavioralLearnGetGlobalConfig(ctx, b.rdb.GetReadDB())
	if err != nil {
		logging.GetLogger().Error().Msgf("get global config fail, err: %v", err)
		err = dal.BehavioralLearnInsertGlobalConfig(ctx, b.rdb.Get(), *globalConfig)
		if err != nil {
			logging.GetLogger().Error().Msgf("insert global config fail, err: %v", err)
		}
		config = globalConfig
	}
	return config, nil
}

func (b *BehavioralLearn) InsertGlobalCommandWhitelist(ctx context.Context, data model.BehavioralLearnCommandModelGlobalWhiteList) (model.BehavioralLearnCommandModelGlobalWhiteList, error) {

	data, err := dal.BehavioralLearnInsertCommandModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert global command whitelist fail, err: %v", err)
		return data, err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnCommandModelWlsValueTemplate, data.Path, data.Command, data.User))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}
	return data, nil
}

func (b *BehavioralLearn) InsertGlobalFileWhitelist(ctx context.Context, data model.BehavioralLearnFileModelGlobalWhiteList) (model.BehavioralLearnFileModelGlobalWhiteList, error) {
	data, err := dal.BehavioralLearnInsertFileModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert global file whitelist fail, err: %v", err)
		return data, err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnFileModelWlsValueTemplate, data.Path, data.Permission))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}
	return data, nil
}

func (b *BehavioralLearn) InsertGlobalNetworkWhitelist(ctx context.Context, data model.BehavioralLearnNetworkModelGlobalWhiteList) (model.BehavioralLearnNetworkModelGlobalWhiteList, error) {
	data, err := dal.BehavioralLearnInsertNetworkModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("insert global network whitelist fail, err: %v", err)
		return data, err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnNetworkModelWlsValueTemplate, data.ClusterKey, data.Kind, data.Namespace, data.Name, data.Port, data.StreamDirection))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}
	return data, nil
}

func (b *BehavioralLearn) UpdateGlobalCommandWhitelist(ctx context.Context, data model.BehavioralLearnCommandModelGlobalWhiteList) error {
	err := dal.BehavioralLearnUpdateCommandModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update global command whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnCommandModelWlsValueTemplate, data.Path, data.Command, data.User))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}

	return nil
}

func (b *BehavioralLearn) UpdateGlobalFileWhitelist(ctx context.Context, data model.BehavioralLearnFileModelGlobalWhiteList) error {
	err := dal.BehavioralLearnUpdateFileModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update global file whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnFileModelWlsValueTemplate, data.Path, data.Permission))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}
	return nil
}

func (b *BehavioralLearn) UpdateGlobalNetworkWhitelist(ctx context.Context, data model.BehavioralLearnNetworkModelGlobalWhiteList) error {
	err := dal.BehavioralLearnUpdateNetworkModelGlobalWhiteList(ctx, b.rdb.Get(), data)
	if err != nil {
		logging.GetLogger().Error().Msgf("update global network whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.UpdateGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(data.ID)),
		fmt.Sprintf(model.BehavioralLearnNetworkModelWlsValueTemplate, data.ClusterKey, data.Kind, data.Namespace,
			data.Name, data.Port, data.StreamDirection))
	if err != nil {
		logging.GetLogger().Error().Msgf("update configmap fail, err: %v", err)
	}
	return nil
}

func (b *BehavioralLearn) DeleteGlobalCommandWhitelist(ctx context.Context, id int64) error {
	err := dal.BehavioralLearnDeleteCommandModelGlobalWhiteList(ctx, b.rdb.Get(), id)
	if err != nil {
		logging.GetLogger().Error().Msgf("delete global command whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.DeleteGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(id)))
	if err != nil {
		logging.GetLogger().Error().Msgf("delete configmap fail, err: %v", err)
	}
	return nil
}

func (b *BehavioralLearn) DeleteGlobalFileWhitelist(ctx context.Context, id int64) error {
	err := dal.BehavioralLearnDeleteFileModelGlobalWhiteList(ctx, b.rdb.Get(), id)
	if err != nil {
		logging.GetLogger().Error().Msgf("delete global file whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.DeleteGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(id)))
	if err != nil {
		logging.GetLogger().Error().Msgf("delete configmap fail, err: %v", err)
	}
	return nil
}

func (b *BehavioralLearn) DeleteGlobalNetworkWhitelist(ctx context.Context, id int64) error {
	err := dal.BehavioralLearnDeleteNetworkModelGlobalWhiteList(ctx, b.rdb.Get(), id)
	if err != nil {
		logging.GetLogger().Error().Msgf("delete global network whitelist fail, err: %v", err)
		return err
	}
	// sync config map
	err = b.DeleteGlobalWhiteListConfigMap(ctx, fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(id)))
	if err != nil {
		logging.GetLogger().Error().Msgf("delete configmap fail, err: %v", err)
	}
	return nil
}

func (b *BehavioralLearn) GetGlobalCommandWhitelist(ctx context.Context, limit, offset int, searchStr string) ([]model.BehavioralLearnCommandModelGlobalWhiteList, int64, error) {
	return dal.BehavioralLearnGetCommandModelGlobalWhiteList(ctx, b.rdb.GetReadDB(), offset, limit, searchStr)
}

func (b *BehavioralLearn) GetGlobalFileWhitelist(ctx context.Context, limit, offset int, searchStr string, permission int) ([]model.BehavioralLearnFileModelGlobalWhiteList, int64, error) {
	return dal.BehavioralLearnGetFileModelGlobalWhiteList(ctx, b.rdb.GetReadDB(), offset, limit, searchStr, permission)
}

func (b *BehavioralLearn) GetGlobalNetworkWhitelist(ctx context.Context, limit, offset int, searchStr string, streamDirection []int) ([]model.BehavioralLearnNetworkModelGlobalWhiteList, int64, error) {
	return dal.BehavioralLearnGetNetworkModelGlobalWhiteList(ctx, b.rdb.GetReadDB(), offset, limit, searchStr, streamDirection)
}

func (b *BehavioralLearn) UpdateGlobalWhiteListConfigMap(ctx context.Context, wlsKey, wlsValue string) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateWhitelistConfigmapLock.Lock()
	defer b.updateWhitelistConfigmapLock.Unlock()
	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnWhitelistName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.BehavioralLearnWhitelistName,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.BehaviorConfigMapLabel, "=")[0]: strings.Split(model.BehaviorConfigMapLabel, "=")[1],
					},
				},
				Data: map[string]string{
					wlsKey: wlsValue,
				},
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create config map error")
				return true
			}
		} else {
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string)
			}
			if len(currentConfigMap.Data)+1 > wlsConfigSize {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
			currentConfigMap.Data[wlsKey] = wlsValue
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
				return true
			}
		}
		return true
	})

	return nil
}

func (b *BehavioralLearn) DeleteGlobalWhiteListConfigMap(ctx context.Context, deleteKey string) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock resource configmap
	b.updateWhitelistConfigmapLock.Lock()
	defer b.updateWhitelistConfigmapLock.Unlock()
	clusterManager.TraverseClient(func(k string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.BehavioralLearnWhitelistName, metav1.GetOptions{})
		if err != nil {
			logging.GetLogger().Warn().Msg("get config map error")
			return true
		}
		if _, ok := currentConfigMap.Data[deleteKey]; ok {
			delete(currentConfigMap.Data, deleteKey)
		} else {
			logging.GetLogger().Warn().Str("key", deleteKey).Msg("delete config map key not exist")
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
		if err != nil {
			logging.GetLogger().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update config map error")
		}
		return true
	})

	return nil
}

func (b *BehavioralLearn) GetResourceBasicInfo(ctx context.Context, resourceUUID uint32) (*model.TensorResource, error) {
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.GetLogger().Error().Msg("get resource service fail")
	}

	query := dal.ResourcesQuery()
	query = query.WithID(resourceUUID)
	res, n, err := resSvc.GetResources(ctx, query, 0, 0)
	if err != nil || n == 0 {
		logging.GetLogger().Error().Msgf("get resources by uuid fail, uuid: %d", resourceUUID)
		return nil, err
	}
	return res[0], nil

}

func (b *BehavioralLearn) GetResourceContainerInfo(ctx context.Context, cluster, namespace, kind, name string) ([]*assets.ContainerInfo, error) {

	containers, err := dal.BehavioralLearnRawContainers(ctx, b.rdb.GetReadDB(), cluster, namespace, kind, name, 0, 0)
	var cnts []*assets.ContainerInfo
	cNameNodeNameMap := make(map[string]struct{})
	for _, c := range containers {
		_, ok := cNameNodeNameMap[c.Name]
		if ok {
			continue
		}
		cnts = append(cnts, &assets.ContainerInfo{
			ContainerID: c.ContainerID,
			Name:        c.Name,
			Image:       c.ImageName,
		})
		cNameNodeNameMap[c.Name] = struct{}{}
	}

	return cnts, err
}

func (b *BehavioralLearn) AddFileModelFromOutside(ctx context.Context, idNum uint64, userName string) (model.BehavioralLearnFileModel, error) {

	res, err := dal.BehavioralLearnGetFileModelByID(ctx, b.rdb.Get(), idNum)
	if err != nil {
		logging.GetLogger().Error().Msgf("update file model out model fail, err: %v", err)
		return res, err
	}
	insertData := model.BehavioralLearnFileModel{
		ResourceUUID:  res.ResourceUUID,
		Path:          res.Path,
		Name:          res.Name,
		Permission:    res.Permission,
		IsInModel:     true,
		Id:            id.UInt64(),
		ContainerID:   res.ContainerID,
		ContainerName: res.ContainerName,
	}

	err = dal.BehavioralLearnAddFileModelOutModel(ctx, b.rdb.Get(), insertData)
	if err != nil {
		logging.GetLogger().Error().Msgf("update file model out model fail, err: %v", err)
	}
	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnFileModelKeyTemplate, uint64(res.Id)),
		fmt.Sprintf(model.BehavioralLearnFileModelValueTemplate, res.Path, res.Permission, res.ContainerName))

	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}
	b.LogModelOperation(ctx, res.ResourceUUID, userName, "ADD", "file", insertData.Id)

	return insertData, nil
}

func (b *BehavioralLearn) AddCommandModelFromOutside(ctx context.Context, idNum uint64, userName string) (model.BehavioralLearnCommandModel, error) {

	res, err := dal.BehavioralLearnGetCommandModelByID(ctx, b.rdb.GetReadDB(), idNum)
	if err != nil {
		logging.GetLogger().Error().Msgf("get command model by id fail, err: %v", err)
	}

	insertData := model.BehavioralLearnCommandModel{
		ResourceUUID:  res.ResourceUUID,
		Command:       res.Command,
		Path:          res.Path,
		User:          res.User,
		IsInModel:     true,
		Id:            id.UInt64(),
		ContainerID:   res.ContainerID,
		ContainerName: res.ContainerName,
	}
	err = dal.BehavioralLearnAddCommandModelOutModel(ctx, b.rdb.Get(), insertData)
	if err != nil {
		logging.GetLogger().Error().Msgf("update command model out model fail, err: %v", err)
	}

	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnCommandModelKeyTemplate, uint64(res.Id)),
		fmt.Sprintf(model.BehavioralLearnCommandModelValueTemplate, res.Command, res.User, res.ContainerName))
	if err != nil {
		logging.GetLogger().Error().Msgf("update config map fail, err: %v", err)
	}

	b.LogModelOperation(ctx, res.ResourceUUID, userName, "ADD", "command", insertData.Id)

	return insertData, nil
}

func (b *BehavioralLearn) AddNetworkModelFromOutside(ctx context.Context, idNum uint64) (model.BehavioralLearnNetworkModel, error) {

	res, err := dal.BehavioralLearnGetNetworkModelByID(ctx, b.rdb.Get(), idNum)
	if err != nil {
		logging.GetLogger().Error().Msgf("update network model out model fail, err: %v", err)
		return res, err
	}

	// insertData := model.BehavioralLearnNetworkModel{
	// 	ResourceUUID:      res.ResourceUUID,
	// 	ClusterKey:        res.ClusterKey,
	// 	ResourceKind:      res.ResourceKind,
	// 	ResourceName:      res.ResourceName,
	// 	ResourceNamespace: res.ResourceNamespace,
	// 	Port:              res.Port,
	// 	StreamDirection:   res.StreamDirection,
	// 	IsInModel:         true,
	// 	Id:                id.UInt64(),
	// 	ContainerID:       res.ContainerID,
	// 	ContainerName:     res.ContainerName,
	// }
	insertData := res
	insertData.IsInModel = true
	insertData.UpdatedAt = time.Now().Unix()
	insertData.Id = id.UInt64()

	err = dal.BehavioralLearnAddNetworkModelOutModel(ctx, b.rdb.Get(), insertData)
	if err != nil {
		logging.GetLogger().Error().Msgf("update network model out model fail, err: %v", err)
	}

	// sync config map
	err = b.BehavioralLearnModelUpdateModelKey(ctx, res.ResourceUUID,
		fmt.Sprintf(model.BehavioralLearnNetworkModelKeyTemplate, uint64(res.Id)),
		fmt.Sprintf(model.BehavioralLearnNetworkModelValueTemplate, res.ClusterKey, res.ResourceKind, res.ResourceNamespace, res.ResourceName, res.Port, res.StreamDirection, res.ContainerName, res.ProcessName))

	b.LogModelOperation(ctx, res.ResourceUUID, "", "ADD", "network", insertData.Id)
	return insertData, nil
}

func parseSignal(item *es.SearchHit) (*palace.Signal, error) {
	var signal palace.Signal
	var err = json.Unmarshal(item.Source, &signal)
	if err != nil {
		return nil, err
	}

	return &signal, nil
}

func (b *BehavioralLearn) GetFileModelFromEs(ctx context.Context, resourceUUID uint32, filePath string, offset, limit int) ([]*palace.Signal, error) {

	res, err := b.GetResourceBasicInfo(ctx, resourceUUID)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resource basic info fail, err: %v", err)
		return nil, err
	}

	esCli, err := b.es.Get()
	if err != nil {
		return nil, err
	}
	boolQuery := es.NewBoolQuery()
	boolQuery.Filter(
		es.NewTermQuery("ruleKey.category.keyword", "ImmuneDefense"),
		es.NewTermQuery("ruleKey.name.keyword", "File access exceptions in containers"),
		es.NewTermQuery("scope.cluster.id", res.ClusterKey),
		es.NewTermQuery("scope.namespace.name.keyword", res.Namespace),
		es.NewTermQuery("scope.resource.name.keyword", fmt.Sprintf("%s(%s)", res.Name, res.Kind)),
	)

	if filePath != "" {
		boolQuery.Filter(es.NewMatchPhraseQuery("context.file_path", filePath).Slop(0))
	}

	// debug
	src, _ := boolQuery.Source()
	logging.GetLogger().Debug().Interface("source", src).Msg("filter condition")

	var result = make([]*palace.Signal, 0)

	searchResult, err := esCli.Search("signals,signals-*,signals_*").Query(boolQuery).
		Sort("createdAt", false).
		Size(limit).Do(ctx)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("search es error")
		return result, nil
	}

	for _, item := range searchResult.Hits.Hits {
		signal, err := parseSignal(item)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("parse signal error")
			continue
		}
		result = append(result, signal)
	}
	return result, nil

}

func (b *BehavioralLearn) GetCommandModelFromEs(ctx context.Context, resourceUUID uint32, filePath, cmdline string, offset, limit int) ([]*palace.Signal, error) {

	res, err := b.GetResourceBasicInfo(ctx, resourceUUID)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resource basic info fail, err: %v", err)
		return nil, err
	}

	esCli, err := b.es.Get()
	if err != nil {
		return nil, err
	}
	boolQuery := es.NewBoolQuery()
	boolQuery.Filter(
		es.NewTermQuery("ruleKey.category.keyword", "ImmuneDefense"),
		es.NewTermQuery("ruleKey.name.keyword", "Command Execution Exception"),
		es.NewTermQuery("scope.cluster.id", res.ClusterKey),
		es.NewTermQuery("scope.namespace.name.keyword", res.Namespace),
		es.NewTermQuery("scope.resource.name.keyword", fmt.Sprintf("%s(%s)", res.Name, res.Kind)),
	)

	if filePath != "" {
		boolQuery.Filter(es.NewTermQuery("context.process_path", filePath))
	}
	if cmdline != "" {
		boolQuery.Filter(es.NewTermsQuery("context.cmd", cmdline))
	}

	// debug
	src, _ := boolQuery.Source()
	logging.GetLogger().Debug().Interface("source", src).Msg("filter condition")

	var result = make([]*palace.Signal, 0)
	searchResult, err := esCli.Search("signals,signals-*,signals_*").Query(boolQuery).
		Sort("createdAt", false).
		Size(limit).Do(ctx)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("search es error")
		return result, nil
	}

	for _, item := range searchResult.Hits.Hits {
		signal, err := parseSignal(item)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("parse signal error")
			continue
		}
		result = append(result, signal)
	}
	return result, nil
}

func (b *BehavioralLearn) GetNetworkModelFromEs(ctx context.Context, resourceUUID uint32, port int,
	resourceName string,
	streamDirection string,
	processName string,
	offset, limit int) ([]*palace.Signal, error) {

	res, err := b.GetResourceBasicInfo(ctx, resourceUUID)
	if err != nil {
		logging.GetLogger().Error().Msgf("get resource basic info fail, err: %v", err)
		return nil, err
	}

	esCli, err := b.es.Get()
	if err != nil {
		return nil, err
	}
	boolQuery := es.NewBoolQuery()
	boolQuery.Filter(
		es.NewTermQuery("ruleKey.category.keyword", "ImmuneDefense"),
		es.NewTermQuery("scope.cluster.id", res.ClusterKey),
		es.NewTermQuery("ruleKey.name.keyword", "Network access exceptions in containers"),
		es.NewTermQuery("scope.namespace.name.keyword", res.Namespace),
		es.NewTermQuery("scope.resource.name.keyword", fmt.Sprintf("%s(%s)", res.Name, res.Kind)),
	)

	if port != 0 {
		boolQuery.Filter(es.NewTermQuery("context.port", port))
	}
	if streamDirection != "" {
		boolQuery.Filter(es.NewTermQuery("context.stream_direction", streamDirection))
	}
	if resourceName != "" {
		boolQuery.Filter(es.NewTermQuery("context.resource_name", resourceName))
	}

	if processName != "" {
		boolQuery.Filter(es.NewTermQuery("context.process_name", processName))
	}

	// debug
	src, _ := boolQuery.Source()
	logging.GetLogger().Debug().Interface("source", src).Msg("filter condition")

	var result = make([]*palace.Signal, 0)
	searchResult, err := esCli.Search("signals,signals-*,signals_*").Query(boolQuery).
		Sort("createdAt", false).
		Size(limit).Do(ctx)
	if err != nil {
		logging.GetLogger().Warn().Err(err).Msg("search es error")
		return result, nil
	}

	for _, item := range searchResult.Hits.Hits {
		signal, err := parseSignal(item)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("parse signal error")
			continue
		}
		result = append(result, signal)
	}
	return result, nil
}
