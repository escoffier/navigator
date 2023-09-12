package iac

import (
	"context"
	"fmt"
	"github.com/robfig/cron/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigYaml "sigs.k8s.io/yaml"
	"time"

	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"

	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

const (
	KafkaTopicResourcesChange   = "kube-resources"
	KafkaGroupIDResourcesChange = "console-iac-kube-resources"

	DBPeriodScheduleName = "period_schedule"
	DBUpdateScheduleName = "update_schedule"

	DBPeriodScheduleDescription = "built-in user-set period schedule"
	DBUpdateScheduleDescription = "built-in update triggered schedule"

	DBPeriodScheduleSchedule = "0 0 * * *"

	DBScheduleOff = 0
	DBScheduleOn  = 1

	DefaultTemplateName = "default benchmark"
)

var (
	db                    *gorm.DB
	BuiltInPeriodSchedule iacModel.YamlSchedule
	BuiltInUpdateSchedule iacModel.YamlSchedule
	resSvc                *assets.TensorResourcesService
	clusterManager        *k8s.ClusterManager
)

func NewYamlScanner(rdb *gorm.DB) error {

	mqFactory := mq.GetClientFactory()
	mqReader, err := mqFactory.Reader(context.Background(), mq.SIOSetStartOffset(kafka.LastOffset)) // 初次上线时，避免历史数据轰炸
	if err != nil {
		logging.Get().Err(err).Msg("init mq reader error")
		panic(err)
	}

	db = rdb
	var ok bool

	ctx := context.Background()
	resSvc, ok = assets.GetResourcesService(ctx)
	if !ok {
		logging.Get().Panic().Msg("init GetResourcesService fails")
		return fmt.Errorf("init GetResourcesService fails")
	}

	clusterManager, ok = k8s.GetClusterManager()
	if !ok {
		logging.Get().Panic().Msg("cluster manager not available")
		return fmt.Errorf("cluster manager not available")
	}

	// job: 执行具体的扫描任务
	initYamlJobWorkers()

	// 周期同步在线资源
	syncOnlineResources()

	// 初始化默认schedule
	err = initBuiltInScheduleAndTemplate()
	if err != nil {
		logging.Get().Error().Err(err).Msg("initBuiltInScheduleAndTemplate fails")
		return err
	}

	// 开启周期扫描
	startScheduleYamlScan()

	// 消费kafka，接收各集群的资源变化数据（新增+更新）
	logging.Get().Info().Msg("new yaml scanner reader")
	err = mqReader.Subscribe(KafkaTopicResourcesChange, KafkaGroupIDResourcesChange, handleKubeResourcesChange)
	if err != nil {
		logging.Get().Error().Err(err).Str("topic", KafkaTopicResourcesChange).Str("group_id", KafkaGroupIDResourcesChange).Msg("mq subscribe fails")
		return err
	}
	logging.Get().Info().Msg("new yaml scanner ok")
	return nil
}

func SyncResources() error {
	ctx := context.Background()
	timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	total, err := resSvc.CountResourceWithRedis(timeOutCtx, dal.ResourcesQuery())
	if err != nil {
		logging.Get().Error().Err(err).Msg("CountResourceWithRedis fails")
		return err
	}
	offset, limit := 0, 100
	for offset < int(total) {
		timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
		resources, _, err := resSvc.GetResourceWithRedis(timeOutCtx, dal.ResourcesQuery(), offset, limit)
		if err != nil {
			logging.Get().Error().Err(err).Msg("GetResourceWithRedis fails")
			cancel()
			return err
		}
		offset += limit
		cancel()
		// 同步到records表中，状态区分未扫描
		for i := range resources {
			clientSet, ok := clusterManager.GetClient(resources[i].ClusterKey)
			if !ok {
				err = fmt.Errorf("clientset of cluster: %s not available", resources[i].ClusterKey)
				logging.Get().Error().Err(err).Msg("clusterManager.GetClient fails")
				continue
			}
			yamlData, _, err := GetYamlFromK8s(ctx, clientSet, iacModel.Resource{
				ClusterKey: resources[i].ClusterKey,
				Namespace:  resources[i].Namespace,
				Kind:       resources[i].Kind,
				Name:       resources[i].Name,
			})
			if err != nil {
				logging.Get().Error().Err(err).Msg("getYamlFromK8s fails")
				continue
			}

			r, err := iacModel.FirstOrCreateResult(ctx, db, iacModel.YamlResult{
				ResourceClusterKey: resources[i].ClusterKey,
				ResourceNamespace:  resources[i].Namespace,
				ResourceKind:       resources[i].Kind,
				ResourceName:       resources[i].Name,
				ResourceGeneration: resources[i].Generation,
				Duration:           -1,
				Status:             iacModel.YamlResultStatusInitial,
				Result:             "",
				Yaml:               string(yamlData),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			})
			if err != nil {
				logging.Get().Error().Err(err).Interface("resource", resources[i]).Msg("CreateYamlResult fails")
				continue
			}
			_, err = iacModel.FirstOrCreateRecord(ctx, db, iacModel.YamlRecord{
				ResultID:           r.ID,
				ResourceClusterKey: resources[i].ClusterKey,
				ResourceNamespace:  resources[i].Namespace,
				ResourceKind:       resources[i].Kind,
				ResourceName:       resources[i].Name,
				ResourceGeneration: resources[i].Generation,
				Status:             iacModel.YamlRecordStatusInitial,
				SuccessRate:        -1,
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			})
			if err != nil {
				logging.Get().Error().Err(err).Interface("resource", resources[i]).Msg("FirstOrCreateRecord fails")
				continue
			}
		}
	}
	return nil
}

func syncOnlineResources() {
	f := func() error {
		logging.Get().Debug().Msg("syncOnlineResources...")
		ctx := context.Background()
		timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		total, err := resSvc.CountResourceWithRedis(timeOutCtx, dal.ResourcesQuery())
		if err != nil {
			logging.Get().Error().Err(err).Msg("CountResourceWithRedis fails")
			return err
		}
		offset, limit := 0, 100
		totalResources := make([]*model.TensorResource, 0)
		for offset < int(total) {
			timeOutCtx, c := context.WithTimeout(ctx, time.Second)
			resources, _, err := resSvc.GetResourceWithRedis(timeOutCtx, dal.ResourcesQuery(), offset, limit)
			if err != nil {
				logging.Get().Error().Err(err).Msg("GetResourceWithRedis fails")
				c()
				return err
			}
			totalResources = append(totalResources, resources...)
			offset += limit
			c()
		}

		timeOutCtx, uc := context.WithTimeout(ctx, time.Second*5)
		defer uc()
		err = iacModel.UpdateYamlRecord(timeOutCtx, db, map[string]interface{}{"resource_online": 1}, map[string]interface{}{"resource_online": 0})
		if err != nil {
			logging.Get().Error().Err(err).Msg("UpdateYamlRecord fails")
			return err
		}
		onlineIDs := make([]int, 0)
		for i := range totalResources {
			timeOutCtx, c := context.WithTimeout(ctx, time.Second)
			records, err := iacModel.FindYamlRecords(timeOutCtx, db, map[string]interface{}{
				"resource_cluster_key": totalResources[i].ClusterKey,
				"resource_namespace":   totalResources[i].Namespace,
				"resource_kind":        totalResources[i].Kind,
				"resource_name":        totalResources[i].Name,
				"resource_generation":  totalResources[i].Generation,
			}, map[string]interface{}{"order": "id desc", "limit": 1})
			if err != nil || len(records) != 1 {
				err = fmt.Errorf("FindYamlRecords err: %v, len: %d", err, len(records))
				logging.Get().Error().Err(err).
					Str("resource_cluster_key", totalResources[i].ClusterKey).
					Str("resource_namespace", totalResources[i].Namespace).
					Str("resource_namespace", totalResources[i].Kind).
					Str("resource_name", totalResources[i].Name).
					Int64("resource_generation", totalResources[i].Generation).
					Msg("FindYamlRecords fails")
				c()
				continue
			}
			c()
			onlineIDs = append(onlineIDs, records[0].ID)
		}

		timeOutCtx, uc2 := context.WithTimeout(ctx, time.Second*5)
		err = iacModel.UpdateYamlRecordByIDs(timeOutCtx, db, onlineIDs, map[string]interface{}{"resource_online": 1})
		if err != nil {
			logging.Get().Error().Err(err).Ints("ids", onlineIDs).Msg("UpdateYamlRecordByIDs fails")
			uc2()
			return err
		}
		uc2()

		return nil
	}

	go func() {
		//// 启动时先同步一次
		//err := f()
		//if err != nil {
		//	logging.Get().Error().Err(err).Msg("syncOnlineResources fails")
		//}

		tick := time.NewTicker(time.Minute * 5)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				err := f()
				if err != nil {
					logging.Get().Error().Err(err).Msg("syncOnlineResources fails")
				}
			}
		}
	}()

}

func initBuiltInScheduleAndTemplate() error {
	timeOutCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// template
	templates, err := iacModel.FindYamlTemplates(timeOutCtx, db, map[string]interface{}{"builtin": 1})
	if err != nil {
		logging.Get().Error().Err(err).Msg("find builtin template fails")
		return err
	}
	var templateSnapshot iacModel.YamlTemplateSnapshot
	if len(templates) == 0 {
		rules, err := iacModel.FindYamlRules(timeOutCtx, db, map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Error().Err(err).Msgf("FindYamlRules fails")
			return err
		}
		if len(rules) == 0 {
			rules = iacModel.YamlRules
			err = iacModel.CreateYamlRules(timeOutCtx, db, rules)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("CreateYamlRules fails")
				return err
			}
		}
		ruleBuiltinIDs := make([]string, len(rules))
		for i := range rules {
			ruleBuiltinIDs[i] = rules[i].BuiltinID
		}
		template, err := iacModel.CreateYamlTemplate(timeOutCtx, db, iacModel.YamlTemplate{
			Name:        DefaultTemplateName,
			Description: "",
			Rules:       ruleBuiltinIDs,
			Creator:     "",
			Updater:     "",
			Builtin:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Msgf("CreateYamlTemplate fails")
			return err
		}
		templateSnapshot, err = iacModel.CreateYamlTemplateSnapshot(timeOutCtx, db, iacModel.YamlTemplateSnapshot{
			TemplateID:  template.ID,
			Name:        DefaultTemplateName,
			Description: "",
			Rules:       ruleBuiltinIDs,
			Creator:     "",
			Updater:     "",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", template.ID).Msgf("CreateYamlTemplateSnapshot fails")
			return err
		}
	}
	// 创建默认schedule
	// 周期计划：period_schedule, tid, built-in user-set period schedule, * * * * *, time, time, time
	// 变更计划：update_schedule, tid, built-in update triggered schedule, null, null, time, time
	schedules, err := iacModel.FindYamlSchedules(timeOutCtx, db, map[string]interface{}{"name": DBPeriodScheduleName})
	if err != nil {
		logging.Get().Error().Err(err).Str("name", DBPeriodScheduleName).Msg("FindYamlSchedules fails")
		return err
	}
	templateID := templateSnapshot.ID
	if len(schedules) == 0 {
		BuiltInPeriodSchedule, err = iacModel.CreateYamlSchedule(timeOutCtx, db, iacModel.YamlSchedule{
			Name:        DBPeriodScheduleName,
			TemplateID:  templateID,
			Description: DBPeriodScheduleDescription,
			Schedule:    DBPeriodScheduleSchedule,
			Config:      []byte(`{}`),
			Status:      DBScheduleOff,
			NextTime:    time.Now(),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", DBPeriodScheduleName).Msg("CreateYamlSchedule fails")
			return err
		}
	} else {
		if len(schedules) != 1 {
			logging.Get().Error().Err(err).Str("name", DBPeriodScheduleName).Msg("more than one schedules")
		}
		BuiltInPeriodSchedule = schedules[0]
	}

	schedules, err = iacModel.FindYamlSchedules(timeOutCtx, db, map[string]interface{}{"name": DBUpdateScheduleName})
	if err != nil {
		logging.Get().Error().Err(err).Str("name", DBUpdateScheduleName).Msg("FindYamlSchedules fails")
		return err
	}
	if len(schedules) == 0 {
		BuiltInUpdateSchedule, err = iacModel.CreateYamlSchedule(timeOutCtx, db, iacModel.YamlSchedule{
			Name:        DBUpdateScheduleName,
			TemplateID:  templateID,
			Description: DBUpdateScheduleDescription,
			Schedule:    "",
			Config:      []byte("{}"),
			Status:      DBScheduleOff,
			NextTime:    time.Now(),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Str("name", DBUpdateScheduleName).Msg("CreateYamlSchedule fails")
			return err
		}
	} else {
		if len(schedules) != 1 {
			logging.Get().Error().Err(err).Str("name", DBUpdateScheduleName).Msg("more than one schedules")
		}
		BuiltInUpdateSchedule = schedules[0]
	}

	return nil
}

func startScheduleYamlScan() {
	go func() {
		ctx := context.Background()

		tick := time.NewTicker(time.Second * 30)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				err := handlePeriodScan(ctx)
				if err != nil {
					logging.Get().Error().Err(err).Msg("handlePeriodScan fails")
					continue
				}
			}
		}

	}()
}

func handlePeriodScan(ctx context.Context) error {
	logging.Get().Debug().Msg("handlePeriodScan...")
	// 未开启不执行
	if BuiltInPeriodSchedule.Status == DBScheduleOff {
		return nil
	}

	// check schedule next_time
	logging.Get().Debug().Time("next_time", BuiltInPeriodSchedule.NextTime).Time("now", time.Now()).Msg("check schedule next_time")
	if !BuiltInPeriodSchedule.NextTime.Before(time.Now()) {
		return nil
	}

	// 计算 next_time
	schedule, _ := cron.ParseStandard(BuiltInPeriodSchedule.Schedule)
	// fixme: schedule是前端通过字符串设置过来的，隐含的带了时区
	BuiltInPeriodSchedule.NextTime = schedule.Next(time.Now().Add(time.Hour * 8)).Add(time.Hour * -8)
	err := iacModel.UpdateYamlSchedule(ctx, db, map[string]interface{}{"id": BuiltInPeriodSchedule.ID}, map[string]interface{}{"next_time": BuiltInPeriodSchedule.NextTime})
	if err != nil {
		logging.Get().Error().Err(err).Msg("UpdateYamlSchedule fails")
		return err
	}

	config := make(map[string]interface{})
	err = json.Unmarshal(BuiltInPeriodSchedule.Config, &config)
	if err != nil {
		logging.Get().Error().Err(err).Msg("Unmarshal BuiltInPeriodSchedule.Config fails")
		return err
	}
	query := dal.ResourcesQuery()
	allClusters, ok := config["all"].(bool)
	if !ok {
		allClusters = false
	}
	if !allClusters {
		iClusterKeys, ok := config["clusters"].([]interface{})
		if !ok || len(iClusterKeys) == 0 {
			logging.Get().Info().Interface("config", config).Msg("BuiltInPeriodSchedule.Config.clusters may not set")
			return nil
		}
		clusterKeys := make([]string, len(iClusterKeys))
		for i := range iClusterKeys {
			clusterKeys[i] = iClusterKeys[i].(string)
		}
		query = dal.ResourcesQuery().WithInConditionCustom("cluster_key", clusterKeys)
	}

	// 创建一个task
	timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	total, err := resSvc.CountResourceWithRedis(timeOutCtx, query)
	if err != nil {
		logging.Get().Error().Err(err).Msg("CountResourceWithRedis fails")
		return err
	}

	templateSnapshots, err := iacModel.FindYamlTemplateSnapshots(ctx, db, map[string]interface{}{"template_id": BuiltInPeriodSchedule.TemplateID}, map[string]interface{}{"order": "id desc", "limit": 1})
	if err != nil || len(templateSnapshots) != 1 {
		logging.Get().Error().Err(fmt.Errorf("FindYamlTemplateSnapshots err: %v, len: %d", err, len(templateSnapshots))).Msg("FindYamlTemplateSnapshots fails")
		return err
	}

	task, err := iacModel.CreateYamlTask(ctx, db, iacModel.YamlTask{
		ScanType:     iacModel.YamlTaskScanTypePeriod,
		ScheduleID:   BuiltInPeriodSchedule.ID,  // 资源变更的schedule ID
		TemplateID:   templateSnapshots[0].ID,   // 模板快照id
		TemplateName: templateSnapshots[0].Name, // 模板快照name
		Total:        int(total),
		Status:       iacModel.YamlTaskStatusPreparing,
		Duration:     -1, // 扫描后更新
		Creator:      iacModel.OperatorSystem,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("CreateYamlTask fails")
		return err
	}
	recordsToRun := make([]iacModel.RecordToRun, 0)
	// 查询当前所有资源
	f := func(offset, limit int) bool {
		timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
		defer cancel()
		resources, _, err := resSvc.GetResourceWithRedis(timeOutCtx, query, offset, limit)
		if err != nil {
			logging.Get().Error().Err(err).Msg("GetResourceWithRedis fails")
			return true
		}

		for i := range resources {
			// 获取每个resource的yaml
			var yamlData []byte
			var resourceGeneration int64
			// 先查询record，有record就不用请求k8s了(已经被扫描过)
			timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
			results, err := iacModel.FindYamlResults(timeOutCtx, db, map[string]interface{}{
				"resource_cluster_key": resources[i].ClusterKey,
				"resource_namespace":   resources[i].Namespace,
				"resource_kind":        resources[i].Kind,
				"resource_name":        resources[i].Name,
				"resource_generation":  resources[i].Generation,
			}, map[string]interface{}{"order": "id desc", "limit": 1})
			if err != nil {
				logging.Get().Error().Err(err).Msg("FindYamlResults fails")
				continue
			}
			if len(results) == 1 && results[0].Yaml != "" {
				yamlData = []byte(results[0].Yaml)
				resourceGeneration = resources[i].Generation
			} else {
				clientSet, ok := clusterManager.GetClient(resources[i].ClusterKey)
				if !ok {
					err = fmt.Errorf("clientset of cluster: %s not available", resources[i].ClusterKey)
					logging.Get().Error().Err(err).Msg("clusterManager.GetClient fails")
					continue
				}
				yamlData, resourceGeneration, err = GetYamlFromK8s(ctx, clientSet, iacModel.Resource{
					ClusterKey: resources[i].ClusterKey,
					Namespace:  resources[i].Namespace,
					Kind:       resources[i].Kind,
					Name:       resources[i].Name,
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("GetYamlFromK8s fails")
					continue
				}
			}

			// 每个资源创建一个result和record，保证先完成
			// ivan_iac_yaml_results
			timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
			now := time.Now()
			result, err := iacModel.FirstOrCreateResult(timeOutCtx, db, iacModel.YamlResult{
				ResourceClusterKey: resources[i].ClusterKey,
				ResourceNamespace:  resources[i].Namespace,
				ResourceKind:       resources[i].Kind,
				ResourceName:       resources[i].Name,
				ResourceGeneration: resourceGeneration,
				Duration:           0,
				Status:             iacModel.YamlResultStatusWaiting,
				Result:             "",
				Yaml:               string(yamlData),
				CreatedAt:          now,
				UpdatedAt:          now,
			})
			if err != nil {
				logging.Get().Error().Err(err).Msg("CreateYamlResult fails")
				cancel()
				continue
			}
			cancel()

			// 查询出历史记录，直接使用result，创建record
			if result.CreatedAt != now && result.Result != "" {
				// ivan_iac_yaml_records
				_, successRate, err := iacModel.FilterYamlResultByTemplate(ctx, db, result.Result, task.TemplateID)
				if err != nil {
					logging.Get().Error().Err(err).Msg("FilterYamlResultByTemplate fails")
					continue
				}
				_, err = iacModel.CreateYamlRecordAndNewOnline(ctx, db, iacModel.YamlRecord{
					TaskID:             task.ID,
					TemplateID:         task.TemplateID,
					TemplateName:       task.TemplateName,
					ResourceClusterKey: resources[i].ClusterKey,
					ResourceNamespace:  resources[i].Namespace,
					ResourceKind:       resources[i].Kind,
					ResourceName:       resources[i].Name,
					ResourceGeneration: resourceGeneration,
					Status:             iacModel.YamlRecordStatusWaiting,
					SuccessRate:        successRate,
					ResultID:           result.ID,
					CreatedAt:          time.Now(),
					UpdatedAt:          time.Now(),
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
					continue
				}
				continue
			} else {
				// ivan_iac_yaml_records
				record, err := iacModel.CreateYamlRecordAndNewOnline(ctx, db, iacModel.YamlRecord{
					TaskID:             task.ID,
					TemplateID:         task.TemplateID,
					TemplateName:       task.TemplateName,
					ResourceClusterKey: resources[i].ClusterKey,
					ResourceNamespace:  resources[i].Namespace,
					ResourceKind:       resources[i].Kind,
					ResourceName:       resources[i].Name,
					ResourceGeneration: resourceGeneration,
					Status:             iacModel.YamlRecordStatusWaiting,
					SuccessRate:        -1,
					ResultID:           result.ID,
					CreatedAt:          time.Now(),
					UpdatedAt:          time.Now(),
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
					continue
				}
				recordsToRun = append(recordsToRun, iacModel.RecordToRun{Record: record, Result: result, Yaml: yamlData})
			}

		}
		return len(resources) < limit
	}
	offset := 0
	limit := 100
	over := false
	for {
		if !over {
			over = f(offset, limit)
			offset += limit
		} else {
			break
		}
	}

	if len(recordsToRun) != 0 {
		// 子任务全部创建完成，修改任务状态 preparing -> waiting
		err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusWaiting})
		if err != nil {
			logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
			err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
			return err
		}

		for i := range recordsToRun {
			// 每个资源发送一个job
			SendScan(ctx, len(recordsToRun), task, recordsToRun[i].Record, recordsToRun[i].Result, iacModel.Resource{
				ClusterKey: recordsToRun[i].Record.ResourceClusterKey,
				Namespace:  recordsToRun[i].Record.ResourceNamespace,
				Kind:       recordsToRun[i].Record.ResourceKind,
				Name:       recordsToRun[i].Record.ResourceName,
				Generation: recordsToRun[i].Record.ResourceGeneration,
			}, recordsToRun[i].Yaml)
			if i == 0 {
				// 子任务开始执行，修改任务状态 waiting -> scanning
				err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusScanning})
				if err != nil {
					logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
					err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
					return err
				}
			}
		}
	} else {
		err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusComplete, "success": total})
		if err != nil {
			logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
			err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
			return err
		}
		err = iacModel.UpdateYamlRecord(ctx, db, map[string]interface{}{"task_id": task.ID}, map[string]interface{}{"status": iacModel.YamlRecordStatusComplete})
		if err != nil {
			return err
		}
	}

	return nil
}

func handleKubeResourcesChange(ctx context.Context, message kafka.Message) error {

	// 解析kafka数据
	kafkaData := pkgassets.ResourceEvent{}
	err := json.Unmarshal(message.Value, &kafkaData)
	if err != nil {
		logging.Get().Error().Err(err).Msg("Unmarshal ResourceEvent fails")
		return err
	}

	yamlData := kafkaData.YamlData
	if yamlData == nil {
		return nil
	}

	// 获取resource数据，并做validation检查（确保不是重复数据）
	var resourceNamespace, resourceKind, resourceName string
	var resourceGeneration int64
	resourceCreationTimestamp := time.Now().Add(-time.Hour)
	resourceM, ok := kafkaData.Resource.(map[string]interface{})
	if ok {
		resourceNamespace, _ = resourceM["namespace"].(string)
		resourceKind, _ = resourceM["kind"].(string)
		resourceName, _ = resourceM["name"].(string)
		fGeneration, _ := resourceM["generation"].(float64)
		resourceGeneration = int64(fGeneration)
		creationTimestamp, ok := resourceM["creationTimestamp"].(string)
		if ok {
			resourceCreationTimestamp, err = time.Parse("2006-01-02T15:04:05Z", creationTimestamp)
		}
	}

	// action==add 表示为新建资源
	// CreationTimestamp - now > minute * 1 表示不是【刚刚】新建的资源
	// 此处为了避免cluster-manager重启导致的重复处理
	if kafkaData.Action == pkgassets.ActionAdd && time.Now().Sub(resourceCreationTimestamp) > time.Minute {
		return nil
	}
	// 资源同步到records中
	_, err = iacModel.FirstOrCreateRecord(ctx, db, iacModel.YamlRecord{
		ResourceClusterKey: kafkaData.ClusterKey,
		ResourceNamespace:  resourceNamespace,
		ResourceKind:       resourceKind,
		ResourceName:       resourceName,
		ResourceGeneration: resourceGeneration,
		Status:             iacModel.YamlRecordStatusInitial,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	})
	if err != nil {
		logging.Get().Error().Err(err).Interface("resource", resourceM).Msg("FirstOrCreateRecord fails")
	}
	// ivan_iac_yaml_results
	timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	now := time.Now()
	result, err := iacModel.FirstOrCreateResult(timeOutCtx, db, iacModel.YamlResult{
		ResourceClusterKey: kafkaData.ClusterKey,
		ResourceNamespace:  resourceNamespace,
		ResourceKind:       resourceKind,
		ResourceName:       resourceName,
		ResourceGeneration: resourceGeneration,
		Duration:           0,
		Status:             iacModel.YamlResultStatusWaiting,
		Result:             "",
		Yaml:               string(yamlData),
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("CreateYamlResult fails")
		return err
	}

	// 未开启不执行扫描
	if BuiltInUpdateSchedule.Status == DBScheduleOff {
		return nil
	}

	// 结果写入数据库
	// ivan_iac_yaml_tasks
	templateSnapshots, err := iacModel.FindYamlTemplateSnapshots(ctx, db, map[string]interface{}{"template_id": BuiltInUpdateSchedule.TemplateID}, map[string]interface{}{"order": "id desc", "limit": 1})
	if err != nil || len(templateSnapshots) != 1 {
		logging.Get().Error().Err(fmt.Errorf("FindYamlTemplateSnapshots err: %v, len: %d", err, len(templateSnapshots))).Msg("FindYamlTemplateSnapshots fails")
		return err
	}
	task, err := iacModel.CreateYamlTask(ctx, db, iacModel.YamlTask{
		ScanType:     iacModel.YamlTaskScanTypeUpdate,
		ScheduleID:   BuiltInUpdateSchedule.ID, // 资源变更的schedule ID
		TemplateID:   templateSnapshots[0].ID,
		TemplateName: templateSnapshots[0].Name,
		Total:        1,
		Status:       iacModel.YamlTaskStatusWaiting,
		Duration:     -1, // 扫描后更新'
		Creator:      iacModel.OperatorSystem,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("CreateYamlTask fails")
		return err
	}

	var record iacModel.YamlRecord
	// 查询出历史记录，直接使用result，创建record
	if result.CreatedAt != now && result.Result != "" {
		// ivan_iac_yaml_records
		_, successRate, err := iacModel.FilterYamlResultByTemplate(ctx, db, result.Result, task.TemplateID)
		if err != nil {
			logging.Get().Error().Err(err).Msg("FilterYamlResultByTemplate fails")
			return err
		}
		record, err = iacModel.CreateYamlRecordAndNewOnline(ctx, db, iacModel.YamlRecord{
			TaskID:             task.ID,
			TemplateID:         task.TemplateID,
			TemplateName:       task.TemplateName,
			ResourceClusterKey: kafkaData.ClusterKey,
			ResourceNamespace:  resourceNamespace,
			ResourceKind:       resourceKind,
			ResourceName:       resourceName,
			ResourceGeneration: resourceGeneration,
			Status:             iacModel.YamlRecordStatusComplete,
			SuccessRate:        successRate,
			ResultID:           result.ID,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
			return err
		}
		err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusComplete, "success": 1})
		if err != nil {
			logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
			err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
			return err
		}
		return nil
	} else {
		// ivan_iac_yaml_records
		record, err = iacModel.CreateYamlRecordAndNewOnline(ctx, db, iacModel.YamlRecord{
			TaskID:             task.ID,
			TemplateID:         task.TemplateID,
			TemplateName:       task.TemplateName,
			ResourceClusterKey: kafkaData.ClusterKey,
			ResourceNamespace:  resourceNamespace,
			ResourceKind:       resourceKind,
			ResourceName:       resourceName,
			ResourceGeneration: resourceGeneration,
			Status:             iacModel.YamlRecordStatusWaiting,
			SuccessRate:        -1,
			ResultID:           result.ID,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Msg("CreateYamlRecord fails")
			return err
		}
	}

	SendScan(ctx, 1, task, record, result, iacModel.Resource{
		ClusterKey: kafkaData.ClusterKey,
		Namespace:  resourceNamespace,
		Kind:       resourceKind,
		Name:       resourceName,
		Generation: resourceGeneration,
	}, yamlData)

	err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusScanning})
	if err != nil {
		logging.Get().Error().Err(err).Int("task_id", task.ID).Msg("UpdateYamlTask to scanning fails")
		err = iacModel.UpdateYamlTask(ctx, db, map[string]interface{}{"id": task.ID}, map[string]interface{}{"status": iacModel.YamlTaskStatusFailed, "fail_reason": iacModel.YamlTaskFailReasonDBFails})
		return err
	}

	return nil
}

func SendScan(ctx context.Context, todo int, task iacModel.YamlTask, record iacModel.YamlRecord, result iacModel.YamlResult, resource iacModel.Resource, yamlData []byte) {

	// 异步扫描yaml数据
	AddYamlScanJob(YamlJob{
		YamlData: yamlData,
		Resource: iacModel.Resource{
			ClusterKey: resource.ClusterKey,
			Namespace:  resource.Namespace,
			Kind:       resource.Kind,
			Name:       resource.Name,
			Generation: resource.Generation,
		},
		TemplateID: record.TemplateID,
		TaskID:     task.ID,
		RecordID:   record.ID,
		ResultID:   result.ID,
		Total:      task.Total,
		Todo:       todo,
	})
}

func GetYamlFromK8s(ctx context.Context, clientSet *pkgassets.Clientset, resource iacModel.Resource) ([]byte, int64, error) {
	var object interface{}
	var generation int64
	switch resource.Kind {
	case string(pkgassets.KindDeployment):
		deployment, err := clientSet.Clientset.AppsV1().Deployments(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get deployment fails")
			return nil, generation, err
		}
		generation = deployment.Generation
		object = deployment
	case string(pkgassets.KindDaemonSet):
		daemonSet, err := clientSet.Clientset.AppsV1().DaemonSets(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get daemonSet fails")
			return nil, generation, err
		}
		generation = daemonSet.Generation
		object = daemonSet
	case string(pkgassets.KindReplicaSet):
		replicaSet, err := clientSet.Clientset.AppsV1().ReplicaSets(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get replicaSet fails")
			return nil, generation, err
		}
		generation = replicaSet.Generation
		object = replicaSet
	case string(pkgassets.KindStatefulSet):
		statefulSet, err := clientSet.Clientset.AppsV1().StatefulSets(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get statefulSet fails")
			return nil, generation, err
		}
		generation = statefulSet.Generation
		object = statefulSet
	case string(pkgassets.KindJob):
		job, err := clientSet.Clientset.BatchV1().Jobs(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get job fails")
			return nil, generation, err
		}
		generation = job.Generation
		object = job
	case string(pkgassets.KindCronJob):
		cronJob, err := clientSet.Clientset.BatchV1beta1().CronJobs(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get cronJob fails")
			return nil, generation, err
		}
		generation = cronJob.Generation
		object = cronJob
	case string(pkgassets.KindReplicationController):
		replicationController, err := clientSet.Clientset.CoreV1().ReplicationControllers(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get replicationController fails")
			return nil, generation, err
		}
		generation = replicationController.Generation
		object = replicationController
	case string(pkgassets.KindPodNoOwner):
		pod, err := clientSet.Clientset.CoreV1().Pods(resource.Namespace).Get(ctx, resource.Name, metav1.GetOptions{})
		if err != nil {
			logging.Get().Error().Err(err).Msg("clientSet get replicationController fails")
			return nil, generation, err
		}
		generation = pod.Generation
		object = pod
	}

	bYaml, err := sigYaml.Marshal(pkgassets.PureObject(object))
	if err != nil {
		logging.Get().Error().Err(err).Str("clusterKey", resource.ClusterKey).Str("namespace", resource.Namespace).Str("kind", resource.Kind).Str("name", resource.Name).Msgf("object marshal to yaml fails")
		return nil, generation, err
	}
	return bYaml, generation, nil
}
