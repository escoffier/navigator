package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/env"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/notifyhandler"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/reporter"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/taskmanager"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	templateID     = int32(util.GetIntValWithDefault(env.TemplateID, 0))
	uuid           = util.GetEnvWithDefault(env.UUID, "")
	startTimestamp = int64(util.GetIntValWithDefault(env.StartTimestamp, 0))
	endTimestamp   = int64(util.GetIntValWithDefault(env.EndTimestamp, 0))
	maxTaskTime    = time.Duration(util.GetIntValWithDefault(env.MaxTaskTimeSec, env.DefaultMaxTaskTimeSec)) * time.Second
	db             *rdbtools.GormWrapper
	manager        def.TaskManager
	handler        def.NotifyHandler
	emailConf      = &def.EmailConf{
		Username: util.GetEnvWithDefault(env.EmailUsername, env.DefaultEmailUsername),
		Password: util.GetEnvWithDefault(env.EmailPassword, env.DefaultEmailPassword),
		Host:     util.GetEnvWithDefault(env.EmailHost, env.DefaultEmailHost),
		Port:     util.GetIntValWithDefault(env.DefaultEmailHost, env.DefaultEmailPort),
		BaseURL:  util.GetEnvWithDefault(env.NotifyBaseURL, ""),
	}
)

func main() {
	if templateID == 0 || uuid == "" || startTimestamp <= 0 || endTimestamp < startTimestamp {
		logrus.Fatalf("invalid arg, templateID:%d, uuid:%s, startTimestamp:%d, endTimestamp:%d",
			templateID, uuid, startTimestamp, endTimestamp)
	}

	if maxTaskTime == 0 {
		logrus.Fatalf("invalid taskTime")
	}

	logrus.Infof("start to generate report, templateID:%d, uuid:%s, startTime:%s, endTime:%s, maxTaskTime:%s",
		templateID, uuid, util.GetTimeByMillisecondTimestamp(startTimestamp), util.GetTimeByMillisecondTimestamp(endTimestamp), maxTaskTime)

	var err error
	db, err = newDBFromEnv()
	if err != nil {
		logrus.Fatalf("new db fail, err:%s", err)
	}

	manager = taskmanager.NewManager(db, maxTaskTime, def.ReportPath)
	handler = notifyhandler.NewHandler(emailConf)

	if err = handleTask(); err != nil {
		logrus.Errorf("handle task fail, err:%s", err)
	} else {
		logrus.Infof("finished sucessfully!")
	}
}

func handleTask() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), maxTaskTime)
	defer cancel()

	defer func() {
		if err != nil {
			oneCtx, oneCancel := context.WithTimeout(context.Background(), time.Second*3)
			defer oneCancel()
			if _err := updateTaskFailed(oneCtx, uuid); _err != nil {
				logrus.Errorf("updateTaskStatus fail, err:%s", err)
			}
		}
	}()

	taskTemplate, err := getTaskTemplate(ctx)
	if err != nil {
		return err
	}

	var categories []string
	err = json.Unmarshal(util.String2BytesNoCopy(taskTemplate.Categories), &categories)
	if err != nil {
		return fmt.Errorf("parse categories fail, err:%s", err)
	}

	var clusters []string
	err = json.Unmarshal(util.String2BytesNoCopy(taskTemplate.Clusters), &clusters)
	if err != nil {
		return fmt.Errorf("parse clusters fail, err:%s", err)
	}

	categoryHash := util.StringArrToMap(categories)
	clusterHash := util.StringArrToMap(clusters)

	if len(categoryHash) == 0 || len(clusterHash) == 0 {
		return fmt.Errorf("invalid taskTemplate, templateID:%d", templateID)
	}

	var report = &model.ReportDetail{
		TemplateName:   taskTemplate.Name,
		Type:           taskTemplate.Type,
		Categories:     categories,
		StartTimestamp: startTimestamp,
		EndTimestamp:   endTimestamp,
	}

	clusterItems := reporter.GetClusters(ctx, db, clusters, util.GetTimeByMillisecondTimestamp(endTimestamp))
	clusterKeyHash := reporter.GenerateClusterKeyHash(clusterItems)
	for category := range categoryHash {
		switch category {
		case model.ReportCategoryEvents:
			if len(clusterItems) == 0 {
				report.EventsReport = &model.EventsReport{}
				continue
			}
			report.EventsReport = reporter.LoadEventsReport(ctx, db, startTimestamp, endTimestamp, clusterKeyHash)
		case model.ReportCategoryAssets:
			if len(clusterItems) == 0 {
				report.AssetsReport = &model.AssetsReport{}
				continue
			}
			report.AssetsReport = reporter.LoadAssetsReport(ctx, db, clusterItems, endTimestamp)
		case model.ReportCategoryImages:
			report.ImagesReport = reporter.LoadImagesReport(ctx, db, endTimestamp)
		default:
			logrus.Errorf("unexpected report category:%s", category)
		}
	}

	content, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report fail, err:%s", err)
	}

	err = finishTask(ctx, templateID, uuid, content)
	if err != nil {
		return fmt.Errorf("updateTaskStatus fail, err:%s", err)
	}

	if _err := handler.Notify(ctx, taskTemplate, startTimestamp, endTimestamp); _err != nil {
		logrus.Errorf("notify fail, err:%s", _err)
	}

	return nil
}

func getTaskTemplate(ctx context.Context) (*model.ReportTaskTemplateMeta, error) {
	var task *model.ReportTaskTemplateMeta
	get := func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, time.Millisecond*500)
		defer oneCancel()
		var _err error
		task, _err = manager.GetTaskTemplate(oneCtx, templateID)
		if _err == def.ErrTaskTemplateNotExist {
			logrus.Errorf("template not found, templateID:%d", templateID)
			return nil
		}

		return _err
	}

	err := util.RetryWithBackoff(ctx, get)
	if err != nil {
		logrus.Errorf("get task fail, err:%s", err)
		return nil, err
	}

	if task == nil {
		return nil, fmt.Errorf("task not found, id:%d", templateID)
	}

	return task, nil
}

func updateTaskFailed(ctx context.Context, uuid string) error {
	update := func() error {
		oneCtx, cancel := context.WithTimeout(ctx, time.Second*2)
		defer cancel()
		return manager.UpdateTaskFailed(oneCtx, uuid)
	}

	return util.RetryWithBackoff(ctx, update)
}

func finishTask(ctx context.Context, templateID int32, uuid string, content []byte) error {
	finish := func() error {
		oneCtx, cancel := context.WithTimeout(ctx, time.Second*2)
		defer cancel()
		return manager.FinishTask(oneCtx, templateID, uuid, content)
	}
	return util.RetryWithBackoff(ctx, finish)
}

func newDBFromEnv() (*rdbtools.GormWrapper, error) {
	postgresqlDSN := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s password=%s",
		util.GetEnvWithDefault(env.PostgresHost, env.DefaultPostgresHost),
		util.GetIntValWithDefault(env.PostgresPort, env.DefaultPostgresPort),
		util.GetEnvWithDefault(env.PostgresUser, env.DefaultPostgresUser),
		util.GetEnvWithDefault(env.PostgresDBName, env.DefaultPostgresDBName),
		util.GetEnvWithDefault(env.PostgresSSLMode, env.DefaultPostgresSSLMode),
		util.GetEnvWithDefault(env.PostgresPassword, ""),
	)

	return rdbtools.NewPostgresClient(postgresqlDSN)
}
