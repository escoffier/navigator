package scapper

import (
	"context"
	"fmt"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (s *Scapper) RunHarborCheck(ctx context.Context, harborClient *harbor.HarborRESTClient) (uuid.UUID, error) {

	// generate check uuid that will identify results of this run in database
	checkUUID := uuid.NewV4()

	harborCfg := model.HarborConfigScan{
		CheckID:   checkUUID.String(),
		CreatedAt: time.Now().Unix(),
		Report:    make(map[string][]model.CfgScan),
	}

	item, harborAddr, err := harborClient.GetHarborProject(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	harborCfg.Harbor = harborAddr

	for _, v := range item {
		projectCfg, err := harborClient.GetHarborProjectConfig(ctx, v.ProjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("get harbor project config error：%w", err)
			continue
		}
		harborCfg.Report[v.Name] = projectCfg
		time.Sleep(time.Millisecond * 200)
	}

	harborCfg.FinishedAt = time.Now().Unix()
	_, err = s.MongoDB.Get().Collection(model.HarborProjectConfigCollection.String()).InsertOne(ctx, harborCfg)
	if err != nil {
		return uuid.Nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("failed to insert new config to harbor  mapping to mongo: %w", err))
	}

	return checkUUID, nil
}

func (s *Scapper) HarborConfigList(ctx context.Context, offset, limit int64, projectName, checkID string) ([]model.HarborConfigScan, int64, error) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*2)
	defer mongoCtxCancel()

	opt := options.Find()
	opt.SetMaxTime(time.Second * 2)
	opt.SetLimit(limit)
	opt.SetSkip(offset)
	opt.SetSort(bson.D{{"finishedAt", -1}})
	copt := options.Count()

	filter := bson.M{}
	if checkID != "" {
		filter = bson.M{"checkId": checkID}
	}
	count, err := s.MongoDB.Get().Collection(model.HarborProjectConfigCollection.String()).CountDocuments(mongoCtx, filter, copt)
	cur, err := s.MongoDB.Get().Collection(model.HarborProjectConfigCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return nil, 0, err
	}

	harborConfigSlice := make([]model.HarborConfigScan, 0)
	for cur.Next(mongoCtx) {
		var harborConfig model.HarborConfigScan
		err := cur.Decode(&harborConfig)
		if err != nil {
			return nil, 0, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't decode document: %w", err))
		}
		if projectName != "" {
			for k, _ := range harborConfig.Report {
				if k != projectName {
					delete(harborConfig.Report, k)
				}
			}
		}

		harborConfigSlice = append(harborConfigSlice, harborConfig)
	}

	return harborConfigSlice, count, nil
}
