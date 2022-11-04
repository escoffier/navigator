package scapper

import (
	"context"
	"time"

	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
			logging.GetLogger().Error().Err(err).Msg("get harbor project config error")
			continue
		}
		harborCfg.Report[v.Name] = projectCfg
		time.Sleep(time.Millisecond * 200)
	}

	//harborCfg.FinishedAt = time.Now().Unix()
	//_, err = s.MongoDB.Get().Collection(model.HarborProjectConfigCollection.String()).InsertOne(ctx, harborCfg)
	//if err != nil {
	//	return uuid.Nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("failed to insert new config to harbor  mapping to mongo: %w", err))
	//}

	return checkUUID, nil
}
