package drift

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	es "github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

var (
	EScli                 *elastic.ESClient
	instance              *TensorDriftService
	rlOnce                sync.Once
	ErrESDocumentNotFound = errors.New("es document not found")
)

func InitResourcesService(rdb *databases.RDBInstance, es *elastic.ESClient) error {
	rlOnce.Do(func() {
		EScli = es
		instance = newTensorResourcesService(rdb, es)
		go instance.UpdateCachePolicy()
	})
	return nil
}

func GetDriftES(ctx context.Context) (*es.Client, error) {
	return EScli.Get()
}

func (rl *TensorDriftService) UpdateCachePolicy() {
	ctx := context.Background()
	for {
		policies, err := dal.GetAllPolicies(ctx, rl.rdb.GetReadDB())
		if err != nil {
			logging.GetLogger().Err(err).Msgf("UpdateCachePolicy error")
			return
		}
		var maxTime int64
		for _, v := range policies {
			if v.UpdatedAt.Unix() > maxTime {
				maxTime = v.UpdatedAt.Unix()
			}
		}
		rl.Cache.LastTime = maxTime
		rl.Cache.Policies = policies
		time.Sleep(5 * time.Minute)
	}
}

func GetDriftService(_ context.Context) (*TensorDriftService, bool) {
	return instance, instance != nil
}

type TensorDriftService struct {
	rdb   *databases.RDBInstance
	Cache model.DriftPolicyCache
	es    *elastic.ESClient
}

func newTensorResourcesService(rdb *databases.RDBInstance, es *elastic.ESClient) *TensorDriftService {
	return &TensorDriftService{
		rdb: rdb,
		es:  es,
	}
}

func (rl *TensorDriftService) CreatePolicy(ctx context.Context, policy model.DriftPolicy) (int64, error) {
	return dal.CreateDriftPolicy(ctx, rl.rdb.Get(), policy)
}

func (rl *TensorDriftService) DeletePolicy(ctx context.Context, policyID int64) (model.DriftPolicy, error) {
	return dal.DeleteDriftPolicy(ctx, rl.rdb.Get(), policyID)
}

func (rl *TensorDriftService) UpdatePolicy(ctx context.Context, policy model.DriftPolicyUpdate) (model.DriftPolicy, error) {
	return dal.UpdateDriftPolicy(ctx, rl.rdb.Get(), policy)
}

func (rl *TensorDriftService) ListPolicy(ctx context.Context, limit int, offset int, clusterKey string, resourceType []string, enable []string, mode []string, search string) ([]model.DriftPolicy, int64, error) {
	return dal.ListDriftPolicy(ctx, rl.rdb.GetReadDB(), limit, offset, clusterKey, resourceType, enable, mode, search)
}

func (rl *TensorDriftService) GetPolicyByID(ctx context.Context, id int64) (model.DriftPolicy, error) {
	return dal.GetPolicyByID(ctx, rl.rdb.GetReadDB(), id)
}

func (rl *TensorDriftService) GetAllPolicies(ctx context.Context) ([]model.DriftPolicy, error) {
	return dal.GetAllPolicies(ctx, rl.rdb.GetReadDB())
}

func (rl *TensorDriftService) PolicyDetail(ctx context.Context, policy model.DriftPolicy, limit int, offset int) ([]model.TensorContainer, error) {
	return dal.PolicyDetail(ctx, rl.rdb.GetReadDB(), policy, limit, offset)
}

func (rl *TensorDriftService) GetImageID(ctx context.Context, ids uint32) ([]int64, error) {
	return dal.GetImageID(ctx, rl.rdb.GetReadDB(), ids)
}

func (rl *TensorDriftService) GetContainerByID(ctx context.Context, id uint32) (model.TensorContainer, error) {
	return dal.GetContainerByID(ctx, rl.rdb.GetReadDB(), id)
}

func (rl *TensorDriftService) GetAbnormal(ctx context.Context, policy model.DriftPolicy, limit int, offset string, containerName string, filePath string) ([]*palace.Signal, error) {
	esCli, err := GetDriftES(ctx)
	if err != nil {
		return nil, err
	}

	boolQuery := es.NewBoolQuery()
	boolQuery.Filter(
		es.NewTermQuery("ruleKey.category.keyword", "DriftPrevention"),
		es.NewTermQuery("scope.cluster.id", policy.ClusterKey),
		es.NewTermQuery("scope.namespace.name.keyword", policy.Namespace),
		es.NewTermQuery("scope.resource.name.keyword", fmt.Sprintf("%s(%s)", policy.Resource, policy.ResourceKind)),
	)

	if containerName != "" {
		boolQuery.Filter(es.NewMatchPhraseQuery("scope.container.name", containerName).Slop(0))
	} else {
		logging.GetLogger().Error().Msg("containerName is empty")
	}
	if filePath != "" {
		boolQuery.Filter(es.NewMatchPhraseQuery("context.filePath", filePath).Slop(0))
	} else {
		logging.GetLogger().Error().Msg("filePath is empty")
	}

	// debug
	src, _ := boolQuery.Source()
	logging.GetLogger().Debug().Interface("source", src).Msg("filter condition")

	var result = make([]*palace.Signal, 0)
	searchResult, err := esCli.Search("signals_*").Query(boolQuery).
		Sort("createdAt", true).Sort("_id", true).
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

func parseSignal(item *es.SearchHit) (*palace.Signal, error) {
	var signal palace.Signal
	var err = json.Unmarshal(item.Source, &signal)
	if err != nil {
		return nil, err
	}

	return &signal, nil
}
