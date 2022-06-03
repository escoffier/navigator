package drift

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	Es "github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
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

func GetDriftES(ctx context.Context) (*Es.Client, error) {
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

func (rl *TensorDriftService) DeletePolicy(ctx context.Context, policyID int64) error {
	return dal.DeleteDriftPolicy(ctx, rl.rdb.Get(), policyID)
}

func (rl *TensorDriftService) UpdatePolicy(ctx context.Context, policy model.DriftPolicyUpdate) error {
	return dal.UpdateDriftPolicy(ctx, rl.rdb.Get(), policy)
}

func (rl *TensorDriftService) ListPolicy(ctx context.Context, limit int, offset int, clusterKey string, resourceType []string, enable []string, mode []string, search string) ([]model.DriftPolicy, error) {
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

func (rl *TensorDriftService) GetSignalByID(ctx context.Context, esCli *Es.Client, id string) (*model.Signal, error) {
	rsp, err := esCli.Search().Index(fmt.Sprintf("%s*", "signal")).
		Query(Es.NewTermQuery("_id", id)).Do(ctx)
	if err != nil {
		return nil, err
	}

	if len(rsp.Hits.Hits) != 1 {
		return nil, ErrESDocumentNotFound
	}

	return parseSignal(rsp.Hits.Hits[0])
}

func (rl *TensorDriftService) GetAbnormal(ctx context.Context, policy model.DriftPolicy, limit int, offset string, containerName string, filePath string) ([]*model.Signal, error) {
	esCli, err := GetDriftES(ctx)
	if err != nil {
		return nil, err
	}
	searchService := esCli.Search(fmt.Sprintf("%s*", "signal")).
		Sort("timestamp", true).Sort("_id", true).Size(limit)
	var queries []Es.Query
	filter := make(map[string]string)
	filter["ruleModule"] = "ContainerSecurity"
	filter["ruleCategory"] = "DriftPrevention"
	filter["namespace.keyword"] = policy.Namespace
	filter["cluster.keyword"] = policy.ClusterKey
	filter["nodeKey.keyword"] = policy.Resource
	filter["nodeType.keyword"] = policy.ResourceKind
	if containerName != "" {
		termKeyQuery := Es.NewMatchQuery("customKV.KVHash.en.Key.keyword", "containerName")
		termValueQuery := Es.NewMatchQuery("customKV.KVHash.en.Value.keyword", containerName)
		queries = append(queries, termKeyQuery)
		queries = append(queries, termValueQuery)
	} else {
		logging.GetLogger().Error().Msg("containerName is empty")
	}
	if filePath != "" {
		termKeyQuery := Es.NewMatchQuery("customKV.KVHash.en.Key.keyword", "filePath")
		termValueQuery := Es.NewWildcardQuery("customKV.KVHash.en.Value.keyword", "*"+filePath+"*")
		queries = append(queries, termKeyQuery)
		queries = append(queries, termValueQuery)
	} else {
		logging.GetLogger().Error().Msg("filePath is empty")
	}
	for k, v := range filter {
		if k != "" && v != "" {
			queries = append(queries, Es.NewMatchQuery(k, v))
		}
	}
	if len(queries) > 0 {
		searchService = searchService.Query(Es.NewBoolQuery().Must(queries...))
	}
	if offset != "" {
		signal, err := rl.GetSignalByID(ctx, esCli, offset)
		if err == nil {
			searchService = searchService.SearchAfter(signal.Timestamp, signal.ID)
		} else if err != ErrESDocumentNotFound {
			return nil, err
		}
	}
	searchResult, err := searchService.Do(ctx)
	if err != nil {
		return nil, err
	}
	var result = make([]*model.Signal, 0, len(searchResult.Hits.Hits))
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

func parseSignal(item *Es.SearchHit) (*model.Signal, error) {
	var signal model.Signal
	var err = json.Unmarshal(item.Source, &signal)
	if err != nil {
		return nil, err
	}

	signal.ID = item.Id
	return &signal, nil
}
