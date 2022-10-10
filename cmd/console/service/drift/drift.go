package drift

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	es "github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
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
		instance = newDriftService(rdb, es)
	})
	return nil
}

func GetDriftES(ctx context.Context) (*es.Client, error) {
	return EScli.Get()
}

func GetDriftService(_ context.Context) (*TensorDriftService, bool) {
	return instance, instance != nil
}

type TensorDriftService struct {
	rdb *databases.RDBInstance
	es  *elastic.ESClient

	policiesVal  *atomic.Value
	whiteListVal *atomic.Value
}

func (rl *TensorDriftService) loadPolicies() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()

	policies, err := dal.GetAllPolicies(context.Background(), rl.rdb.GetReadDB())
	if err != nil {
		logging.Get().Err(err).Msg("load drift policies error")
		return
	}
	rl.policiesVal.Store(policies)
}

func (rl *TensorDriftService) loadWhiteList() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()

	wlist, err := dal.GetAllDriftGlobalWhiteList(context.Background(), rl.rdb.GetReadDB())
	if err != nil {
		logging.Get().Err(err).Msg("load drift policies error")
		return
	}

	rl.whiteListVal.Store(wlist)
}

func (rl *TensorDriftService) asyncLoop() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for _ = range ticker.C {
			rl.loadPolicies()
			rl.loadWhiteList()
		}
	}()

}

func newDriftService(rdb *databases.RDBInstance, es *elastic.ESClient) *TensorDriftService {
	s := &TensorDriftService{
		rdb:          rdb,
		es:           es,
		policiesVal:  new(atomic.Value),
		whiteListVal: new(atomic.Value),
	}
	s.loadPolicies()
	s.loadWhiteList()
	s.asyncLoop()
	return s
}

func (rl *TensorDriftService) CreateGlobalWhitelist(ctx context.Context, whitelist model.DriftGlobalWhitelistItem) (int64, error) {
	return dal.CreateDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelist)
}

func (rl *TensorDriftService) UpdateGlobalWhitelist(ctx context.Context, whitelist model.DriftGlobalWhitelistItem) (model.DriftGlobalWhitelistItem, error) {
	return dal.UpdateDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelist)
}
func (rl *TensorDriftService) DelGlobalWhitelist(ctx context.Context, whitelistID int64) (model.DriftGlobalWhitelistItem, error) {
	return dal.DelDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelistID)
}

func (rl *TensorDriftService) ListGlobalWhitelist(ctx context.Context, limit, offset int, path, searchStr string, startTime, endTime int64) ([]model.DriftGlobalWhitelistItem, int64, error) {
	return dal.ListDriftGlobalWhiteList(ctx, rl.rdb.GetReadDB(), limit, offset, path, searchStr, startTime, endTime)
}

func (rl *TensorDriftService) GetGlobalWhitelistById(ctx context.Context, id int64) (model.DriftGlobalWhitelistItem, error) {
	return dal.GetDriftGlobalWhiteListById(ctx, rl.rdb.GetReadDB(), id)
}

func (rl *TensorDriftService) GetAllGlobalWhitelist(ctx context.Context) ([]model.DriftGlobalWhitelistItem, error) {
	val := rl.whiteListVal.Load()
	if val == nil {
		logging.Get().Warn().Msg("drift whitelist isn't set")
		rl.loadWhiteList()
		val = rl.whiteListVal.Load()
		if val == nil {
			logging.Get().Warn().Msg("drift whitelist isn't set")
			return nil, nil
		}
	}
	whiteList := val.([]model.DriftGlobalWhitelistItem)
	return whiteList, nil
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

func (rl *TensorDriftService) ListPolicy(ctx context.Context, limit int, offset int, clusterKey string, resourceType, namespaces, enable, mode []string, search string) ([]model.DriftPolicy, int64, error) {
	return dal.ListDriftPolicy(ctx, rl.rdb.GetReadDB(), limit, offset, clusterKey, resourceType, namespaces, enable, mode, search)
}

func (rl *TensorDriftService) GetPolicyByID(ctx context.Context, id int64) (model.DriftPolicy, error) {
	return dal.GetPolicyByID(ctx, rl.rdb.GetReadDB(), id)
}

// GetAllPolicies will return all the policies of the given cluster or all if given empty
func (rl *TensorDriftService) GetAllPolicies(ctx context.Context, clusterKey string) ([]model.DriftPolicy, error) {
	val := rl.policiesVal.Load()
	if val == nil {
		logging.Get().Warn().Msg("drift policies isn't set")
		rl.loadPolicies()
		val = rl.policiesVal.Load()
		if val == nil {
			logging.Get().Warn().Msg("drift policies isn't set")
			return nil, nil
		}
	}
	policies := val.([]model.DriftPolicy)
	clusterFiltered := make([]model.DriftPolicy, 0, len(policies))
	for i := range policies {
		if clusterKey == "" || policies[i].ClusterKey == clusterKey {
			clusterFiltered = append(clusterFiltered, policies[i])
		}

	}
	return clusterFiltered, nil
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

func (rl *TensorDriftService) GetAbnormal(ctx context.Context, policy model.DriftPolicy, limit int, containerName string, filePath string) ([]*palace.Signal, error) {
	esCli, err := rl.es.Get()
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
	}
	if filePath != "" {
		boolQuery.Filter(es.NewMatchPhraseQuery("context.filePath", filePath).Slop(0))
	}

	// debug
	src, _ := boolQuery.Source()
	logging.Get().Debug().Interface("source", src).Msg("filter condition")

	var result = make([]*palace.Signal, 0)

	searchResult, err := esCli.Search("signals_*").Query(boolQuery).
		Sort("createdAt", true).Sort("_id", true).
		Size(limit).Do(ctx)
	if err != nil {
		logging.Get().Warn().Err(err).Msg("search es error")
		return result, nil
	}

	for _, item := range searchResult.Hits.Hits {
		signal, err := parseSignal(item)
		if err != nil {
			logging.Get().Err(err).Msgf("parse signal error")
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
