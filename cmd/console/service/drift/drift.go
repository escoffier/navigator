package drift

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	es "github.com/olivere/elastic/v7"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	EScli                 *elastic.ESClient
	instance              *TensorDriftService
	rlOnce                sync.Once
	ErrESDocumentNotFound = errors.New("es document not found")
)

const (
	policyConfigMapSize    = 5e3
	whitelistConfigMapSize = 5e3
)

func InitDriftService(rdb *databases.RDBInstance, es *elastic.ESClient, mqReader mq.Reader) error {
	rlOnce.Do(func() {
		EScli = es
		instance = newDriftService(rdb, es)
		err := mqReader.Subscribe(
			model.SubjectOfDriftWhiteListEvent,
			"drift image whitelist",
			handleDriftWhitelistEvent,
		)
		if err != nil {
			logging.Get().Err(err).Msg("subscribe drift image whitelist event error")
		}
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

	configMapLock sync.Mutex

	policiesPtr  *atomic.Pointer[model.PoliciesData]
	whitelistPtr *atomic.Pointer[model.WhitelistData]
}

func (rl *TensorDriftService) getVersionOfKey(ctx context.Context, db *gorm.DB, key string) (int64, error) {
	config, err := dal.GetConfig(ctx, db, key)
	if err != nil {
		return 0, err
	}
	version, err := strconv.ParseInt(string(config.Config), 10, 64)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func getVersionFromPolicies(policies []model.DriftPolicy) int64 {
	version := int64(0)
	for _, p := range policies {
		stamp := p.UpdatedAt.UnixMilli()
		if stamp > version {
			version = stamp
		}
	}
	return version
}
func getVersionFromWhitelist(list []model.DriftGlobalWhitelistItem) int64 {
	version := int64(0)
	for _, p := range list {
		if p.UpdatedAt > version {
			version = p.UpdatedAt
		}
	}
	return version
}

func updateImageWhitelist(ctx context.Context, db *gorm.DB, data model.DriftImageWhitelistKafka) error {

	var insertData []model.DriftImageWhitelist
	for _, v := range data.Whitelists {
		insertData = append(insertData, model.DriftImageWhitelist{
			ImageID:  data.ImageID,
			RepoTag:  data.RepoTags[0],
			Filepath: v.FileName,
			CheckSum: v.Checksum,
		})
	}

	err := dal.InsertImageWhitelist(ctx, db, insertData)
	if err != nil {
		logging.Get().Err(err).Msg("update image whitelist error")
		return err
	}
	return nil
}

func handleDriftWhitelistEvent(ctx context.Context, m kafka.Message) error {
	var data model.DriftImageWhitelistKafka
	err := json.Unmarshal(m.Value, &data)
	if err != nil {
		logging.Get().Err(err).Msg("json decode fail")
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	logging.Get().Info().Str("receive msg:", fmt.Sprintf("%+v", data)).Msg("handleDriftWhitelistEvent")
	err = updateImageWhitelist(ctx, instance.rdb.Get(), data)
	if err != nil {
		logging.Get().Err(err).Msg("update fail")
	}
	return err
}

func (rl *TensorDriftService) loadPolicies() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var policies []model.DriftPolicy
	var version int64
	versionNotSet := false
	terr := rl.rdb.GetReadDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		policies, err = dal.GetAllPolicies(ctx, tx)
		if err != nil {
			logging.Get().Err(err).Msg("load drift policies error")
			return err
		}
		version, err = rl.getVersionOfKey(ctx, tx, model.ConfDriftPoliciesVersionKey)
		if err == gorm.ErrRecordNotFound {
			versionNotSet = true
			return nil
		}
		if err != nil {
			logging.Get().Err(err).Msg("load drift policies version error")
			return err
		}
		return nil
	})
	setPtr := false
	if terr != nil {
		logging.Get().Err(terr).Msg("load drift policies error")
		// set the error message if it's the first loading situation. Don't set when it has value set, which means it will return the previous result if errored and not first time.
		setPtr = rl.policiesPtr.CompareAndSwap(nil, &model.PoliciesData{
			Err: terr,
		})
	}
	if !setPtr { // if it hasn't set the cache
		if versionNotSet {
			version = getVersionFromPolicies(policies)
		}

		rl.policiesPtr.Store(&model.PoliciesData{
			Policies:     policies,
			VersionStamp: version,
		})
	}

}

func (rl *TensorDriftService) loadWhiteList() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wlist []model.DriftGlobalWhitelistItem
	var version int64
	var versionNotSet bool
	terr := rl.rdb.GetReadDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		wlist, err = dal.GetAllDriftGlobalWhiteList(ctx, tx)
		if err != nil {
			logging.Get().Err(err).Msg("load drift whitelist error")
			return err
		}
		version, err = rl.getVersionOfKey(ctx, tx, model.ConfDriftWhitelistVersionKey)
		if err == gorm.ErrRecordNotFound {
			versionNotSet = true
			return nil
		}
		if err != nil {
			logging.Get().Err(err).Msg("load drift whitelist version error")
			return err
		}
		return nil
	})

	setPtr := false
	if terr != nil {
		logging.Get().Err(terr).Msg("load drift policies error")
		// set the error message if it's the first loading situation. Don't set when it has value set, which means it will return the previous result if errored and not first time.
		setPtr = rl.whitelistPtr.CompareAndSwap(nil, &model.WhitelistData{
			Err: terr,
		})
	}
	if !setPtr {
		if versionNotSet {
			version = getVersionFromWhitelist(wlist)
		}

		rl.whitelistPtr.Store(&model.WhitelistData{
			Whitelist:    wlist,
			VersionStamp: version,
		})
	}

}

func (rl *TensorDriftService) asyncLoop() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			rl.loadPolicies()
			rl.loadWhiteList()
		}
	}()

}

func newDriftService(rdb *databases.RDBInstance, es *elastic.ESClient) *TensorDriftService {
	s := &TensorDriftService{
		rdb:          rdb,
		es:           es,
		policiesPtr:  new(atomic.Pointer[model.PoliciesData]),
		whitelistPtr: new(atomic.Pointer[model.WhitelistData]),
	}
	s.loadPolicies()
	s.loadWhiteList()
	s.asyncLoop()
	return s
}

func (tl *TensorDriftService) Start() error {

	tl.initConfigMap()
	return nil
}

func (rl *TensorDriftService) CreateGlobalWhitelist(ctx context.Context, whitelist model.DriftGlobalWhitelistItem) (uint64, error) {
	id, err := dal.CreateDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelist)
	if err != nil {
		return 0, err
	}
	createItem := model.DriftGlobalWhitelistItem{
		ID:        id,
		Path:      whitelist.Path,
		ExpireAt:  whitelist.ExpireAt,
		IsForever: whitelist.IsForever,
	}
	err = rl.whitelistConfigMapUpdate(ctx, model.WhitelistData{
		Whitelist: []model.DriftGlobalWhitelistItem{createItem},
	})
	if err != nil {
		logging.Get().Err(err).Msg("update whitelist config map error")
	}
	return id, err
}

func (rl *TensorDriftService) UpdateGlobalWhitelist(ctx context.Context, whitelist model.DriftGlobalWhitelistItem) (model.DriftGlobalWhitelistItem, error) {
	updateWhitelist, err := dal.UpdateDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelist)
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	err = rl.whitelistConfigMapUpdate(ctx, model.WhitelistData{
		Whitelist: []model.DriftGlobalWhitelistItem{updateWhitelist},
	})
	if err != nil {
		logging.Get().Err(err).Msg("update whitelist config map error")
	}
	return updateWhitelist, err
}
func (rl *TensorDriftService) DelGlobalWhitelist(ctx context.Context, whitelistID uint64) (model.DriftGlobalWhitelistItem, error) {
	deleteWhitelist, err := dal.DelDriftGlobalWhiteList(ctx, rl.rdb.Get(), whitelistID)
	if err != nil {
		return model.DriftGlobalWhitelistItem{}, err
	}
	err = rl.whitelistConfigMapDelete(ctx, model.WhitelistData{
		Whitelist: []model.DriftGlobalWhitelistItem{deleteWhitelist},
	})
	if err != nil {
		logging.Get().Err(err).Msg("update whitelist config map error")
	}
	return deleteWhitelist, err
}

func (rl *TensorDriftService) ListGlobalWhitelist(ctx context.Context, limit, offset int, path, searchStr string, startTime, endTime int64) ([]model.DriftGlobalWhitelistItem, int64, error) {
	return dal.ListDriftGlobalWhiteList(ctx, rl.rdb.GetReadDB(), limit, offset, path, searchStr, startTime, endTime)
}

func (rl *TensorDriftService) GetGlobalWhitelistById(ctx context.Context, id uint64) (model.DriftGlobalWhitelistItem, error) {
	return dal.GetDriftGlobalWhiteListById(ctx, rl.rdb.GetReadDB(), id)
}

func (rl *TensorDriftService) GetAllGlobalWhitelist(ctx context.Context) (model.WhitelistData, error) {
	val := rl.whitelistPtr.Load()
	if val == nil {
		logging.Get().Warn().Msg("drift whitelist isn't set")
		rl.loadWhiteList()
		val = rl.whitelistPtr.Load()
		if val == nil {
			logging.Get().Warn().Msg("drift whitelist isn't set")
			return model.WhitelistData{}, errors.New("drift whitelist isn't set")
		}
	}

	if val.Err != nil {
		return model.WhitelistData{}, val.Err
	}

	// must fork data
	forked := *val
	return forked, nil
}

func (rl *TensorDriftService) CreatePolicies(ctx context.Context, policies []model.DriftPolicy) ([]model.DriftPolicy, error) {
	insertPolicies, err := dal.CreateDriftPolicies(ctx, rl.rdb.Get(), policies)
	if err != nil {
		return nil, err
	}
	err = rl.driftConfigMapUpdate(ctx, model.PoliciesData{
		Policies: insertPolicies,
	})
	if err != nil {
		return nil, err
	}
	return insertPolicies, nil
}

func (rl *TensorDriftService) CreatePolicy(ctx context.Context, policy model.DriftPolicy) (int64, error) {
	return dal.CreateDriftPolicy(ctx, rl.rdb.Get(), policy)
}

var (
	ErrPolicyEnabledCannotDelete = errors.New("cannot delete an enabled policy")
)

func (rl *TensorDriftService) DeletePolicy(ctx context.Context, policyID int64) (model.DriftPolicy, error) {
	policy, err := dal.GetPolicyByID(ctx, rl.rdb.Get(), policyID)
	// resource status
	resourceIsReady := true
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		logging.Get().Error().Msg("get assets service fail")
	} else {
		query := dal.ResourcesQuery()
		query = query.WithCluster(policy.ClusterKey)
		query = query.WithNamespace(policy.Namespace)
		query = query.WithResourceKind(assetsPkg.ResourceKind(policy.ResourceKind))
		query = query.WithResourceName(policy.Resource)

		resources, resCnt, err := resSvc.GetResources(ctx, query, 0, 1)
		if err != nil || resCnt == 0 || len(resources) == 0 || resources[0].Status != 0 || resources[0].ScannerStatus != 2 {
			resourceIsReady = false
		}
	}

	if err == nil && policy.Enable == 1 && resourceIsReady {
		return policy, ErrPolicyEnabledCannotDelete
	} else if err == gorm.ErrRecordNotFound {
		return model.DriftPolicy{}, err
	} else if err != nil {
		logging.Get().Warn().Int64("policyID", policyID).Msg("error get policy")
		return model.DriftPolicy{}, err
	}

	err = dal.DeleteDriftPolicy(ctx, rl.rdb.Get(), policyID)
	if err != nil {
		logging.Get().Err(err).Int64("policyID", policyID).Msg("failed to delete policy")
		return policy, err
	}
	err = rl.driftConfigMapDelete(ctx, model.PoliciesData{
		Policies: []model.DriftPolicy{policy},
	})
	if err != nil {
		logging.Get().Err(err).Int64("policyID", policyID).Msg("failed to delete policy from configmap")
	}

	return policy, nil
}

func (rl *TensorDriftService) UpdatePolicy(ctx context.Context, policy model.DriftPolicyUpdate) (model.DriftPolicy, error) {
	oldPolicy, err := dal.UpdateDriftPolicy(ctx, rl.rdb.Get(), policy)
	if err != nil {
		return oldPolicy, err
	}
	updatePolicy := oldPolicy
	updatePolicy.Enable = policy.Enable
	updatePolicy.Mode = policy.Mode

	err = rl.driftConfigMapUpdate(ctx, model.PoliciesData{
		Policies: []model.DriftPolicy{updatePolicy},
	})
	if err != nil {
		logging.Get().Err(err).Int64("policyID", policy.PolicyID).Msg("failed to update policy from configmap")
	}
	return oldPolicy, nil
}

func (rl *TensorDriftService) UpdatePolicies(ctx context.Context, policies []model.DriftPolicyUpdate) ([]model.DriftPolicy, []error) {
	updatePolicies, errs := dal.UpdateDriftPolicies(ctx, rl.rdb.Get(), policies)
	err := rl.driftConfigMapUpdate(ctx, model.PoliciesData{
		Policies: updatePolicies,
	})
	if err != nil {
		errs = append(errs, err)
	}
	return updatePolicies, errs
}

func (rl *TensorDriftService) ListPolicy(ctx context.Context, limit int, offset int, clusterKey string, resourceType, namespaces, enable, mode []string, search string) ([]model.DriftPolicy, int64, error) {
	return dal.ListDriftPolicy(ctx, rl.rdb.GetReadDB(), limit, offset, clusterKey, resourceType, namespaces, enable, mode, search)
}

func (rl *TensorDriftService) GetPoliciesCount(ctx context.Context, clusterKey string) (int64, error) {
	return dal.GetDriftPoliciesCount(ctx, rl.rdb.GetReadDB(), clusterKey)
}

func (rl *TensorDriftService) GetSupportResources(ctx context.Context, clusterKey string) ([]model.TensorResource, error) {
	return dal.GetDriftSupportResources(ctx, rl.rdb.GetReadDB(), clusterKey)
}

func (rl *TensorDriftService) GetPolicyByID(ctx context.Context, id int64) (model.DriftPolicy, error) {
	return dal.GetPolicyByID(ctx, rl.rdb.GetReadDB(), id)
}

// GetAllPolicies will return all the policies of the given cluster or all if given empty
func (rl *TensorDriftService) GetAllPolicies(ctx context.Context, clusterKey string) (model.PoliciesData, error) {
	val := rl.policiesPtr.Load()
	if val == nil {
		logging.Get().Warn().Msg("drift policies isn't set")
		rl.loadPolicies()
		val = rl.policiesPtr.Load()
		if val == nil {
			logging.Get().Warn().Msg("drift policies isn't set")
			return model.PoliciesData{}, nil
		}
	}
	if val.Err != nil {
		return model.PoliciesData{}, val.Err
	}
	clusterFiltered := make([]model.DriftPolicy, 0, len(val.Policies))
	for i := range val.Policies {
		if clusterKey == "" || val.Policies[i].ClusterKey == clusterKey {
			clusterFiltered = append(clusterFiltered, val.Policies[i])
		}
	}
	return model.PoliciesData{Policies: clusterFiltered, VersionStamp: val.VersionStamp}, nil
}

func (rl *TensorDriftService) GetAllPoliciesFromDB(ctx context.Context, clusterKey string) ([]model.DriftPolicy, error) {
	if clusterKey == "" {
		return dal.GetAllPolicies(ctx, rl.rdb.GetReadDB())
	}
	return dal.GetAllPoliciesByClusterKey(ctx, rl.rdb.GetReadDB(), clusterKey)
}

func (rl *TensorDriftService) GetRawContainers(ctx context.Context, policy model.DriftPolicy) ([]model.TensorRawContainer, error) {
	return dal.RawContainers(ctx, rl.rdb.GetReadDB(), policy)
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

	// TODO: 应该不直接查询es，调用sherlockAPI
	searchResult, err := esCli.Search("signals,signals-*,signals_*").Query(boolQuery).
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

func (rl *TensorDriftService) GetDefaultWhitelist(ctx context.Context, offset, limit int, tags []string, searchStr string) ([]model.DriftImageWhitelist, int64, error) {
	return dal.GetDefaultWhitelistByImageTags(ctx, rl.rdb.GetReadDB(), offset, limit, tags, searchStr)
}

func (rl *TensorDriftService) driftConfigMapUpdate(ctx context.Context, policyData model.PoliciesData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	logging.Get().Debug().Interface("policyData", policyData).Msg("update drift config map")

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}

	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()
	updateMap := make(map[string]string)
	for _, policy := range policyData.Policies {
		updateMap[fmt.Sprintf(model.PolicyConfigMapKeyTemplate, policy.ID)] = fmt.Sprintf(model.PolicyConfigMapValueTemplate, policy.ClusterKey, policy.Namespace, policy.ResourceKind, policy.Resource, policy.Enable, policy.Mode)
	}
	if len(updateMap) > policyConfigMapSize {
		return errors.New("policy config map size is too large")
	}

	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {

		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.PoliciesConfigMapName, metav1.GetOptions{})
		if err != nil || currentConfigMap == nil {
			logging.Get().Warn().Msg("get drift config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.PoliciesConfigMapName,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.DriftConfigMapLabel, "=")[0]: strings.Split(model.DriftConfigMapLabel, "=")[1],
					},
				},
				Data: updateMap,
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create drift config map error")
				return false
			}

		} else {
			if len(currentConfigMap.Data)+len(updateMap) > policyConfigMapSize {
				// return errors.New("policy config map size is too large")
				logging.Get().Warn().Msg("policy config map size is too large")
				return false
			}
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string, len(updateMap))
			}
			for key, value := range updateMap {
				currentConfigMap.Data[key] = value
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update drift config map error")
				return false
			}
		}
		return true
	})

	return nil
}

func (rl *TensorDriftService) driftConfigMapDelete(ctx context.Context, policyData model.PoliciesData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	logging.Get().Debug().Interface("policyData", policyData).Msg("delete drift config map")
	deleteKeys := make([]string, 0, len(policyData.Policies))
	for _, policy := range policyData.Policies {
		deleteKeys = append(deleteKeys, fmt.Sprintf(model.PolicyConfigMapKeyTemplate, policy.ID))
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()

	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {

		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.PoliciesConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.Get().Warn().Msg("get drift config map error")
			return false
		}

		for _, key := range deleteKeys {
			if _, ok := currentConfigMap.Data[key]; ok {
				delete(currentConfigMap.Data, key)
				_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
				if err != nil {
					logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update drift config map error")
					return false
				}
			} else {
				logging.Get().Warn().Str("key", key).Msg("delete drift config map key not exist")
			}
		}
		return true
	})

	return nil
}

func (rl *TensorDriftService) driftConfigMapReset(ctx context.Context, policyData model.PoliciesData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()
	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		// delete drift config map
		err := client.CoreV1().ConfigMaps(namespace).Delete(ctx, model.PoliciesConfigMapName, metav1.DeleteOptions{})
		if err != nil {
			logging.Get().Warn().Msgf("delete drift config map error %v", err)
		}

		addMap := make(map[string]string)
		for _, policy := range policyData.Policies {
			addMap[fmt.Sprintf(model.PolicyConfigMapKeyTemplate, policy.ID)] = fmt.Sprintf(model.PolicyConfigMapValueTemplate, policy.ClusterKey, policy.Namespace, policy.ResourceKind, policy.Resource, policy.Enable, policy.Mode)
		}
		if len(addMap) > policyConfigMapSize {
			logging.Get().Warn().Msg("policy config map size is too large")
			return false
		}

		// create drift config map
		configmap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      model.PoliciesConfigMapName,
				Namespace: namespace,
				Labels: map[string]string{
					strings.Split(model.DriftConfigMapLabel, "=")[0]: strings.Split(model.DriftConfigMapLabel, "=")[1],
				},
			},
			Data: addMap,
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
		if err != nil {
			logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create drift config map error")
			return false
		}
		return true
	})
	return nil
}

func (rl *TensorDriftService) whitelistConfigMapUpdate(ctx context.Context, whitelistData model.WhitelistData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	logging.Get().Debug().Interface("whitelistData", whitelistData).Msg("update whitelist config map")

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()

	updateMap := make(map[string]string)
	for _, whitelist := range whitelistData.Whitelist {
		updateMap[fmt.Sprintf(model.WhitelistConfigMapKeyTemplate, whitelist.ID)] = fmt.Sprintf(model.WhitelistConfigMapValueTemplate,
			whitelist.Path, whitelist.ExpireAt, whitelist.IsForever)
	}

	if len(updateMap) > whitelistConfigMapSize {
		return errors.New("whitelist config map size is too large")
	}

	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.WhitelistConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.Get().Warn().Msg("get whitelist config map error")
			configmap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      model.WhitelistConfigMapName,
					Namespace: namespace,
					Labels: map[string]string{
						strings.Split(model.DriftConfigMapLabel, "=")[0]: strings.Split(model.DriftConfigMapLabel, "=")[1],
					},
				},
				Data: updateMap,
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
			if err != nil {
				logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create whitelist config map error")
				return false
			}

		} else {
			if len(currentConfigMap.Data)+len(updateMap) > whitelistConfigMapSize {
				logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update whitelist config map error")
				return false
			}
			if currentConfigMap.Data == nil {
				currentConfigMap.Data = make(map[string]string, len(updateMap))
			}
			for key, value := range updateMap {
				currentConfigMap.Data[key] = value
			}
			_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
			if err != nil {
				logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update whitelist config map error")
				return false
			}
		}
		return true
	})

	return nil
}

func (rl *TensorDriftService) whitelistConfigMapDelete(ctx context.Context, whitelistData model.WhitelistData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	logging.Get().Debug().Interface("whitelistData", whitelistData).Msg("delete whitelist config map")

	deleteKeys := make([]string, len(whitelistData.Whitelist))
	for _, whitelist := range whitelistData.Whitelist {
		deleteKeys = append(deleteKeys, fmt.Sprintf(model.WhitelistConfigMapKeyTemplate, whitelist.ID))
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// cli := clusterManager.HostClient
	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()

	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		currentConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, model.WhitelistConfigMapName, metav1.GetOptions{})
		if err != nil {
			logging.Get().Warn().Msg("get whitelist config map error")
			return false
		}

		for _, key := range deleteKeys {
			if _, ok := currentConfigMap.Data[key]; ok {
				delete(currentConfigMap.Data, key)
				_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, currentConfigMap, metav1.UpdateOptions{})
				if err != nil {
					logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", currentConfigMap)).Msg("update whitelist config map error")
					return false
				}
			} else {
				logging.Get().Warn().Str("key", key).Msg("delete whitelist config map key not exist")
			}
		}
		return true
	})
	return nil
}

func (rl *TensorDriftService) whitelistConfigMapReset(ctx context.Context, whitelistData model.WhitelistData) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return errors.New("get cluster manager error")
	}
	// cli := clusterManager.HostClient
	// lock drift-config configmap
	rl.configMapLock.Lock()
	defer rl.configMapLock.Unlock()

	clusterManager.TraverseClient(func(key string, client *assetsPkg.Clientset) bool {
		// delete drift config map
		err := client.CoreV1().ConfigMaps(namespace).Delete(ctx, model.WhitelistConfigMapName, metav1.DeleteOptions{})
		if err != nil {
			logging.Get().Warn().Msgf("delete whitelist config map error %v", err)
		}

		updateMap := make(map[string]string)
		for _, whitelist := range whitelistData.Whitelist {
			updateMap[fmt.Sprintf(model.WhitelistConfigMapKeyTemplate, whitelist.ID)] = fmt.Sprintf(model.WhitelistConfigMapValueTemplate,
				whitelist.Path, whitelist.ExpireAt, whitelist.IsForever)
		}
		if len(updateMap) > whitelistConfigMapSize {
			logging.Get().Err(err).Msg("whitelist config map size is too large")
			return false
		}

		// create drift config map
		configmap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      model.WhitelistConfigMapName,
				Namespace: namespace,
				Labels: map[string]string{
					strings.Split(model.DriftConfigMapLabel, "=")[0]: strings.Split(model.DriftConfigMapLabel, "=")[1],
				},
			},
			Data: updateMap,
		}
		_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, configmap, metav1.CreateOptions{})
		if err != nil {
			logging.Get().Err(err).Str("cm:", fmt.Sprintf("%+v", configmap)).Msg("create whitelist config map error")
			return false
		}
		return true
	})
	return nil
}

func (rl *TensorDriftService) initConfigMap() {
	policyData, err := rl.GetAllPolicies(context.Background(), "")
	if err != nil {
		logging.Get().Err(err).Msg("get all policies error")
	}

	err = rl.driftConfigMapReset(context.Background(), policyData)
	if err != nil {
		logging.Get().Err(err).Msg("drift config map reset error")
	}

	whitelistData, err := rl.GetAllGlobalWhitelist(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("get all whitelists error")
	}

	err = rl.whitelistConfigMapReset(context.Background(), whitelistData)
	if err != nil {
		logging.Get().Err(err).Msg("whitelist config map reset error")
	}
}
