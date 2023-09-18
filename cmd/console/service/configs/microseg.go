package configs

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"os"
	"strconv"
	"strings"

	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/redisearch"
)

type MicroSegOperator struct {
	Aperator string
	rdb      *databases.RDBInstance
}

func (c *MicroSegOperator) GetAperator() string {
	return c.Aperator
}

func (c *MicroSegOperator) SetAperator(username string) {
	c.Aperator = username
}

func NewMicroSegOperator(rdb *databases.RDBInstance) (*MicroSegOperator, error) {
	var err error
	var redisearchClient *redisearch.Client

	if os.Getenv("USE_REDISEARCH") != "false" {
		redisearchClient, err = redisearch.NewClient()
		if err != nil {
			return nil, err
		}
		err = redisearchClient.RegisterClient(context.Background(), "pod", "resource", "rawContainer")
		if err != nil {
			return nil, err
		}

	}

	scannerURL := os.Getenv("SCANNER_URL")
	err = assets.InitResourcesService(rdb, redisearchClient, scannerURL)
	if err != nil {
		logging.Get().Err(err).Msg("ERROR: InitResourcesService init error")
		return nil, err
	}

	return &MicroSegOperator{}, nil
}

func (ms *MicroSegOperator) Export(ctx context.Context) (data []byte, err error) {
	cMicroSeg := ConfigMicroSeg{}

	// cluster_config
	var cluster []*model.TensorCluster
	err = ms.rdb.Get().WithContext(ctx).
		Raw("select * from ivan_assets_clusters").
		Scan(&cluster).Error
	if err != nil {
		return nil, err
	}
	cMicroSeg.ClusterConfig = make(map[string]string)
	for _, val := range cluster {
		cMicroSeg.ClusterConfig[val.Name] = val.Key
	}

	cMicroSeg, err = ms.ExportMicrosegSqlInfo(ctx, cMicroSeg)
	if err != nil {
		return nil, fmt.Errorf("export microseg failed: %w", err)
	}
	// get json data
	jsondata, err := json.Marshal(cMicroSeg)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("couldn't get data ")
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}

	return jsondata, nil
}

func (ms *MicroSegOperator) ExportMicrosegSqlInfo(ctx context.Context, cMicroSeg ConfigMicroSeg) (ConfigMicroSeg, error) {
	// cluster_config
	var cluster []*model.TensorCluster
	err := ms.rdb.Get().WithContext(ctx).
		Raw("select * from ivan_assets_clusters").
		Scan(&cluster).Error
	if err != nil {
		return cMicroSeg, err
	}
	cMicroSeg.ClusterConfig = make(map[string]string)
	for _, val := range cluster {
		cMicroSeg.ClusterConfig[val.Name] = val.Key
	}

	deleteUuidList := make(map[uint32]uint32)

	// export microseg_tenants
	MicrosegTenantsInfo, TenantsStatus, err := ExportMicrosegTenants(ctx, ms.rdb.Get(), cMicroSeg.ClusterConfig, deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !TenantsStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegTenants = MicrosegTenantsInfo

	// export microseg_resources configInfo
	MicrosegResourcesInfo, ResourcesStatus, err := ExportMicrosegResources(ctx, ms.rdb.Get(), cMicroSeg.ClusterConfig, deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !ResourcesStatus {
		cMicroSeg.MicrosegResources = nil
	}
	cMicroSeg.MicrosegResources = MicrosegResourcesInfo

	// export microseg_segments configInfo
	MicrosegSegmentInfo, SegmentStatus, err := ExportMicrosegSegment(ctx, ms.rdb.Get(), cMicroSeg.ClusterConfig, deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !SegmentStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegSegments = MicrosegSegmentInfo

	// export microseg_nsgrps configInfo
	MicrosegNsgrpsInfo, NsgrpsStatus, err := ExportMicrosegNsgrps(ctx, ms.rdb.Get(), cMicroSeg.ClusterConfig, deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !NsgrpsStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegNSGroups = MicrosegNsgrpsInfo

	// export microseg_policies
	MicrosegPoliciesInfo, PoliciesStatus, err := ExportMicrosegPolicies(ctx, ms.rdb.Get(), deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !PoliciesStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegPolicies = MicrosegPoliciesInfo

	// export microseg_rules
	MicrosegRulesInfo, RulesStatus, err := ExportMicrosegRules(ctx, ms.rdb.Get(), deleteUuidList)
	if err != nil {
		return cMicroSeg, err
	}
	if !RulesStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegRules = MicrosegRulesInfo

	// export microseg_logic_clusters
	MicrosegLogicClustersInfo, LogicClustersStatus, err := ExportMicrosegLogicClusters(ctx, ms.rdb.Get(), cMicroSeg.MicrosegTenants)
	if err != nil {
		return cMicroSeg, err
	}
	if !LogicClustersStatus {
		cMicroSeg.MicrosegSegments = nil
	}
	cMicroSeg.MicrosegLogicClusters = MicrosegLogicClustersInfo
	return cMicroSeg, nil
}

type ConfigMicroSeg struct {
	MicrosegLogicClusters []TensorMicrosegLogicCluster `json:"ivan_microseg_logic_clusters"`
	MicrosegNSGroups      []TensorMicrosegNsgrp        `json:"ivan_microseg_nsgrps"`
	MicrosegResources     []TensorMicrosegResource     `json:"ivan_microseg_resources"`
	MicrosegSegments      []TensorMicrosegSegment      `json:"ivan_microseg_segments"`
	MicrosegTenants       []TensorMicrosegTenant       `json:"ivan_microseg_tenants"`
	MicrosegPolicies      []TensorMicrosegPolicy       `json:"ivan_microseg_policies"`
	MicrosegRules         []TensorMicrosegRule         `json:"ivan_microseg_rules"`
	ClusterConfig         map[string]string            `json:"cluster_config"`
}

// microseg_resources
func ExportMicrosegResources(ctx context.Context, db *gorm.DB, ClusterConfig map[string]string, deleteUuidList map[uint32]uint32) ([]TensorMicrosegResource, bool, error) {
	var res []TensorMicrosegResource

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_resources").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrap(err, "failed to list resource of specified cluster")
		}
		return nil, false, nil
	}

	var finalRes []TensorMicrosegResource

	clusters := make(map[string]string) // key : name
	for key, val := range ClusterConfig {
		clusters[val] = key
	}

	for _, val := range res {
		if _, ok := clusters[val.Cluster]; !ok {
			deleteUuidList[val.ID] = val.ID
		} else {
			finalRes = append(finalRes, val)
		}
	}

	return finalRes, true, nil
}

// microseg_segments
func ExportMicrosegSegment(ctx context.Context, db *gorm.DB, ClusterConfig map[string]string, deleteUuidList map[uint32]uint32) ([]TensorMicrosegSegment, bool, error) {
	var res []TensorMicrosegSegment

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_segments").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	var finalRes []TensorMicrosegSegment

	clusters := make(map[string]string) // key : name
	for key, val := range ClusterConfig {
		clusters[val] = key
	}

	for _, val := range res {
		if _, ok := clusters[val.Cluster]; !ok {
			deleteUuidList[val.ID] = val.ID
		} else {
			finalRes = append(finalRes, val)
		}
	}

	return finalRes, true, nil
}

// microseg_nsgrps
func ExportMicrosegNsgrps(ctx context.Context, db *gorm.DB, ClusterConfig map[string]string, deleteUuidList map[uint32]uint32) ([]TensorMicrosegNsgrp, bool, error) {
	var res []TensorMicrosegNsgrp

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_nsgrps").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	var finalRes []TensorMicrosegNsgrp

	clusters := make(map[string]string) // key : name
	for key, val := range ClusterConfig {
		clusters[val] = key
	}

	for _, val := range res {
		if _, ok := clusters[val.Cluster]; !ok {
			deleteUuidList[val.UUID] = val.UUID
		} else {
			finalRes = append(finalRes, val)
		}
	}

	return finalRes, true, nil
}

// microseg_tenants
func ExportMicrosegTenants(ctx context.Context, db *gorm.DB, ClusterConfig map[string]string, deleteUuidList map[uint32]uint32) ([]TensorMicrosegTenant, bool, error) {
	var res []TensorMicrosegTenant

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_tenants").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	var existRes []TensorMicrosegTenant

	clusters := make(map[string]string) // key : name
	for key, val := range ClusterConfig {
		clusters[val] = key
	}

	for _, val := range res {
		if _, ok := clusters[val.Cluster]; !ok {
			deleteUuidList[val.UUID] = val.UUID
		} else {
			existRes = append(existRes, val)
		}
	}

	var finalRes []TensorMicrosegTenant
	for _, val := range existRes {
		var users []model.User
		var accountList []string
		usernameList := strings.Split(val.Users, ",")
		if err := db.WithContext(ctx).Where("username in ?", usernameList).Find(&users).Error; err != nil {
			logging.Get().Error().Err(err).Msg("")
			return nil, false, nil
		}
		for _, user := range users {
			accountList = append(accountList, user.Account)
		}
		val.Users = strings.Join(accountList, ",")
		finalRes = append(finalRes, val)
	}

	return finalRes, true, nil
}

// microseg_policies
func ExportMicrosegPolicies(ctx context.Context, db *gorm.DB, deleteUuidList map[uint32]uint32) ([]TensorMicrosegPolicy, bool, error) {
	var res []TensorMicrosegPolicy
	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_policies").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	var finalRes []TensorMicrosegPolicy

	for _, val := range res {
		uuid, err := strconv.ParseUint(val.Name, 10, 32)
		if err != nil {
			return nil, false, nil
		}

		if _, ok := deleteUuidList[uint32(uuid)]; !ok {
			finalRes = append(finalRes, val)
		}
	}

	return finalRes, true, nil
}

// microseg_rules
func ExportMicrosegRules(ctx context.Context, db *gorm.DB, deleteUuidList map[uint32]uint32) ([]TensorMicrosegRule, bool, error) {
	var res []TensorMicrosegRule

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_rules").
		Scan(&res).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	var finalRes []TensorMicrosegRule
	//
	for _, val := range res {
		uuid, err := strconv.ParseUint(val.Policy, 10, 32)
		if err != nil {
			return nil, false, nil
		}
		if _, ok := deleteUuidList[uint32(uuid)]; ok {
			continue
		}
		if _, ok := deleteUuidList[val.SrcID]; ok {
			continue
		}
		if _, ok := deleteUuidList[val.DstID]; ok {
			continue
		}

		finalRes = append(finalRes, val)
	}
	return finalRes, true, nil
}

// microseg_logic_clusters
func ExportMicrosegLogicClusters(ctx context.Context, db *gorm.DB, Tenants []TensorMicrosegTenant) ([]TensorMicrosegLogicCluster, bool, error) {
	var res []TensorMicrosegLogicCluster

	err := db.WithContext(ctx).
		Raw("select * from ivan_microseg_logic_clusters").
		Scan(&res).Error

	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, false, errors.Wrapf(err, "list segments failed: %v", err)
		}
		return nil, false, nil
	}

	tenantIDList := make(map[string]struct{})
	for _, val := range Tenants {
		tenantIDList[strconv.FormatInt(val.ID, 10)] = struct{}{}
	}

	for _, val := range res {
		oldtenantList := strings.Split(val.Tenants, ",")

		var newtenantList []string
		//
		for _, id := range oldtenantList {
			if _, ok := tenantIDList[id]; ok {
				newtenantList = append(newtenantList, id)
			}
		}
		val.Tenants = strings.Join(newtenantList, ",")
	}

	return res, true, nil
}

func (ms *MicroSegOperator) Import(ctx context.Context, config []byte) error {
	// json unmarshal
	cMicroSeg := &ConfigMicroSeg{}
	err := json.Unmarshal(config, cMicroSeg)
	if err != nil {
		logging.Get().Error().Err(err).Str("config data", string(config)).Msg("invalid config data")
		return err
	}

	// 获取新环境的集群数据
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		err = errors.New("service instance get error")
		logging.Get().Error().Err(err).Msg("service instance get error")
		return err
	}

	query := dal.ClusterQuery()
	newClustersConfig := map[string]string{} // { oldKey: newKey }

	// change cluster id(hashKey)
	for name, oldKey := range cMicroSeg.ClusterConfig {
		if name != "" {
			query.WithName(name)
		}

		clusters, _, err := resSvc.GetClusters(ctx, query, 0, 1)
		if err != nil {
			logging.Get().Err(err).Msg("get cluster error")
			return err
		}

		if len(clusters) != 1 {
			err = errors.New("invalid cluster name: " + name)
			logging.Get().Error().Err(err).Str("name", name).Int("clusters len", len(clusters)).Msg("invalid cluster name")
			return err
		}
		newClustersConfig[oldKey] = clusters[0].Key
	}

	// import
	err, configMic, ClusterMap := ms.selectMicrosegConfig(ctx)
	if err != nil {
		return err
	}
	ResourcePolicy, err := ms.createResourcePolicyList(configMic.MicrosegResources, configMic.MicrosegPolicies)
	if err != nil {
		return err
	}
	// delete
	if err := ms.deleteMicrosegConfig(ctx, ms.rdb.Get(), configMic, ResourcePolicy); err != nil {
		return err
	}

	// import
	createdList, resourcesPolicies, err := ms.ImportMicrosegConfig(ctx, ms.rdb.Get(), cMicroSeg, newClustersConfig)

	if err != nil {
		logging.Get().Error().Err(err).Msgf("import failed")
		// delete
		if deleteErr := ms.deleteMicrosegConfig(ctx, ms.rdb.Get(), createdList, resourcesPolicies); deleteErr != nil {
			logging.Get().Error().Err(deleteErr).Msg("delete import Info failed")
		}
		// rollback
		if _, _, rollBackErr := ms.ImportMicrosegConfig(ctx, ms.rdb.Get(), &configMic, ClusterMap); rollBackErr != nil {
			logging.Get().Error().Err(rollBackErr).Msg("rollback  failed")
		}

		return err
	}

	return nil
}

func (ms *MicroSegOperator) ImportMicrosegConfig(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, newClustersConfig map[string]string) (ConfigMicroSeg, []TensorMicrosegResourcePolicy, error) {
	var createdConfig ConfigMicroSeg
	var resourcesPolicies []TensorMicrosegResourcePolicy
	// 导入 租户
	createdTenantList, newIDConfig, err := ms.ImportMicrosegTenants(ctx, db, cMicroSeg, newClustersConfig)
	if len(createdTenantList) != 0 {
		createdConfig.MicrosegTenants = createdTenantList
	}
	if err != nil {
		return createdConfig, resourcesPolicies, err
	}

	// 导入 逻辑集群
	createdLogicClusters, err := ms.ImportMicrosegLogicClusters(ctx, db, cMicroSeg, newClustersConfig, newIDConfig)
	if len(createdLogicClusters) != 0 {
		createdConfig.MicrosegLogicClusters = createdLogicClusters
	}
	if err != nil {
		return createdConfig, resourcesPolicies, err
	}

	// 导入 命名空间
	createdNamespaces, err := ms.ImportMicrosegNamespaces(ctx, db, cMicroSeg, newClustersConfig)
	if len(createdNamespaces) != 0 {
		createdConfig.MicrosegNSGroups = createdNamespaces
	}
	if err != nil {
		return createdConfig, resourcesPolicies, err
	}

	// 获取 IDmap和newMap
	IDMap, newMap, SegmentResourcesMap := ms.GetMicrosegResourcesInfo(ctx, db, cMicroSeg, newClustersConfig)
	// 导入 资源
	resourcesPolicies, err = ms.ImportMicrosegResources(ctx, db, cMicroSeg, newClustersConfig, IDMap, newMap)
	// todo
	if err != nil {
		return createdConfig, resourcesPolicies, err
	}

	// 导入 资源组
	createdSegments, err := ms.ImportMicrosegSegments(ctx, db, cMicroSeg, newClustersConfig, IDMap, newMap, SegmentResourcesMap)
	if len(createdSegments) != 0 {
		createdConfig.MicrosegSegments = createdSegments
	}
	if err != nil {
		return createdConfig, resourcesPolicies, err
	}

	// end
	return createdConfig, resourcesPolicies, nil
}

// delete mysql data
func (ms *MicroSegOperator) deleteMicrosegConfig(ctx context.Context, db *gorm.DB, Config ConfigMicroSeg, resourcesPolicies []TensorMicrosegResourcePolicy) error {
	// delete microseg_logic_clusters
	err := db.Exec("update ivan_microseg_logic_clusters set tenants=?", "[]").Error
	if err != nil {
		return err
	}
	err = db.Exec("update ivan_microseg_tenants set logic_cluster =?", "-1").Error
	if err != nil {
		return err
	}

	// delete logic_cluster
	if err = ms.DeleteMicrosegLogicClusters(ctx, Config.MicrosegLogicClusters); err != nil {
		return err
	}

	// delete tenants
	if err = ms.DeleteMicrosegTenants(ctx, Config.MicrosegTenants); err != nil {
		return err
	}

	// delete namespace
	if err = ms.DeleteMicrosegNsgrps(ctx, Config.MicrosegNSGroups); err != nil {
		return err
	}

	// 删除 资源组
	if err = ms.deleteMicrosegSegments(ctx, Config.MicrosegSegments); err != nil {
		return err
	}

	// 资源 不需要删除 ,但需要删除资源的所有策略
	if err = ms.deleteMicrosegResourcesPolicies(ctx, resourcesPolicies); err != nil {
		return err
	}

	return nil
}

// select mysql data
func (ms *MicroSegOperator) selectMicrosegConfig(ctx context.Context) (error, ConfigMicroSeg, map[string]string) {
	var Conf ConfigMicroSeg

	Conf, err := ms.ExportMicrosegSqlInfo(ctx, Conf)
	if err != nil {
		return err, Conf, nil
	}
	ClusterMap := make(map[string]string)

	for _, value := range Conf.ClusterConfig {
		ClusterMap[value] = value
	}

	return nil, Conf, ClusterMap
}

// microseg_logic_clusters
func (ms *MicroSegOperator) ImportMicrosegLogicClusters(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClustersConfig map[string]string, newIDConfig map[int64]int64) ([]TensorMicrosegLogicCluster, error) {
	var createdList []TensorMicrosegLogicCluster

	for _, val := range cMicroSeg.MicrosegLogicClusters {
		tenantsStr := strings.ReplaceAll(val.Tenants, "[", "")
		tenantsStr = strings.ReplaceAll(tenantsStr, "]", "")

		tenantList := strings.Split(tenantsStr, ",")
		var tenantListInt []int64
		for _, val := range tenantList {
			num, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return createdList, err
			}
			newID := newIDConfig[num]
			tenantListInt = append(tenantListInt, newID)
		}
		newClusterKey := ClustersConfig[val.Cluster]

		createConfig := CreateLogicClusterRequest{
			Name:    val.Name,
			Nodes:   strings.Split(val.Nodes, ","),
			Tenants: tenantListInt,
		}

		newLogicClusterInfo, err := ms.createMicrosegLogicCluster(createConfig, newClusterKey)
		if err != nil {
			logging.Get().Error().Err(err).Msgf("createLogicCluster failed")
			return createdList, err
		}
		newID := newLogicClusterInfo.ID
		createdList = append(createdList, TensorMicrosegLogicCluster{ID: newID, Cluster: newClusterKey})
	}
	//
	return createdList, nil
}

func (ms *MicroSegOperator) DeleteMicrosegLogicClusters(ctx context.Context, Config []TensorMicrosegLogicCluster) error {
	if len(Config) == 0 {
		logging.Get().Debug().Msgf("microseg_logic_clusters, nothing need to delete")
		return nil
	}

	for _, val := range Config {
		if err := ms.DeleteMicrosegLogicCluster(val.Cluster, val.ID); err != nil {
			return err
		}
	}
	return nil
}

// microseg_tenants
func (ms *MicroSegOperator) ImportMicrosegTenants(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClusterConfig map[string]string) ([]TensorMicrosegTenant, map[int64]int64, error) {
	var createdList []TensorMicrosegTenant      // 导入成功的租户列表
	uuidConfig := make(map[uint32]uint32)       // 新旧uuid的替换
	IDConfig := make(map[int64]int64)           // 新旧ID 的替换
	createdMap := make(map[uint32]SingleTenant) // 内部使用的新增租户查询map  ---map[ newuuid : 结构体 ]

	for _, val := range cMicroSeg.MicrosegTenants {
		oldClusterKey := val.Cluster
		oldID := val.ID
		accountList := strings.Split(val.Users, ",")
		var users []model.User
		var usernameList []string
		if err := db.WithContext(ctx).Where("account in ?", accountList).Find(&users).Error; err != nil {
			logging.Get().Error().Err(err).Msg("")
			return createdList, nil, err // 把已经创建好的租户数据传出用于回滚
		}
		for _, user := range users {
			usernameList = append(usernameList, user.UserName)
		}
		val.Users = strings.Join(usernameList, ",")
		newClusterKey := ClusterConfig[oldClusterKey] // 获取创建结构体所需的新集群key
		createConfig := CreateTenantRequest{
			BaseInfo: TenantBaseInfo{
				ID:         0,
				Name:       val.Name,
				Namespaces: strings.Split(val.Namespaces, ","),
				Users:      usernameList,
			},
		}
		// 将 组合好的结构体 传入转发函数中
		newTenantInfo, err := ms.createMicrosegTenants(createConfig, newClusterKey)
		if err != nil {
			return createdList, nil, err // 把已经创建好的租户数据传出用于回滚
		}
		newTenantInfo.Namespaces = strings.Split(val.Namespaces, ",")
		newTenantInfo.Users = strings.Split(val.Users, ",")

		newUuid, newID := newTenantInfo.UUID, newTenantInfo.ID
		createdList = append(createdList, TensorMicrosegTenant{ID: newID, Cluster: newClusterKey})
		uuidConfig[val.UUID] = newUuid
		IDConfig[oldID] = newID
		createdMap[newUuid] = newTenantInfo
	}

	var enablingTenantPolicy []uint32
	// 租户已经创建完成，开始创建策略和规则
	for _, val := range cMicroSeg.MicrosegPolicies {
		policyName, _ := strconv.ParseUint(val.Name, 10, 32) // 获取策略对应的uuid(旧)
		if Nuuid, ok := uuidConfig[uint32(policyName)]; ok {
			if val.Status == 1 {
				enablingTenantPolicy = append(enablingTenantPolicy, Nuuid)
			}
			// 建立update结构体
			updateConfig := UpdateTenantRequest{
				BaseInfo: TenantBaseInfo{
					Name:       createdMap[Nuuid].Name,
					Namespaces: createdMap[Nuuid].Namespaces,
					Users:      createdMap[Nuuid].Users,
				},
				PolicyInfo: CreateTenantPolicyRequest{
					CreatePolicyRequest: CreatePolicyRequest{
						Status:        0,
						Revision:      1,
						AllowExternal: val.AllowExternal,
						Operator:      val.Creator,
					},
					Trusted: val.Trusted,
				},
			}
			var ruleList []Rule
			// 更新结构体还差 rule 没有填入 ,rule 依靠policyName（uuid）关联
			for _, rule := range cMicroSeg.MicrosegRules {
				if rule.Policy == val.Name { // get
					action := actionToDto[rule.Action]
					direction := directionToDto[rule.Direction]
					protocol := protocolTypeToDto[rule.Protocol]

					ruleconfig := Rule{
						Action:    action,
						Direction: direction,
						Protocol:  protocol,
					}

					if direction == "Ingress" {
						srcType := microTypeToDto[rule.SrcType]
						srcId := uuidConfig[rule.SrcID] // 将新uuid写入
						srcIPBlock := rule.SrcIPBlock
						srcTenant := SuggestionTenant{
							Cluster: createdMap[srcId].Cluster,
							Name:    createdMap[srcId].Name,
						}
						ruleconfig.SrcType = srcType
						ruleconfig.SrcId = srcId
						ruleconfig.SrcIPBlock = srcIPBlock
						ruleconfig.SrcTenant = srcTenant
					} else {
						dstType := microTypeToDto[rule.DstType]
						dstId := uuidConfig[rule.DstID]
						dstIPBlock := rule.DstIPBlock
						dstTenant := SuggestionTenant{
							Cluster: createdMap[dstId].Cluster,
							Name:    createdMap[dstId].Name,
						}
						ruleconfig.DstType = dstType
						ruleconfig.DstId = dstId
						ruleconfig.DstIPBlock = dstIPBlock
						ruleconfig.DstTenant = dstTenant
					}

					ruleList = append(ruleList, ruleconfig)
				}
			}
			updateConfig.PolicyInfo.Rules = ruleList

			// updatePolicy data is ok
			err := ms.UpdateMicrosegTenant(updateConfig, createdMap[Nuuid].Cluster, createdMap[Nuuid].ID)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("get updatepolicy failed")
				return createdList, nil, err
			}
		}
	}

	// 启用策略
	for _, val := range enablingTenantPolicy {
		config := PolicyEnabling{
			Enable:   1,
			Revision: 2,
		}
		err := ms.EnablingTenantPolicy(config, createdMap[val].Cluster, createdMap[val].ID)
		if err != nil {
			return createdList, IDConfig, err
		}
	}

	return createdList, IDConfig, nil
}

func (ms *MicroSegOperator) DeleteMicrosegTenants(ctx context.Context, Config []TensorMicrosegTenant) error {
	if len(Config) == 0 {
		logging.Get().Debug().Msgf("microseg_tenants, nothing need to delete")
		return nil
	}

	for _, val := range Config {
		if err := ms.DeleteMicrosegTenant(val.Cluster, val.ID); err != nil {
			return err
		}
	}
	return nil
}

// microseg_nsgrps
func (ms *MicroSegOperator) ImportMicrosegNamespaces(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClusterConfig map[string]string) ([]TensorMicrosegNsgrp, error) {
	var createdList []TensorMicrosegNsgrp
	uuidConfig := make(map[uint32]uint32)      // 新旧uuid的替换
	createdMap := make(map[uint32]SingleNsgrp) // 内部使用的新增租户查询map

	for _, val := range cMicroSeg.MicrosegNSGroups {

		createInfo := CreateNsgrpRequest{
			BaseInfo: NsgrpBaseInfo{
				Name:       val.Name,
				Namespaces: strings.Split(val.Namespaces, ","),
			},
		}

		oldClusterKey := val.Cluster
		newClusterKey := ClusterConfig[oldClusterKey]

		newNsgrpsInfo, err := ms.createMicrosegNsgrp(createInfo, newClusterKey)
		if err != nil {
			return createdList, err
		}
		newNsgrpsInfo.Namespaces = strings.Split(val.Namespaces, ",")

		uuidConfig[val.UUID] = newNsgrpsInfo.UUID
		createdMap[newNsgrpsInfo.UUID] = newNsgrpsInfo
		createdList = append(createdList, TensorMicrosegNsgrp{ID: newNsgrpsInfo.ID, Cluster: newNsgrpsInfo.Cluster})
	}

	var enablingNsgrpPolicy []uint32

	for _, val := range cMicroSeg.MicrosegPolicies {
		policyName, _ := strconv.ParseUint(val.Name, 10, 32)
		if Nuuid, ok := uuidConfig[uint32(policyName)]; ok {
			if val.Status == 1 {
				enablingNsgrpPolicy = append(enablingNsgrpPolicy, Nuuid)
			}
			// 建立update结构体
			updateConfig := UpdateNsgrpRequest{
				BaseInfo: NsgrpBaseInfo{
					Name:       createdMap[Nuuid].Name,
					Namespaces: createdMap[Nuuid].Namespaces,
				},
				PolicyInfo: CreateNsgrpPolicyRequest{
					CreatePolicyRequest: CreatePolicyRequest{
						Status:        0,
						Revision:      1,
						AllowExternal: val.AllowExternal,
						Operator:      val.Creator,
					},
					Trusted: val.Trusted,
				},
			}
			var ruleList []Rule
			for _, rule := range cMicroSeg.MicrosegRules {
				if rule.Policy == val.Name {
					action := actionToDto[rule.Action]
					direction := directionToDto[rule.Direction]
					protocol := protocolTypeToDto[rule.Protocol]

					ruleconfig := Rule{
						Action:    action,
						Direction: direction,
						Protocol:  protocol,
					}

					if direction == "Ingress" {
						srcType := microTypeToDto[rule.SrcType]
						srcId := uuidConfig[rule.SrcID]
						srcNsgrp := SuggestionNsgrp{
							Cluster: createdMap[srcId].Cluster,
							Name:    createdMap[srcId].Name,
						}
						ruleconfig.SrcType = srcType
						ruleconfig.SrcId = srcId
						ruleconfig.SrcNsgrp = srcNsgrp
					} else {
						dstType := microTypeToDto[rule.DstType]
						dstId := uuidConfig[rule.DstID]
						dstNsgrp := SuggestionNsgrp{
							Cluster: createdMap[dstId].Cluster,
							Name:    createdMap[dstId].Name,
						}
						ruleconfig.DstType = dstType
						ruleconfig.DstId = dstId
						ruleconfig.DstNsgrp = dstNsgrp
					}

					ruleList = append(ruleList, ruleconfig)
				}
			}
			updateConfig.PolicyInfo.Rules = ruleList

			err := ms.UpdateMicrosegNsgrp(updateConfig, createdMap[Nuuid].Cluster, createdMap[Nuuid].ID)
			if err != nil {
				logging.Get().Error().Err(err)
				return createdList, err
			}
		}
	}

	// 启用策略
	for _, val := range enablingNsgrpPolicy {
		config := PolicyEnabling{
			Enable:   1,
			Revision: 2,
		}
		err := ms.EnablingNsgrpPolicy(config, createdMap[val].Cluster, createdMap[val].ID)
		if err != nil {
			return createdList, err
		}
	}
	return createdList, nil
}

func (ms *MicroSegOperator) DeleteMicrosegNsgrps(ctx context.Context, Config []TensorMicrosegNsgrp) error {
	if len(Config) == 0 {
		logging.Get().Debug().Msgf("microseg_nsgrps, nothing need to delete")
		return nil
	}

	for _, val := range Config {
		if err := ms.DeleteMicrosegNsgrp(val.Cluster, val.ID); err != nil {
			return err
		}
	}

	return nil
}

// microseg_resources
func (ms *MicroSegOperator) createResourcePolicyList(Resources []TensorMicrosegResource, Policies []TensorMicrosegPolicy) ([]TensorMicrosegResourcePolicy, error) {
	resourcesPolicies := make([]TensorMicrosegResourcePolicy, 0)

	resourceMap := make(map[string]TensorMicrosegResource)
	for i := range Resources {
		resourceMap[fmt.Sprintf("%d", Resources[i].ID)] = Resources[i]
	}

	for i := range Policies {
		if Policies[i].Type != Resource {
			continue
		}
		resource, ok := resourceMap[Policies[i].Name]
		if !ok {
			logging.Get().Error().Str("policy name", Policies[i].Name).Msg("cannot find policy name in resources")
			return resourcesPolicies, errors.New("cannot find policy name in resources")
		}
		resourcesPolicies = append(resourcesPolicies, TensorMicrosegResourcePolicy{resource, Policies[i]})
	}
	return resourcesPolicies, nil
}

func (ms *MicroSegOperator) GetMicrosegResourcesInfo(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClusterConfig map[string]string) (map[uint32]uint32, map[uint32]CommonMicroSegObject, map[uint32][]K8sResource) {
	IDMap := make(map[uint32]uint32)
	newMap := make(map[uint32]CommonMicroSegObject)
	SegmentResourcesMap := make(map[uint32][]K8sResource)

	for _, val := range cMicroSeg.MicrosegResources {
		if val.SegmentID != 0 {
			resource := K8sResource{
				Name:      val.Name,
				Kind:      val.Kind,
				Namespace: val.Namespace,
				Cluster:   val.Cluster,
			}
			if _, ok := SegmentResourcesMap[val.SegmentID]; !ok {
				SegmentResourcesMap[val.SegmentID] = []K8sResource{resource}
			} else {
				SegmentResourcesMap[val.SegmentID] = append(SegmentResourcesMap[val.SegmentID], resource)
			}
		}
		newClusterkey := ClusterConfig[val.Cluster]
		newID := GenID(newClusterkey, val.Namespace, val.Kind, val.Name)
		IDMap[val.ID] = newID
		newMap[newID] = CommonMicroSegObject{
			Cluster:   newClusterkey, // new
			Namespace: val.Namespace,
			Kind:      val.Kind,
			Name:      val.Name,
		}
	}

	for _, val := range cMicroSeg.MicrosegSegments {
		newCluster := ClusterConfig[val.Cluster]
		newID := GenID(newCluster, val.Namespace, val.Name)
		IDMap[val.ID] = newID
		newMap[newID] = CommonMicroSegObject{
			Cluster:   newCluster,
			Namespace: val.Namespace,
			Name:      val.Name,
		}
	}

	return IDMap, newMap, SegmentResourcesMap
}

func (ms *MicroSegOperator) ImportMicrosegResources(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClustersConfig map[string]string, IDMap map[uint32]uint32, newMap map[uint32]CommonMicroSegObject) ([]TensorMicrosegResourcePolicy, error) {
	resourcesPolicies := make([]TensorMicrosegResourcePolicy, 0)

	// 反转 新老集群key map
	newOldClustersConfig := make(map[string]string)
	for k, v := range ClustersConfig {
		newOldClustersConfig[v] = k
	}

	// 遍历resource，构建resourceMap
	resourceMap := make(map[string]TensorMicrosegResource)
	for i := range cMicroSeg.MicrosegResources {
		resourceMap[fmt.Sprintf("%d", cMicroSeg.MicrosegResources[i].ID)] = cMicroSeg.MicrosegResources[i]
	}

	// 遍历rules，构建ruleMap
	ruleMap := make(map[string][]Rule)
	for i := range cMicroSeg.MicrosegRules {
		rule, err := dbRuleToRule(cMicroSeg.MicrosegRules[i], IDMap, newMap)
		if err != nil {
			logging.Get().Error().Err(err).Msg("convert rule fails")
			return resourcesPolicies, err
		}
		if rules, ok := ruleMap[cMicroSeg.MicrosegRules[i].Policy]; ok {
			ruleMap[cMicroSeg.MicrosegRules[i].Policy] = append(rules, rule)
		} else {
			ruleMap[cMicroSeg.MicrosegRules[i].Policy] = []Rule{rule}
		}
	}

	// 遍历policy，直接调用 microseg 接口
	for i := range cMicroSeg.MicrosegPolicies {
		if cMicroSeg.MicrosegPolicies[i].Type != Resource {
			continue
		}

		newClusterKey, ok := ClustersConfig[cMicroSeg.MicrosegPolicies[i].Cluster]
		if !ok {
			logging.Get().Error().Interface("clustersConfig", ClustersConfig).Str("old cluster key", cMicroSeg.MicrosegPolicies[i].Cluster).Msg("no same name cluster")
			return resourcesPolicies, errors.New("no same name cluster")
		}
		resource, ok := resourceMap[cMicroSeg.MicrosegPolicies[i].Name]
		if !ok {
			logging.Get().Error().Str("policy name", cMicroSeg.MicrosegPolicies[i].Name).Msg("cannot find policy name in resources")
			return resourcesPolicies, errors.New("cannot find policy name in resources")
		}
		// 先调用 get /policy/enabling 会创建一个默认的policy，revision为0
		resource.Cluster = newClusterKey
		resp, err := ms.getMicrosegResourcePolicyEnabling(
			resource.Cluster,
			resource.Namespace,
			resource.Kind,
			resource.Name,
		)
		if err != nil {
			logging.Get().Error().Err(err).Str("cluster", resource.Cluster).Str("namespace", cMicroSeg.MicrosegPolicies[i].Namespace).Str("kind", resource.Kind).Str("name", resource.Name).Msg("policy enabling fails")
			return resourcesPolicies, errors.New("policy enabling fails")
		}

		// 再调用 create /policy 更新成真正的policy
		createReq := CreatePolicyRequest{
			Status:        0,
			Rules:         ruleMap[cMicroSeg.MicrosegPolicies[i].Name],
			Revision:      resp.Data.Item.Revision,
			Operator:      "maohaoxin@tensorsecurity.cn",
			AllowExternal: cMicroSeg.MicrosegPolicies[i].AllowExternal,
		}
		cMicroSeg.MicrosegPolicies[i].Revision = resp.Data.Item.Revision
		err = ms.createMicrosegResourcePolicy(
			createReq,
			resource.Cluster,
			resource.Namespace,
			resource.Kind,
			resource.Name,
		)
		if err != nil {
			logging.Get().Error().Err(err).Str("cluster", resource.Cluster).Str("namespace", cMicroSeg.MicrosegPolicies[i].Namespace).Str("kind", resource.Kind).Str("name", resource.Name).Msg("create policy fails")
			return resourcesPolicies, errors.New("create policy fails")
		}
		cMicroSeg.MicrosegPolicies[i].Revision++

		if cMicroSeg.MicrosegPolicies[i].Status == 1 {
			err = ms.enableMicrosegResourcePolicy(PolicyEnabling{
				Enable:   1,
				Revision: cMicroSeg.MicrosegPolicies[i].Revision,
			},
				resource.Cluster,
				resource.Namespace,
				resource.Kind,
				resource.Name,
			)
			if err != nil {
				logging.Get().Error().Err(err).Str("cluster", resource.Cluster).Str("namespace", cMicroSeg.MicrosegPolicies[i].Namespace).Str("kind", resource.Kind).Str("name", resource.Name).Msg("enable policy fails")
				return resourcesPolicies, errors.New("enable policy fails")
			}
		}
		resourcesPolicies = append(resourcesPolicies, TensorMicrosegResourcePolicy{resource, cMicroSeg.MicrosegPolicies[i]})
	}
	return resourcesPolicies, nil
}

// microseg_segments
func (ms *MicroSegOperator) ImportMicrosegSegments(ctx context.Context, db *gorm.DB, cMicroSeg *ConfigMicroSeg, ClustersConfig map[string]string, IDMap map[uint32]uint32, newMap map[uint32]CommonMicroSegObject, SegmentResourcesMap map[uint32][]K8sResource) ([]TensorMicrosegSegment, error) {
	resourceMap := make(map[string]TensorMicrosegSegment)
	createdList := make([]TensorMicrosegSegment, 0)

	for i := range cMicroSeg.MicrosegSegments {

		createInfo := CreateSegmentRequest{
			Name: cMicroSeg.MicrosegSegments[i].Name,
		}

		oldClusterKey := cMicroSeg.MicrosegSegments[i].Cluster

		newClusterKey := ClustersConfig[oldClusterKey]

		err := ms.createMicrosegSegment(createInfo, newClusterKey, cMicroSeg.MicrosegSegments[i].Namespace)
		if err != nil {
			return createdList, err
		}
		createdList = append(createdList, TensorMicrosegSegment{
			Name:      cMicroSeg.MicrosegSegments[i].Name,
			Cluster:   newClusterKey,
			Namespace: cMicroSeg.MicrosegSegments[i].Namespace,
		})

		resourceMap[fmt.Sprintf("%d", cMicroSeg.MicrosegSegments[i].ID)] = cMicroSeg.MicrosegSegments[i]

		if val, ok := SegmentResourcesMap[cMicroSeg.MicrosegSegments[i].ID]; ok {
			// val 即为 该 segment 需要添加的 旧资源
			var resourceNameList []string
			for _, val := range val {
				resourceNameList = append(resourceNameList, val.Name)
			}

			var resourceList []TensorMicrosegResource
			err = db.WithContext(ctx).Model(&TensorMicrosegResource{}).Where("name in ? and namespace=?", resourceNameList, cMicroSeg.MicrosegSegments[i].Namespace).Scan(&resourceList).Error
			if err != nil {
				return createdList, err
			}

			var request []K8sResource
			for _, res := range resourceList {
				data := K8sResource{
					Name:      res.Name,
					Kind:      res.Kind,
					Namespace: res.Namespace,
					Cluster:   res.Cluster,
				}
				request = append(request, data)
			}

			err := ms.updateMicrosegSegment(request, newClusterKey, cMicroSeg.MicrosegSegments[i].Namespace, cMicroSeg.MicrosegSegments[i].Name)
			if err != nil {
				return createdList, err
			}
		}
	}

	// 遍历rules，构建ruleMap
	ruleMap := make(map[string][]Rule)
	for i := range cMicroSeg.MicrosegRules {
		rule, err := dbRuleToRule(cMicroSeg.MicrosegRules[i], IDMap, newMap)
		if err != nil {
			logging.Get().Error().Err(err).Msg("convert rule fails")
			return createdList, err
		}
		if rules, ok := ruleMap[cMicroSeg.MicrosegRules[i].Policy]; ok {
			ruleMap[cMicroSeg.MicrosegRules[i].Policy] = append(rules, rule)
		} else {
			ruleMap[cMicroSeg.MicrosegRules[i].Policy] = []Rule{rule}
		}
	}

	// 遍历policy，直接调用 microseg 接口
	for i := range cMicroSeg.MicrosegPolicies {
		// 不是resource的policy跳过
		if cMicroSeg.MicrosegPolicies[i].Type != Segment {
			continue
		}

		newClusterKey, ok := ClustersConfig[cMicroSeg.MicrosegPolicies[i].Cluster]
		if !ok {
			logging.Get().Error().Interface("clustersConfig", ClustersConfig).Str("old cluster key", cMicroSeg.MicrosegPolicies[i].Cluster).Msg("no same name cluster")
			return createdList, errors.New("no same name cluster")
		}

		segment, ok := resourceMap[cMicroSeg.MicrosegPolicies[i].Name]
		if !ok {
			logging.Get().Error().Str("policy name", cMicroSeg.MicrosegPolicies[i].Name).Msg("cannot find policy name in resources")
			return createdList, errors.New("cannot find policy name in resources")
		}

		// 调用 create /policy 更新成真正的policy
		createReq := CreatePolicyRequest{
			// Status:        cMicroSeg.MicrosegPolicies[i].Status,
			Status:        0,
			Rules:         ruleMap[cMicroSeg.MicrosegPolicies[i].Name],
			Revision:      0,
			Operator:      "maohaoxin@tensorsecurity.cn",
			AllowExternal: cMicroSeg.MicrosegPolicies[i].AllowExternal,
		}
		err := ms.createMicrosegSegmentPolicy(
			createReq,
			newClusterKey,
			segment.Namespace,
			segment.Name,
		)
		if err != nil {
			logging.Get().Error().Err(err).Str("cluster", newClusterKey).Str("namespace", segment.Namespace).Str("segment", segment.Name).Msg("create policy fails")
			return createdList, errors.New("policy create fails")
		}

		// 调用enabling接口，开启该策略
		if cMicroSeg.MicrosegPolicies[i].Status == 1 {
			err = ms.enableMicrosegSegmentPolicy(PolicyEnabling{
				Enable:   1,
				Revision: 1,
			},
				newClusterKey,
				segment.Namespace,
				segment.Name,
			)
			if err != nil {
				logging.Get().Error().Err(err).Str("cluster", newClusterKey).Str("namespace", segment.Namespace).Str("segment", segment.Name).Msg("enable policy fails")
				return createdList, errors.New("policy enabling fails")
			}
		}
	}
	return createdList, nil
}

func (ms *MicroSegOperator) deleteMicrosegSegments(ctx context.Context, Config []TensorMicrosegSegment) error {
	if len(Config) == 0 {
		logging.Get().Debug().Msgf("microseg_segments, nothing need to delete")
		return nil
	}

	for _, val := range Config {
		if err := ms.DeleteMicrosegSegment(val.Cluster, val.Namespace, val.Name); err != nil {
			return err
		}
	}

	return nil
}

func (ms *MicroSegOperator) deleteMicrosegResourcesPolicies(ctx context.Context, resourcesPolicies []TensorMicrosegResourcePolicy) error {
	for i := range resourcesPolicies {
		createReq := CreatePolicyRequest{
			Status:        resourcesPolicies[i].Policy.Status,
			Rules:         []Rule{},
			Revision:      resourcesPolicies[i].Policy.Revision,
			Operator:      "maohaoxin@tensorsecurity.cn",
			AllowExternal: resourcesPolicies[i].Policy.AllowExternal,
		}

		err := ms.createMicrosegResourcePolicy(
			createReq,
			resourcesPolicies[i].Resource.Cluster,
			resourcesPolicies[i].Resource.Namespace,
			resourcesPolicies[i].Resource.Kind,
			resourcesPolicies[i].Resource.Name,
		)
		if err != nil {
			logging.Get().Error().Err(err).Str("cluster", resourcesPolicies[i].Resource.Cluster).Str("namespace", resourcesPolicies[i].Resource.Namespace).Str("kind", resourcesPolicies[i].Resource.Kind).Str("name", resourcesPolicies[i].Resource.Name).Msg("create policy fails")
			return errors.New("create policy fails")
		}

		if resourcesPolicies[i].Policy.Status == 1 {
			err = ms.enableMicrosegResourcePolicy(PolicyEnabling{
				Enable:   0,
				Revision: resourcesPolicies[i].Policy.Revision + 1,
			},
				resourcesPolicies[i].Resource.Cluster,
				resourcesPolicies[i].Resource.Namespace,
				resourcesPolicies[i].Resource.Kind,
				resourcesPolicies[i].Resource.Name,
			)
			if err != nil {
				logging.Get().Error().Err(err).Str("cluster", resourcesPolicies[i].Resource.Cluster).Str("namespace", resourcesPolicies[i].Resource.Namespace).Str("kind", resourcesPolicies[i].Resource.Kind).Str("name", resourcesPolicies[i].Resource.Name).Msg("enable policy fails")
				return errors.New("enable policy fails")
			}
		}
	}

	return nil
}
