package dal

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"strconv"
	"sync"
	"time"
)

var (
	OnDupUpdatedColsForAssetsTagRel = []string{
		"updated_at",
	}
	OnDupUpdatedColsForAssetsTag = []string{
		"updated_at",
		"name",
		"desc",
	}
)

const ( // 内置标签对应的字符串
	BuiltInTag_all  = "All assets"
	BuiltInTag_k8s  = "K8s assets"
	BuiltInTag_node = "Node assets"
	BuiltInTag_app  = "App assets"
)

var ( // 内置标签对应的类型
	BuiltInTagObjTypeMap = map[string][]model.TagRelObjType{
		BuiltInTag_all: model.TagRelObjList,
		BuiltInTag_k8s: {model.ObjType_cluster, model.ObjType_namespace, model.ObjType_resource, model.ObjType_pod, model.ObjType_pod, model.ObjType_container,
			model.ObjType_service, model.ObjType_endpoints, model.ObjType_ingress,
			model.ObjType_api, model.ObjType_secret, model.ObjType_pv, model.ObjType_pvc, model.ObjType_label, model.ObjType_node},
		BuiltInTag_node: {model.ObjType_node},
		BuiltInTag_app:  {model.ObjType_webSit, model.ObjType_app, model.ObjType_webApp, model.ObjType_dbApp},
	}

	// 类型对应的内置标签
	ObjTypeBuiltInTagMap = map[model.TagRelObjType][]string{
		model.ObjType_cluster:   []string{BuiltInTag_k8s},
		model.ObjType_namespace: []string{BuiltInTag_k8s},
		model.ObjType_resource:  []string{BuiltInTag_k8s},
		model.ObjType_pod:       []string{BuiltInTag_k8s},
		model.ObjType_container: []string{BuiltInTag_k8s},
		model.ObjType_service:   []string{BuiltInTag_k8s},
		model.ObjType_endpoints: []string{BuiltInTag_k8s},
		model.ObjType_ingress:   []string{BuiltInTag_k8s},
		model.ObjType_api:       []string{BuiltInTag_k8s},
		model.ObjType_pv:        []string{BuiltInTag_k8s},
		model.ObjType_pvc:       []string{BuiltInTag_k8s},
		model.ObjType_label:     []string{BuiltInTag_k8s},
		model.ObjType_node:      []string{BuiltInTag_k8s, BuiltInTag_node},
		model.ObjType_webSit:    []string{BuiltInTag_app},
		model.ObjType_app:       []string{BuiltInTag_app},
		model.ObjType_webApp:    []string{BuiltInTag_app},
		model.ObjType_dbApp:     []string{BuiltInTag_app},
	}
	BuiltInTagEnCnMap = map[string]string{
		BuiltInTag_k8s:  "K8s资产",
		BuiltInTag_node: "节点资产",
		BuiltInTag_app:  "应用资产",
	}
)

func GetBuiltInTagByObjTypeAndLanguage(objtype model.TagRelObjType, isEn bool) []string {
	tags := ObjTypeBuiltInTagMap[objtype]
	if isEn {
		return tags
	}
	var result []string
	for _, tag := range tags {
		result = append(result, BuiltInTagEnCnMap[tag])
	}
	return result
}

func GetEnableAssetsTagList(ctx context.Context, rdb *gorm.DB) (tagList []*model.TensorAssetsTag, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	err = rdb.WithContext(pgCtx).Model(&model.TensorAssetsTag{}).Where("status = 0").Order("type desc").Order("created_at desc").Find(&tagList).Error
	if err != nil {
		return nil, err
	}
	return
}

type TensorAssetsTagWithRelCounts struct {
	model.TensorAssetsTag
	Count int64 `json:"count"`
}

func GetAssetsTagList(ctx context.Context, rdb *gorm.DB, tagName string, offset int, limit int) (tagList []*TensorAssetsTagWithRelCounts, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	db := rdb.Offset(offset).Limit(limit)
	if tagName != "" {
		db = db.Where("name like ?", GetLikeExpr(tagName)).Where("type=?", 0)
	}
	err = db.WithContext(pgCtx).Model(&model.TensorAssetsTag{}).Order("type desc").Order("created_at desc").Scan(&tagList).Error
	if err != nil {
		return nil, err
	}
	var customTagIdList []string
	var builtInTagNameList []string
	for _, tag := range tagList {
		_, isOk := BuiltInTagEnCnMap[tag.Name]
		if isOk {
			builtInTagNameList = append(builtInTagNameList, tag.Name)
		} else {
			customTagIdList = append(customTagIdList, tag.ID)
		}
	}
	builtMap, customMap := getTagRelCountsByTagIds(ctx, rdb, builtInTagNameList, customTagIdList)
	logging.Get().Info().Msgf("getTagRelCountsByTagIds:%v,%v", builtMap, customMap)
	for _, tag := range tagList {

		c, isOk := builtMap[tag.Name]
		if isOk == false {
			tag.Count = customMap[tag.ID]
		} else {
			tag.Count = c
		}
	}
	return
}

func getTagRelCountsByTagIds(ctx context.Context, rdb *gorm.DB, builtTagNameList []string, customIdList []string) (builtCountMap map[string]int64, customCountMap map[string]int64) {

	builtInResultMap := make(map[string]int64)
	customResultMap := make(map[string]int64)
	type TagsInObj struct {
		TagId    string
		RelCount int64
	}

	for _, tagName := range builtTagNameList {
		counts, err := getBuiltInTagAssetsCount(ctx, rdb, BuiltInTagObjTypeMap[tagName])
		if err != nil {
			return nil, nil
		}
		for _, count := range counts {
			builtInResultMap[tagName] = builtInResultMap[tagName] + count.Count
		}
	}

	var err error
	for _, objType := range model.TagRelObjList {
		var tagRelCounts []TagsInObj
		db := rdb.WithContext(ctx).Model(&model.TensorAssetsTagRel{}).Select("tag_id,COUNT(*) as rel_count").Where("tag_id  in ? and obj_type=?", customIdList, objType).Group("ivan_assets_tag_rel.tag_id")
		switch objType {
		case model.ObjType_cluster:
			err = db.Joins("join  ivan_assets_clusters c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_namespace:
			err = db.Joins("join  ivan_assets_namespaces c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_resource:
			err = db.Joins("join  ivan_assets_resources c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_pod:
			err = db.Joins("join  ivan_assets_pod_res_relations c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_container:
			err = db.Joins("join  ivan_assets_raw_containers c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status < ?", 5).Scan(&tagRelCounts).Error
		case model.ObjType_service:
			err = db.Joins("join  ivan_assets_services c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_endpoints:
			err = db.Joins("join  ivan_assets_endpoints c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_ingress:
			err = db.Joins("join  ivan_assets_ingresses c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_api:
			err = db.Joins("join  ivan_assets_apis c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_secret:
			err = db.Joins("join  ivan_assets_secrets c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_pv:
			err = db.Joins("join  ivan_assets_pvs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_pvc:
			err = db.Joins("join  ivan_assets_pvcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_node:
			err = db.Joins("join  ivan_assets_nodes c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_webSit:
			err = db.Joins("join (SELECT DISTINCT host from ivan_assets_ingress_rules) i on i.host=ivan_assets_tag_rel.obj_id").Scan(&tagRelCounts).Error
		case model.ObjType_app:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Scan(&tagRelCounts).Error
		case model.ObjType_webApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeWebEn).Scan(&tagRelCounts).Error
		case model.ObjType_dbApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeDbEn).Scan(&tagRelCounts).Error
		}
		if err != nil {
			logging.Get().Err(err).Msgf("get assets count failed.objType:%s,tagIds:%s,%s", string(objType), builtTagNameList, customIdList)
		}
		if len(tagRelCounts) > 0 {
			logging.Get().Info().Msgf("objType:%s,count:%s", tagRelCounts[0])
		}
		for _, count := range tagRelCounts {
			total, isOk := customResultMap[count.TagId]
			if !isOk {
				customResultMap[count.TagId] = count.RelCount
			} else {
				customResultMap[count.TagId] = count.RelCount + total
			}
		}
	}
	return builtInResultMap, customResultMap
}

func CountAssetsTag(ctx context.Context, rdb *gorm.DB, tagName string) (total int64, err error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	db := rdb
	if tagName != "" {
		db = rdb.Where("name like ?", GetLikeExpr(tagName)).Where("type=?", 0)
	}
	err = db.WithContext(pgCtx).Model(&model.TensorAssetsTag{}).Count(&total).Error
	return
}

func ChangeAssetsTagStatus(ctx context.Context, rdb *gorm.DB, enableIds []string, disableIds []string) error {
	if len(enableIds) == 0 && len(disableIds) == 0 {
		return nil
	}

	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(enableIds) > 0 {
			err := tx.Model(&model.TensorAssetsTag{}).Where("id in ?", enableIds).UpdateColumn("status", 0).Error
			if err != nil {
				return err
			}
		}
		if len(disableIds) > 0 {
			err := tx.Model(&model.TensorAssetsTag{}).Where("id in ?", disableIds).UpdateColumn("status", 1).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

type AssetsTagRelIdsCount struct {
	ObjType model.TagRelObjType
	Count   int64
	ObjIds  []string
}
type AssetsTagRelsIds struct {
	ObjType model.TagRelObjType `json:"objType"`
	ObjIds  []string            `json:"objIds"`
}

type AssetsTagRelCount struct {
	ObjType model.TagRelObjType `json:"objType"`
	Count   int64               `json:"count"`
}

type AssetsTagWithIdsCounts struct {
	Tag       *model.TensorAssetsTag
	RelCounts []*AssetsTagRelIdsCount
}

type AssetsTagWithCounts struct {
	TagId     string
	TagName   string
	RelCounts []*AssetsTagRelIdsCount
}

type ObjInfo struct {
	ObjType model.TagRelObjType
	ObjId   string
}

func GetAssetsTagRelIdsCounts(ctx context.Context, rdb *gorm.DB, tagId string) (detail *AssetsTagWithIdsCounts, err error) {
	if len(tagId) == 0 {
		return nil, nil
	}
	detail = &AssetsTagWithIdsCounts{
		Tag: &model.TensorAssetsTag{},
	}
	err = rdb.Model(&model.TensorAssetsTag{}).Where("id = ?", tagId).Take(detail.Tag).Error
	if err != nil {
		return nil, err
	}
	if detail.Tag == nil {
		return nil, nil
	}
	for _, objType := range model.TagRelObjList {
		item := AssetsTagRelIdsCount{
			ObjType: objType,
		}

		db := rdb.WithContext(ctx).Model(&model.TensorAssetsTagRel{}).Where("tag_id = ? and obj_type=?", tagId, objType).Select("obj_id")
		switch objType {
		case model.ObjType_cluster:
			err = db.Joins("join  ivan_assets_clusters c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_namespace:
			err = db.Joins("join  ivan_assets_namespaces c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_resource:
			err = db.Joins("join  ivan_assets_resources c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pod:
			err = db.Joins("join  ivan_assets_pod_res_relations c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_container:
			err = db.Joins("join  ivan_assets_raw_containers c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status <", 5).Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_service:
			err = db.Joins("join  ivan_assets_services c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_endpoints:
			err = db.Joins("join  ivan_assets_endpoints c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_ingress:
			err = db.Joins("join  ivan_assets_ingresses c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_api:
			err = db.Joins("join  ivan_assets_apis c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_type", &item.ObjIds).Error
		case model.ObjType_secret:
			err = db.Joins("join  ivan_assets_secrets c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pv:
			err = db.Joins("join  ivan_assets_pvs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pvc:
			err = db.Joins("join  ivan_assets_pvcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_node:
			err = db.Joins("join  ivan_assets_nodes c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_webSit:
			err = db.Joins("join (SELECT DISTINCT host from ivan_assets_ingress_rules) i on i.host=ivan_assets_tag_rel.obj_id").Pluck("i.host", &item.ObjIds).Error
		case model.ObjType_app:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_webApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeWebEn).Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_dbApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeDbEn).Pluck("obj_id", &item.ObjIds).Error
		}
		if err != nil {
			logging.Get().Err(err).Msgf("get assets count failed.tagId:%s,objType:%s", tagId, string(objType))
		}
		item.Count = int64(len(item.ObjIds))
		detail.RelCounts = append(detail.RelCounts, &item)
	}
	return detail, nil
}

func GetAssetsTagRelCounts(ctx context.Context, rdb *gorm.DB, tagId string) (relCounts *AssetsTagWithCounts, err error) {
	if len(tagId) == 0 {
		return &AssetsTagWithCounts{}, nil
	}
	relCounts = &AssetsTagWithCounts{}
	if tagId == "allAssets" {
		relCounts.TagId = BuiltInTag_all
		relCounts.TagName = BuiltInTag_all
		relCounts.RelCounts, err = getBuiltInTagAssetsCount(ctx, rdb, BuiltInTagObjTypeMap[BuiltInTag_all])
		return relCounts, err
	}
	var tag model.TensorAssetsTag
	err = rdb.Model(&model.TensorAssetsTag{}).Where("id = ?", tagId).Take(&tag).Error
	if err != nil {
		return nil, err
	}
	relCounts.TagId = tag.ID
	relCounts.TagName = tag.Name
	if tag.Type != 0 {
		relCounts.RelCounts, err = getBuiltInTagAssetsCount(ctx, rdb, BuiltInTagObjTypeMap[tag.Name])
		return relCounts, err
	}

	//	 自定义
	var targetObjType []model.TagRelObjType
	err = rdb.Model(&model.TensorAssetsTagRel{}).Where("tag_id = ?", tagId).Distinct("obj_type").Pluck("obj_type", &targetObjType).Error
	if err != nil {
		return nil, err
	}
	if len(targetObjType) == 0 {
		return &AssetsTagWithCounts{}, nil
	}
	for _, objType := range model.TagRelObjList {
		item := AssetsTagRelIdsCount{
			ObjType: objType,
		}

		db := rdb.WithContext(ctx).Model(&model.TensorAssetsTagRel{}).Where("tag_id = ? and obj_type=?", tagId, objType).Select("obj_id")
		switch objType {
		case model.ObjType_cluster:
			err = db.Joins("join  ivan_assets_clusters c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_namespace:
			err = db.Joins("join  ivan_assets_namespaces c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_resource:
			err = db.Joins("join  ivan_assets_resources c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pod:
			err = db.Joins("join  ivan_assets_pod_res_relations c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_container:
			err = db.Joins("join  ivan_assets_raw_containers c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status <", 5).Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_service:
			err = db.Joins("join  ivan_assets_services c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_endpoints:
			err = db.Joins("join  ivan_assets_endpoints c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_ingress:
			err = db.Joins("join  ivan_assets_ingresses c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_api:
			err = db.Joins("join  ivan_assets_apis c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_type", &item.ObjIds).Error
		case model.ObjType_secret:
			err = db.Joins("join  ivan_assets_secrets c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pv:
			err = db.Joins("join  ivan_assets_pvs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_pvc:
			err = db.Joins("join  ivan_assets_pvcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_node:
			err = db.Joins("join  ivan_assets_nodes c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_webSit:
			err = db.Joins("join (SELECT DISTINCT host from ivan_assets_ingress_rules) i on i.host=ivan_assets_tag_rel.obj_id").Pluck("i.host", &item.ObjIds).Error
		case model.ObjType_app:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0").Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_webApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeWebEn).Pluck("obj_id", &item.ObjIds).Error
		case model.ObjType_dbApp:
			err = db.Joins("join  ivan_assets_raw_containers_svcs c on c.id = ivan_assets_tag_rel.obj_id").Where("c.status=0 and svc_type = ?", assets.BusiSvcTypeDbEn).Pluck("obj_id", &item.ObjIds).Error
		}
		if err != nil {
			logging.Get().Err(err).Msgf("get assets count failed.tagId:%s,objType:%s", tagId, string(objType))
		}
		item.Count = int64(len(item.ObjIds))
		if item.Count > 0 {
			relCounts.RelCounts = append(relCounts.RelCounts, &item)
		}
	}
	return relCounts, nil
}

// 内置标签的 资产卡片计数
func getBuiltInTagAssetsCount(ctx context.Context, rdb *gorm.DB, types []model.TagRelObjType) ([]*AssetsTagRelIdsCount, error) {
	var result []*AssetsTagRelIdsCount
	var wg sync.WaitGroup
	var lock sync.Mutex
	var err error
	for _, objType := range types {
		wg.Add(1)
		go func(t model.TagRelObjType) {
			item := AssetsTagRelIdsCount{
				ObjType: t,
			}
			ctx, _ := context.WithTimeout(ctx, time.Second*8)
			switch t {
			case model.ObjType_cluster:
				item.Count, err = CountClusters(ctx, rdb, ClusterQuery())
			case model.ObjType_namespace:
				item.Count, err = CountNamespaces(ctx, rdb, "", "")
			case model.ObjType_resource:
				item.Count, err = CountResources(ctx, rdb, ResourcesQuery())
			case model.ObjType_pod:
				item.Count, err = CountPods(ctx, rdb, ResourcePodssQuery())
			case model.ObjType_container:
				query := RawContainersQuery()
				query.WithInConditionCustom("status", []int{assets.Running, assets.Created, assets.Restarting, assets.Removing, assets.Paused})
				item.Count, err = CountRawContainer(ctx, rdb, query)
			case model.ObjType_service:
				item.Count, err = CountService(ctx, rdb, ServicesQuery())
			case model.ObjType_endpoints:
				item.Count, err = CountEndpoints(ctx, rdb, EndpointsQuery())
			case model.ObjType_ingress:
				item.Count, err = CountIngress(ctx, rdb, IngressesQuery())
			case model.ObjType_api:
				err = rdb.Model(&model.TensorApi{}).Count(&item.Count).Error
			case model.ObjType_secret:
				item.Count, err = CountSecrets(ctx, rdb, SecretsQuery())
			case model.ObjType_pv:
				item.Count, err = CountPVs(ctx, rdb, PVQuery())
			case model.ObjType_pvc:
				item.Count, err = CountPVCs(ctx, rdb, PVCQuery())
			case model.ObjType_node:
				item.Count, err = CountNodes(ctx, rdb, NodeQuery())
			case model.ObjType_webSit:
				item.Count, err = CountExposeHost(ctx, rdb, "", nil, nil)
			case model.ObjType_app:
				item.Count, err = CountBusiSvcs(ctx, rdb, GetBusiSvcQueryOption())
			case model.ObjType_webApp:
				option := GetBusiSvcQueryOption()
				option.WhereEqCondition["svc_type"] = assets.BusiSvcTypeWebEn
				item.Count, err = CountBusiSvcs(ctx, rdb, option)
			case model.ObjType_dbApp:
				option := GetBusiSvcQueryOption()
				option.WhereEqCondition["svc_type"] = assets.BusiSvcTypeDbEn
				item.Count, err = CountBusiSvcs(ctx, rdb, option)
			case model.ObjType_label:
				item.Count, err = CountNamespaceLabels(ctx, rdb, NamespaceLabelQuery())
			}
			if err != nil {
				logging.Get().Err(err).Msgf("query count for %s failed.", t)
			}
			lock.Lock()
			result = append(result, &item)
			lock.Unlock()
			wg.Done()
		}(objType)
	}
	wg.Wait()
	return result, err
}

type AssetsTagRelDetail struct {
	Tag  *model.TensorAssetsTag `json:"tag"`
	Rels []*AssetsTagRelsIds    `json:"rels"`
}

func SaveAssetsTagRel(ctx context.Context, rdb *gorm.DB, detail *AssetsTagRelDetail) (err error) {
	if detail == nil {
		return
	}
	isCreate := detail.Tag.ID == ""
	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		tmpTag := model.TensorAssetsTag{}
		err = tx.Model(&tmpTag).Where("name=?", detail.Tag.Name).Take(&tmpTag).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logging.Get().Err(err).Msgf("check name unique failed.")
			return errors.New("check name unique failed")
		}
		if tmpTag.ID != "" && tmpTag.ID != detail.Tag.ID {
			logging.Get().Err(err).Msgf("tag's name is already existed.")
			return errors.New("标签名称已存在，请输入其他名称")
		}
		if isCreate { // create
			detail.Tag.ID = strconv.Itoa(int(util.GenerateUUID(time.Now().String())))
		}
		err = tx.Model(&model.TensorAssetsTag{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForAssetsTag),
		}).Create(&detail.Tag).Error
		if err != nil {
			logging.Get().Err(err).Msgf("insert assets tag failed")
			return errors.New("insert assets tag failed")
		}
		// rel
		var tagRels []*model.TensorAssetsTagRel
		for _, rel := range detail.Rels {
			for _, objId := range rel.ObjIds {
				item := model.TensorAssetsTagRel{
					TableBase: model.TableBase{
						ID:        util.GenerateUUID(detail.Tag.ID, string(rel.ObjType), objId),
						CreatedAt: now,
						UpdatedAt: now,
						Status:    0,
					},
					TagId:   detail.Tag.ID,
					ObjType: rel.ObjType,
					ObjId:   objId,
				}
				tagRels = append(tagRels, &item)
			}
		}
		if len(tagRels) > 0 {
			err = tx.Model(&model.TensorAssetsTagRel{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(OnDupUpdatedColsForAssetsTagRel),
			}).Create(&tagRels).Error
			if err != nil {
				logging.Get().Err(err).Msgf("insert assets tag  rel failed")
				return errors.New("insert assets tag rel failed")
			}
		}
		//	 clean old rel
		if isCreate {
			return nil
		}
		err = tx.Where("tag_id = ? and  updated_at < ? ", detail.Tag.ID, now.Add(-time.Millisecond)).Delete(&model.TensorAssetsTagRel{}).Error
		if err != nil {
			logging.Get().Err(err).Msgf("clean old assets tag  rel failed")
			return errors.New("clean old assets tag rel failed")
		}
		return nil
	})
}

func DeleteAssetsTag(ctx context.Context, rdb *gorm.DB, tagId string) error {
	if tagId == "" {
		return nil
	}
	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("id=?", tagId).Delete(&model.TensorAssetsTag{}).Error
		if err != nil {
			logging.Get().Err(err).Msgf("delete assetsTag failed.")
			return errors.New("delete assetsTag failed")
		}
		err = tx.Where("tag_id = ?", tagId).Delete(&model.TensorAssetsTagRel{}).Error
		if err != nil {
			logging.Get().Err(err).Msgf("delete assetsTag rel failed.")
			return errors.New("delete assetsTag rel failed")
		}
		return nil
	})
}

type AssetsChangeTagsReq struct {
	Action string            `json:"action"` // add/delete
	Objs   *AssetsTagRelsIds `json:"objs"`
	TagIds []string          `json:"tagIds"`
}

func AssetsChangeTags(ctx context.Context, rdb *gorm.DB, req *AssetsChangeTagsReq) (err error) {
	now := time.Now()
	switch req.Action {
	case "add":
		var rels []model.TensorAssetsTagRel
		for _, objId := range req.Objs.ObjIds {
			for _, tagId := range req.TagIds {
				item := model.TensorAssetsTagRel{
					TableBase: model.TableBase{
						ID:        util.GenerateUUID(tagId, string(req.Objs.ObjType), objId),
						CreatedAt: now,
						UpdatedAt: now,
						Status:    0,
					},
					TagId:   tagId,
					ObjType: req.Objs.ObjType,
					ObjId:   objId,
				}
				rels = append(rels, item)
			}
		}
		err = rdb.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoNothing: true,
		}).Create(&rels).Error

	case "delete":
		var relIds []uint32
		for _, objId := range req.Objs.ObjIds {
			for _, tagId := range req.TagIds {
				relIds = append(relIds, util.GenerateUUID(tagId, string(req.Objs.ObjType), objId))
			}
		}
		err = rdb.WithContext(ctx).Where("id in ?", relIds).Delete(&model.TensorAssetsTagRel{}).Error

	default:
		return errors.New("not support action:" + req.Action)
	}
	return
}

func GetAssetsCustomTags(ctx context.Context, rdb *gorm.DB) ([]*model.TensorAssetsTag, error) {
	var customTags []*model.TensorAssetsTag
	err := rdb.WithContext(ctx).Model(&model.TensorAssetsTag{}).Where("type = 0").Find(&customTags).Error
	if err != nil {
		return nil, err
	}
	return customTags, nil
}

type TagRelOne struct {
	TagName string
	//ObjType model.TagRelObjType
	ObjId string
}

func GetTagsByAssetsIds(ctx context.Context, rdb *gorm.DB, objType model.TagRelObjType, objIds []string) ([]*TagRelOne, error) {
	var relList []*TagRelOne
	err := rdb.WithContext(ctx).Model(&model.TensorAssetsTagRel{}).Where("obj_type = ? and obj_id in ?", objType, objIds).
		Joins("join ivan_assets_tag t on t.id = ivan_assets_tag_rel.tag_id").Select("obj_id,name as tag_name").Scan(&relList).Error
	if err != nil {
		return nil, err
	}

	return relList, nil
}
