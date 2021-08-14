package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	VegetaDatabase   = "vegeta"
	TrueString       = "true"
	ImageTable       = "tensor_image_list"
	ImageRelateTable = "image_relate"
	ImageScanTable   = "scan_images"
)

type ScannerDalInterface interface {
	SearchImage(param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
	DeleteImage(param DeleteImageParam) error

	SearchScanLayer(param SearchScanLayerParam, filter *model.Filter) ([]model.ScanLayer, int64, error)
	SearchScanImage(param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error)
	UpdateImage(where string, updater map[string]interface{}) error
	DeleteScanImage(param DeleteScanImageParam) error

	InsertScanImage(sis []model.ScanImage) (int64, error)
	InsertAdapterImageList(im model.ImageList) (int64, error)
	SearchAssetsContainers(param SearchAssetsContainersParam, filter *model.Filter) ([]model.AssetContainer, int64, error)
	SearchRegistry(param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
	GetImageOverView(param GetImageOverViewParm) ([]ImageGroup, error)
	SearchRejectPolicy(param SearchRejectPolicyParam) ([]model.RejectPolicy, error)
	SearchRejectVuln(param SearchRejectRejectVulnParam) ([]model.RejectVuln, error)
	CreateRejectRecord(data model.RejectRecord) (*model.RejectRecord, error)

	GetScanimageFromImageList(ctx context.Context, imgId int64) (model.ScanImage, model.ImageList)

	GetTaskFromImageList(ctx context.Context, imgId int64, fromUrl string, auth string) (model.ScanTask, model.VirusScanTask, error)
	SearchScanAllStatus(ctx context.Context) harbor.ScanAllStatus
	GetVulnTotal(ctx context.Context) (int, error)
	GetVulnSeverityCount(ctx context.Context) (model.SeverityCount, error)
	GetVulnTop5(ctx context.Context) ([]model.ImageRiskScore, error)

	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)

	GetOnlineImage(parm GetOnlineImageParam) ([]OnlineImage, error)
	GetRelationImage(ctx context.Context, vulnImageLists []model.VulnImageList) ([]model.VulnDetailContainer, error)

	SetAllImagePending(ctx context.Context) error

	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail

	OverviewForInterval(interval int, intervalType string) ([]IntervalDateGroup, error)
	OverviewReasonTopN(param OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error)
	SearchRejectRecord(param SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error)
	CreateImageWhitelist(data model.ImageWhitelist) (*model.ImageWhitelist, error)
	SearchImageWhitelist(param SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error)
	UpdateImageWhitelist(where string, update map[string]interface{}) error
	DeleteImageWhitelist(param DeleteImageWhitelistParam) error

	GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error)
	AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error)
	UpdatePolicy(ctx context.Context, policy model.RejectPolicy)
	DeletePolicy(ctx context.Context, policyId int64)
	IsInRegistry(ctx context.Context, library string) bool
	GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList
	AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy)
	GetGlobalPolicyConfig(ctx context.Context) []model.RejectPolicy
}

type ScannerOrm struct {
	mongo *mongo.Client
	ctx   context.Context // 一个空的context
	psql  *gorm.DB
	log   *logging.Logger
}

func (s *ScannerOrm) UpdateImageWhitelist(where string, updater map[string]interface{}) error {
	if where == "" {
		return errors.New("no where for update condition")
	}
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ImageWhitelist)).WithContext(ctx).Where(where).Updates(updater)
	return db.Error

}

func (s *ScannerOrm) DeleteImage(param DeleteImageParam) error {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ImageList)).WithContext(ctx)
	if param.ImageId <= 0 && (param.Library == "" && param.Tags == "" && param.FullRepoName == "" && param.FromType <= 0) {
		return errors.New("no condition for delete image")
	}
	if param.ImageId > 0 {
		db = db.Where("id = ? ", param.ImageId)
	}
	if param.Library != "" {
		db = db.Where("library = ? ", param.Library)
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.Tags != "" {
		db = db.Where("tags = ? ", param.Tags)
	}
	if param.FromType > 0 {
		db = db.Where("from_type = ? ", param.FromType)
	}
	err := db.Delete(&model.ImageList{}).Error
	return err
}

func (s *ScannerOrm) DeleteScanImage(param DeleteScanImageParam) error {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ScanImage)).WithContext(ctx)
	db = db.Where("image_id = ? ", param.ImageId)
	err := db.Delete(&model.ScanImage{}).Error
	return err
}

func (s *ScannerOrm) IsInRegistry(ctx context.Context, library string) bool {
	res := s.psql.Model(model.Registry{}).Where("url = ? AND use_type!=0", library).First(&model.Registry{})
	if res.RowsAffected < 1 {
		return false
	}
	return true
}

func (s *ScannerOrm) GetScanimageFromImageList(ctx context.Context, imgId int64) (model.ScanImage, model.ImageList) {
	resScanImage := model.ScanImage{}
	s.psql.Model(model.ScanImage{}).Where("image_id = ?", imgId).First(&resScanImage)
	resImageList := model.ImageList{}
	s.psql.Model(model.ImageList{}).Where("id = ?", imgId).First(&resImageList)
	return resScanImage, resImageList
}

func (s *ScannerOrm) GetGlobalPolicyConfig(ctx context.Context) []model.RejectPolicy {
	res := []model.RejectPolicy{}
	s.psql.Model(model.RejectPolicy{}).Where("is_global = ?", true).Find(&res)
	return res
}

func (s *ScannerOrm) AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy) {
	res := s.psql.Model(&model.RejectPolicy{}).Where("is_global = ?", true).First(&model.RejectPolicy{})
	if res.RowsAffected < 1 {
		s.psql.Model(model.RejectPolicy{}).Create(&policy)
	} else {
		// fmt.Println("在更新")
		s.psql.Model(&model.RejectPolicy{}).Where("is_global = ?", true).Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
	}
	s.psql.Model(&model.RejectPolicy{}).Where("is_global = ?", false).Omit("is_global").Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
}

func (s *ScannerOrm) SearchRejectPolicy(param SearchRejectPolicyParam) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.RejectPolicy)).WithContext(ctx)
	res := make([]model.RejectPolicy, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	// 序列化
	for i := range res {
		libs := make([]string, 0)
		if err := json.Unmarshal(res[i].LibraryJSON, &libs); err == nil {
			res[i].Library = libs
		}
	}
	if param.Library != "" {
		ans := make([]model.RejectPolicy, 0)
		for i := range res {
			for j := range res[i].Library {
				if res[i].Library[j] == param.Library {
					ans = append(ans, res[i])
				}
			}
		}
		res = ans
	}
	// 自定义漏洞
	for i := range res {
		vulns, err := s.SearchRejectVuln(SearchRejectRejectVulnParam{RejectID: res[i].ID})
		if err != nil {
			s.log.WithContext(ctx).Errorf(err, "查询自定义漏洞出错")
			continue
		}
		res[i].RejectVulns = vulns
	}

	return res, nil
}

func (s *ScannerOrm) SearchRejectVuln(param SearchRejectRejectVulnParam) ([]model.RejectVuln, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.RejectVuln)).WithContext(ctx)
	if param.RejectID > 0 {
		db = db.Where("reject_policy_id = ?", param.RejectID)
	}
	res := make([]model.RejectVuln, 0)
	err := db.Find(&res).Error
	return res, err
}

func (s ScannerOrm) GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList {
	var id int64
	// 如果传了digest就先查digest
	if image.Digest != "" {
		s.psql.Model(model.ImageList{}).Select("id").
			Where("digest = ? AND library = ?", image.Digest, image.Library).First(&id)
		if id != 0 {
			image.ID = id
			return &image
		}
	}
	var ids []int64
	res := s.psql.Model(model.ImageList{}).Select("id").
		Where("full_repo_name = ? AND tags = ? AND library = ?", image.FullRepoName, image.Tags, image.Library).Order("updated_at desc").Find(&ids)
	if res.RowsAffected > 0 {
		for k := range ids {
			tmp := []model.ScanImage{}
			resScan := s.psql.Model(model.ScanImage{}).Where("image_id = ? AND status != ?", ids[k], model.ScanStatusInProgress).Find(&tmp)
			if resScan.RowsAffected > 0 {
				image.ID = ids[k]
				return &image
			}
		}
		image.ID = ids[0] // 随便返回一个，避免返回未在仓库中，后续会返回镜像未扫描的
		return &image
	}

	return nil
}

func (s ScannerOrm) DeletePolicy(ctx context.Context, policyId int64) {
	s.psql.Model(model.RejectPolicy{}).Where("id = ? ", policyId).Delete(model.RejectPolicy{})
	s.psql.Model(model.RejectVuln{}).Where("reject_policy_id = ? ", policyId).Delete(model.RejectVuln{})
}

func (s ScannerOrm) UpdatePolicy(ctx context.Context, policy model.RejectPolicy) {
	s.psql.Model(model.RejectPolicy{}).Where("id = ?", policy.ID).Updates(&policy)
	s.psql.Model(&model.RejectPolicy{}).Where("id = ?", policy.ID).Omit("is_global").Select("cicd_enable", "k8s_enable", "mode", "online_monitor", "vuln_score", "enable").Updates(&policy)
	s.psql.Model(model.RejectVuln{}).Where("reject_policy_id = ?", policy.ID).Delete(model.RejectVuln{})
	tmpVuln := []model.RejectVuln{}
	tmpVuln = policy.RejectVulns
	for k := range tmpVuln {
		tmpVuln[k].RejectPolicyID = policy.ID
	}
	s.psql.Model(model.RejectVuln{}).Create(&tmpVuln)
}

func (s ScannerOrm) AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error) {
	s.psql.Model(model.RejectPolicy{}).Create(&policy)
	tmpVuln := []model.RejectVuln{}
	tmpVuln = policy.RejectVulns
	for k := range tmpVuln {
		tmpVuln[k].RejectPolicyID = policy.ID
	}
	s.psql.Model(model.RejectVuln{}).Create(&tmpVuln)
	return policy.ID, nil
}

func (s ScannerOrm) GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error) {
	tmpPolicies := []model.RejectPolicy{}
	err := s.psql.Model(model.RejectPolicy{}).Where("deleted_at = 0 And is_global != true").Find(&tmpPolicies).Error
	if err != nil {
		return []model.RejectPolicy{}, nil
	}
	if getVuln == true {
		for k := range tmpPolicies {
			s.psql.Model(model.RejectVuln{}).Where("reject_policy_id = ?", tmpPolicies[k].ID).Find(&tmpPolicies[k].RejectVulns)
		}
	}
	return tmpPolicies, nil
}

func (s ScannerOrm) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	var imageId int
	res := s.psql.Model(model.ImageList{}).Select("id").Where("tags = ? AND library = ? AND full_repo_name = ?", tag, library, fullRepoName).First(&imageId)
	if res.RowsAffected < 1 {
		return model.SimpleImageDetail{}
	}
	resDetail := model.SimpleImageDetail{}
	tmpScanImage := model.ScanImage{}
	res = s.psql.Model(model.ScanImage{}).Select("vuln_info_json,sensitive_file_json").Where("image_id = ?", imageId).First(&tmpScanImage)
	if res.RowsAffected < 1 {
		return model.SimpleImageDetail{}
	}
	json.Unmarshal(tmpScanImage.VulnInfoJSON, &resDetail.Vulnerabilities)
	json.Unmarshal(tmpScanImage.SensitiveFileJSON, &resDetail.Vulnerabilities)
	return resDetail
}

func (s *ScannerOrm) SetAllImagePending(ctx context.Context) error {
	var ids []int64
	err := s.psql.Model(model.ImageList{}).Select("id").Find(&ids).Error //避免scan_image有数据但imagelist没有的情况
	if err != nil {
		return err
	}
	err = s.psql.Model(model.ScanImage{}).Where("status != ? AND image_id in ?", model.ScanStatusInProgress, ids).Update("status", model.ScanStatusPending).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *ScannerOrm) GetRelationImage(ctx context.Context, vulnImageLists []model.VulnImageList) ([]model.VulnDetailContainer, error) {
	type tmppodinfo struct {
		podUID         string
		podimage       string
		namespace      string
		digest         string
		full_repo_name string `gorm:"column:full_repo_name"`
		library        string `gorm:"column:library"`
		tag            string `gorm:"column:tags"`
		imageId        int
	}
	// imageInfo := chi.URLParam(r, "imageInfo")
	VulnImageLists := vulnImageLists
	// json.Unmarshal([]byte(imageInfo), &VulnImageLists)
	collection := s.mongo.Database(VegetaDatabase).Collection(new(model.AssetContainer).TableName())
	res := []model.VulnDetailContainer{}
	tmpPodInfos := []tmppodinfo{}
	for _, v := range VulnImageLists {
		tmpImagelist := model.ImageList{}
		err := s.psql.Model(model.ImageList{}).Select("tags,library,full_repo_name,digest").Limit(1).Where("id = ?", v.ImageId).Find(&tmpImagelist).Error
		if err != nil {
			continue
		}
		findOptions := options.Find().SetMaxTime(time.Second * 30)
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*30)
		defer cancelFunc()
		tmpLibrary := ""
		if strings.Contains(tmpImagelist.Library, "https://") {
			tmpLibrary = tmpImagelist.Library[8:]
		} else {
			tmpLibrary = tmpImagelist.Library
		}
		tmpImageName := tmpLibrary + "/" + tmpImagelist.FullRepoName + ":" + tmpImagelist.Tags
		filter := bson.M{"image": tmpImageName, "tag": tmpImagelist.Tags, "isDeleted": false}
		cursor, err := collection.Find(ctx, filter, findOptions)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("关联服务ERROR")
			continue
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var tmpPodInfo tmppodinfo
			var tmp model.AssetContainer
			err := cursor.Decode(&tmp)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("关联服务ERROR")
				continue
			}
			tmpPodInfo.podUID = tmp.PodUID
			tmpPodInfo.podimage = tmp.Image
			tmpPodInfo.namespace = tmp.Namespace
			tmpPodInfo.digest = tmpImagelist.Digest
			tmpPodInfo.library = tmpImagelist.Library
			tmpPodInfo.full_repo_name = tmpImagelist.FullRepoName
			tmpPodInfo.tag = tmpImagelist.Tags
			tmpPodInfo.imageId = v.ImageId
			tmpPodInfos = append(tmpPodInfos, tmpPodInfo)
		}
	}
	collectionPS := s.mongo.Database(VegetaDatabase).Collection(model.PodOwnerRefRelationCollection.String())
	for _, v := range tmpPodInfos {
		tmpContainer := model.VulnDetailContainer{}
		tmpContainer.ImageName = v.podimage
		tmpContainer.Namespace = v.namespace
		findOptions := options.Find().SetMaxTime(time.Second * 30)
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*30)
		defer cancelFunc()
		filter := bson.M{"podUid": v.podUID}
		cursor, err := collectionPS.Find(ctx, filter, findOptions)
		tmpContainer.Digest = v.digest
		tmpContainer.FullRepoName = v.full_repo_name
		tmpContainer.Library = v.library
		tmpContainer.Tag = v.tag
		tmpContainer.Id = v.imageId
		if err != nil {
			res = append(res, tmpContainer)
			logging.GetLogger().Error().Err(err).Msg("关联服务ERROR")
			continue
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var tmp model.PodOwnerRefRelation
			err := cursor.Decode(&tmp)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("关联服务ERROR")
				continue
			}
			tmpContainer.ServiceName = tmp.OwnerRefName
			res = append(res, tmpContainer)
		}
	}
	return res, nil
}

func (s *ScannerOrm) GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error) {
	tmp := model.Vuln{}
	// 取出对应vuln信息
	err := s.psql.Model(model.Vuln{}).Where("name = ?", name).Find(&tmp).Error
	if err != nil {
		return model.VulnDetail{}, err
	}
	tmpMate := model.VulnMatedata{}
	err = json.Unmarshal(tmp.MetadataJSON, &tmpMate)
	if err != nil {
		return model.VulnDetail{}, err
	}
	res := model.VulnDetail{}
	res.VulninfoApi.Name = tmp.Name
	res.VulninfoApi.Pkgname = tmp.PkgName
	res.VulninfoApi.Pkgversion = tmp.PkgVersion
	res.VulninfoApi.Severity = tmp.Severity
	res.VulninfoApi.Cvss = tmpMate.CVSS
	res.VulninfoApi.CNNVDs = tmpMate.CNNVDs
	res.VulninfoApi.Cnvd = tmpMate.CNVDs
	json.Unmarshal(tmp.LinkJSON, &res.VulninfoApi.Links)
	res.VulninfoApi.Fixedby = tmp.FixedBy
	res.VulninfoApi.Description = tmp.Description
	tmpImageID := []int{}
	tmpImageLists := []model.VulnImageList{}
	// 查询这个vuln关联的imageid
	s.psql.Model(model.VulnImage{}).Select("image_id").Where("vuln_name = ? ", name).Find(&tmpImageID)
	// 查询image具体信息
	s.psql.Model(model.ImageList{}).Select("full_repo_name,digest,library,id").Where("id IN ? ", tmpImageID).Find(&tmpImageLists)
	// 查询每一个镜像关联pod
	detailContainers, _ := s.GetRelationImage(ctx, tmpImageLists)
	res.Containers = detailContainers
	// res.VulnImageList = tmpImageLists
	return res, nil
}

func (s *ScannerOrm) SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(model.Vuln{}).Select("name,severity,pkg_name,pkg_version").Order("severity_int desc")
	if searchWord != "" {
		db = db.Where("name LIKE ?", fmt.Sprintf("%%%s%%", searchWord))
	}
	resVulnList := []model.VulnList{}
	var count int64
	err := db.Count(&count).Error
	if err != nil {
		return []model.VulnList{}, 0, err
	}
	db = model.AddFilter(db, filter)
	err = db.Find(&resVulnList).Error
	if err != nil {
		return []model.VulnList{}, 0, err
	}
	// s.psql.Model(model.Vuln{}).Select("count(*)").Find(&count)
	return resVulnList, int(count), nil
}

func (s *ScannerOrm) GetOnlineImage(param GetOnlineImageParam) ([]OnlineImage, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	res := make([]OnlineImage, 0)
	db := s.psql.WithContext(ctx)
	if err := db.Raw(param.SQL).Scan(&res).Error; err != nil {
		return nil, err
	}
	return res, nil

}

func (s *ScannerOrm) SearchScanLayer(param SearchScanLayerParam, filter *model.Filter) ([]model.ScanLayer, int64, error) {

	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()

	db := s.psql.Model(new(model.ScanLayer)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	db = db.Where("deleted_at = ? ", param.DeletedAt)
	if len(param.LayerDigests) > 0 {
		if len(param.LayerDigests) == 0 {
			db = db.Where("layer_digest = ? ", param.LayerDigests[0])
		} else {
			db = db.Where("layer_digest IN ? ", param.LayerDigests)
		}
	}
	if len(param.ImageIds) > 0 {
		if len(param.ImageIds) == 1 {
			db = db.Where("image_id = ? ", param.ImageIds[0])
		} else {
			db = db.Where("image_id IN ? ", param.ImageIds)
		}
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	res := make([]model.ScanLayer, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// serialize
	for i := range res {
		if res[i].VulnInfoJSON != nil {
			vulns := make([]model.VulnerabilityInfo, 0)
			if err := json.Unmarshal(res[i].VulnInfoJSON, &vulns); err == nil {
				res[i].VulnInfo = vulns
			} else {
				s.log.WithContext(s.ctx).Errorf(err, fmt.Sprintf("serialize VulnInfoJSON error:%s", err.Error()))
			}
		}
		if res[i].SensitiveFileJSON != nil {
			sensitives := make([]model.Sensitive, 0)
			if err := json.Unmarshal(res[i].SensitiveFileJSON, &sensitives); err == nil {
				res[i].SensitiveFile = sensitives
			} else {
				s.log.WithContext(s.ctx).Errorf(err, fmt.Sprintf("serialize SensitiveFile error:%s", err.Error()))
			}
		}
		if res[i].MaliciousInfoJSON != nil {
			malicious := make([]model.Malicious, 0)
			if err := json.Unmarshal(res[i].MaliciousInfoJSON, &malicious); err == nil {
				res[i].MaliciousInfo = malicious
			} else {
				s.log.WithContext(s.ctx).Errorf(err, fmt.Sprintf("serialize MaliciousInfo error:%s", err.Error()))
			}
		}
	}

	return res, cnt, nil
}

type newImageRiskScore []*model.ImageRiskScore

func (I newImageRiskScore) Len() int {
	return len(I)
}
func (I newImageRiskScore) Less(i, j int) bool {
	return I[i].Score > I[j].Score
}
func (I newImageRiskScore) Swap(i, j int) {
	I[i], I[j] = I[j], I[i]
}

func (s *ScannerOrm) GetVulnTop5(ctx context.Context) ([]model.ImageRiskScore, error) {

	type tmpRes struct {
		ImageID               int
		RiskScore             float64
		SeverityHistogramJSON datatypes.JSON
	}
	tmp := []tmpRes{}
	err := s.psql.Model(model.ScanImage{}).Select("scan_images.image_id,scan_images.risk_score,scan_images.severity_histogram_json").
		Joins("right join tensor_image_list on tensor_image_list.id=scan_images.id").
		Where("scan_images.status = ?", model.ScanStatusSucceeded).Limit(5).Order("scan_images.risk_score desc").Find(&tmp).Error
	if err != nil {
		return []model.ImageRiskScore{}, nil
	}
	res := []model.ImageRiskScore{}
	type tmpInfo struct {
		FullRepoName string
		Tags         string
	}
	for _, v := range tmp {
		tmpRiskScore := model.ImageRiskScore{}
		tmpInfo := tmpInfo{}
		err = s.psql.Model(model.ImageList{}).Select("full_repo_name,tags").Where("id = ?", v.ImageID).Find(&tmpInfo).Error
		if err != nil {
			continue
		}
		tmpRiskScore.Name = tmpInfo.FullRepoName
		tmpRiskScore.Score = v.RiskScore
		tmpRiskScore.Tag = tmpInfo.Tags
		tmpRiskScore.ImageId = v.ImageID
		json.Unmarshal(v.SeverityHistogramJSON, &tmpRiskScore.SeverityHistogramInfo)
		res = append(res, tmpRiskScore)
	}
	return res, nil
}

func (s *ScannerOrm) GetVulnSeverityCount(ctx context.Context) (model.SeverityCount, error) {
	tmp := []string{}
	err := s.psql.Model(model.Vuln{}).Select("severity").Scan(&tmp).Error
	if err != nil {
		return model.SeverityCount{}, err
	}
	res := model.SeverityCount{}
	for _, v := range tmp {
		if v == model.SeverityCritical {
			res.Critical += 1
		} else if v == model.SeverityHigh {
			res.High += 1
		} else if v == model.SeverityMedium {
			res.Medium += 1
		} else if v == model.SeverityLow {
			res.Low += 1
		} else if v == model.SeverityNegligible {
			res.Negligible += 1
		} else if v == model.SeverityUnknown {
			res.Unknown += 1
		}
	}
	return res, nil
}
func (s *ScannerOrm) GetVulnTotal(ctx context.Context) (int, error) {
	var total int
	err := s.psql.Model(model.Vuln{}).Select("Count(*)").Scan(&total).Error
	if err != nil {
		return 0, err
	}
	logging.GetLogger().Info().Int("Vulns total is : ", total)
	return total, nil
}

func (s *ScannerOrm) InsertScanImage(sis []model.ScanImage) (int64, error) {
	if len(sis) == 0 {
		return 0, nil
	}
	db := s.psql
	db = db.Create(&sis)
	return db.RowsAffected, db.Error
}

func (s *ScannerOrm) UpdateImage(where string, updater map[string]interface{}) error {
	if where == "" {
		return errors.New("no where")
	}
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ImageList)).WithContext(ctx).Where(where).Updates(updater)
	return db.Error
}

func (s *ScannerOrm) SearchScanAllStatus(ctx context.Context) harbor.ScanAllStatus {
	var status harbor.ScanAllStatus
	var tmpScanImage []model.ScanImage
	var total int
	var doingNum, errorNum, successNum, pendingNum int
	s.psql.Model(&model.ScanImage{}).Select("scan_images.image_id,scan_images.status").Joins("right join tensor_image_list on tensor_image_list.id=scan_images.image_id").
		Where("tensor_image_list.from_type = 1").Find(&tmpScanImage).Debug() // 可能分段查询更好,todo
	total = len(tmpScanImage)
	//s.psql.Model(&model.ImageList{}).Where("status = 0").Count(&total)
	for _, v := range tmpScanImage {
		if v.Status == "inprogress" {
			doingNum++
		} else if v.Status == "failed" {
			errorNum++
		} else if v.Status == "succeeded" {
			successNum++
		} else if v.Status == "pending" {
			pendingNum++
		}
	}
	status.Total = int(total)
	status.Completed = status.Total - doingNum
	status.Metrics.Error = errorNum
	status.Metrics.Pending = pendingNum
	status.Metrics.Running = doingNum
	status.Metrics.Success = status.Total - status.Metrics.Pending - status.Metrics.Running - status.Metrics.Error // 这个地方要和前端联调,多仓库的情况下会有部分镜像是未扫描的
	if doingNum+pendingNum == 0 {
		status.IsOngoing = false
	} else {
		status.IsOngoing = true
	}
	return status
}

func (s *ScannerOrm) GetAuthFromRegistry(ctx context.Context, url string) string {
	tmp := model.Registry{}
	res := s.psql.Where("url = ?", url).First(&tmp)
	if res.RowsAffected < 1 {
		return ""
	}
	decryPass := make([]byte, 1024)
	decryPass, err := util.DesDecrypt(tmp.Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("NewCipher Error")
		return ""
	}
	tmpStr := tmp.Username + ":" + string(decryPass)
	authByte := []byte(tmpStr)
	encodeStr := base64.StdEncoding.EncodeToString(authByte)
	authStr := "Basic " + encodeStr
	return authStr
}

func (s *ScannerOrm) GetImageID(ctx context.Context, digest string, fullRepoName string) (int64, error) {
	var tmp model.ImageList
	res := s.psql.Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.RowsAffected < 1 {
		return -1, nil
	}
	return tmp.ID, nil
}

func (s *ScannerOrm) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) {
	tmp := model.ScanImage{}
	res := s.psql.Where(&model.ScanImage{ImageId: ScanImage.ImageId}).First(&tmp)
	if res.RowsAffected < 1 {
		s.psql.Create(ScanImage)
	} else {
		s.UpdateToScanImage(ctx, ScanImage, tmp.ID)
		ScanImage.ID = tmp.ID
	}
}

func (s *ScannerOrm) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) {
	tmpImage := model.ScanImage{ID: tableID}
	s.psql.Model(tmpImage).Updates(ScanImage)
}

func (s *ScannerOrm) GetTaskFromImageList(ctx context.Context, imgId int64, fromUrl string, auth string) (model.ScanTask, model.VirusScanTask, error) {

	tmp := model.ImageList{}
	res := s.psql.Where(&model.ImageList{ID: imgId}).First(&tmp)
	if res.RowsAffected < 1 {
		return model.ScanTask{}, model.VirusScanTask{}, fmt.Errorf("未找到对应镜像记录")
	}
	authStr := s.GetAuthFromRegistry(ctx, tmp.Library)
	if authStr == "" && auth == "" {
		return model.ScanTask{}, model.VirusScanTask{}, fmt.Errorf("未找到对应仓库记录")
	} else if authStr == "" {
		authStr = auth
	}
	// return tmp, nil
	task := model.ScanTask{
		Status:        model.ScanStatusInProgress,
		StartedAt:     time.Now().Unix(),
		Repository:    tmp.FullRepoName,
		Tag:           tmp.Tags,
		URL:           tmp.Library,
		HarborURL:     "",
		Authorization: authStr,
		ImageDigest:   tmp.Digest,
	}
	// 插入待扫描的任务进postgres
	imageID := tmp.ID
	ttmp := &model.ScanImage{}
	if imageID != -1 {
		ttmp.StartedAt = time.Now().Unix()
		ttmp.ImageId = imageID
		ttmp.Status = model.ScanStatusInProgress
		s.InsertToScanImage(ctx, ttmp)
		task.ImageID = imageID
	}
	task.ID = primitive.NewObjectIDFromTimestamp(time.Now())
	task.HistoricisedTimestamp = time.Now()
	task.ImageID = tmp.ID
	task.TableID = ttmp.ID

	virustask := model.VirusScanTask{
		Status:        model.ScanStatusInProgress,
		StartedAt:     time.Now().Unix(),
		Repository:    tmp.FullRepoName,
		Tag:           tmp.Tags,
		URL:           tmp.Library,
		HarborURL:     "",
		Authorization: authStr,
		ImageDigest:   tmp.Digest,
	}
	virustask.ImageID = tmp.ID
	virustask.TableID = ttmp.ID
	return task, virustask, nil
}

func (s *ScannerOrm) SearchScanOneStatus(param SearchScanOneStatusParam, filter *model.Filter) string {
	tmp := model.ImageList{}
	res := s.psql.Where(&model.ImageList{FullRepoName: param.RepositoryName, Tags: param.Tag, Digest: param.Digest}).First(&tmp)
	if res.RowsAffected < 1 {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = s.psql.Where(&model.ScanImage{ImageId: tmp.ID}).First(&tmpScanImage)

	if res.RowsAffected < 1 {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (s *ScannerOrm) GetImageOverView(param GetImageOverViewParm) ([]ImageGroup, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	res := make([]ImageGroup, 0)
	db := s.psql.WithContext(ctx)
	if err := db.Raw(param.SQL).Scan(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) SearchScanImage(param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ScanImage)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	// 确认是是且的关系
	if param.Kind != "" {
		split := strings.Split(param.Kind, ",")
		for _, k := range split {
			if k == strconv.Itoa(model.QUESTION_VULN) {
				db = db.Where("vuln_info_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_SENSITIVE) {
				db = db.Where("sensitive_file_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_VIRUS) {
				db = db.Where("malicious_info_json is not null ")
			}
		}
	}

	if len(param.Ids) > 0 {
		if len(param.Ids) == 1 {
			db = db.Where("id = ? ", param.Ids[0])
		} else {
			db = db.Where("id IN ? ", param.Ids)
		}
	}
	if len(param.TaskIds) > 0 {
		if len(param.TaskIds) == 1 {
			db = db.Where("scan_task_id = ? ", param.TaskIds[0])
		} else {
			db = db.Where("scan_task_id IN ? ", param.TaskIds)
		}
	}
	if len(param.ImageIds) > 0 {
		if len(param.ImageIds) == 1 {
			db = db.Where("image_id = ? ", param.ImageIds[0])
		} else {
			db = db.Where("image_id IN ? ", param.ImageIds)
		}
	}
	if param.NoStatus != "" {
		db = db.Where("status != ? ", param.NoStatus)
	}
	if param.Status != "" {
		db = db.Where("status = ? ", param.Status)
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	res := make([]model.ScanImage, 0)
	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	// 序列化数据,
	if !param.NoSerialization {
		for i := range res {
			vulnInfo := make([]model.VulnerabilityInfo, 0)
			if err := json.Unmarshal(res[i].VulnInfoJSON, &vulnInfo); err == nil {
				res[i].VulnInfo = vulnInfo
				res[i].VulnInfoJSON = nil
			}

			perLayerReport := make([]model.VulnerabilityLayerReport, 0)
			if err := json.Unmarshal(res[i].PerLayerReportJSON, &perLayerReport); err == nil {
				res[i].PerLayerReport = perLayerReport
				res[i].PerLayerReportJSON = nil
			}

			severityHistogram := new(model.SeverityHistogramInfo)
			if err := json.Unmarshal(res[i].SeverityHistogramJSON, severityHistogram); err == nil {
				res[i].SeverityHistogram = *severityHistogram
				res[i].SeverityHistogramJSON = nil
			}

			sensitiveFile := make([]model.Sensitive, 0)
			if err := json.Unmarshal(res[i].SensitiveFileJSON, &sensitiveFile); err == nil {
				res[i].SensitiveFile = sensitiveFile
				res[i].SensitiveFileJSON = nil
			}

			maliciousInfo := make([]model.Malicious, 0)
			if err := json.Unmarshal(res[i].MaliciousInfoJSON, &maliciousInfo); err == nil {
				res[i].MaliciousInfo = maliciousInfo
				res[i].MaliciousInfoJSON = nil
			}
		}
	}
	return res, cnt, nil
}

func (s *ScannerOrm) SearchRegistry(param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.Registry)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	if len(param.RegistryIds) > 0 {
		if len(param.RegistryIds) == 1 {
			db = db.Where("id = ? ", param.RegistryIds[0])
		} else {
			db = db.Where("id IN ? ", param.RegistryIds)
		}
	}
	if param.LibraryUrl != "" {
		db = db.Where("url = ? ", param.LibraryUrl)
	}
	if param.UseType > 0 {
		db = db.Where("use_type = ? ", param.UseType)
	}

	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	res := make([]model.Registry, 0)
	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	// 加解密
	key := []byte("talkerss")
	for i := range res {
		decryPass := make([]byte, 1024)
		decryPass, err := util.DesDecrypt(res[i].Password, key)
		if err != nil {
			continue
		}
		res[i].PasswordString = string(decryPass)
		tmpStr := res[i].Username + ":" + string(decryPass)
		authByte := []byte(tmpStr)
		encodeStr := base64.StdEncoding.EncodeToString(authByte)
		authStr := "Basic " + encodeStr
		res[i].AuthStr = authStr
	}

	return res, cnt, nil
}

func (s *ScannerOrm) SearchImage(param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error) {
	ctx, cancelFunc := context.WithTimeout(s.ctx, time.Second*30)
	defer cancelFunc()
	db := s.psql.Model(new(model.ImageList)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	db = db.Where("status = ? ", param.Status)
	if len(param.Digests) > 0 {
		if len(param.Digests) == 1 {
			db = db.Where("digest = ? ", param.Digests[0])
		} else {
			db = db.Where("digest IN ? ", param.Digests)
		}
	}
	if len(param.Ids) > 0 {
		if len(param.Ids) == 1 {
			db = db.Where("id = ?", param.Ids[0])
		} else {
			db = db.Where("id IN ? ", param.Ids)
		}
	}
	if param.Library != "" {
		db = db.Where("library = ? ", param.Library)
	}
	if param.FullRepoSearch != "" {
		db = db.Where("full_repo_name LIKE ? ", fmt.Sprintf("%%%s%%", param.FullRepoSearch))
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.TagSearch != "" {
		db = db.Where("tags LIKE ? ", fmt.Sprintf("%%%s%%", param.TagSearch))
	}
	if param.BiggerID > 0 {
		db = db.Where("id > ?", param.BiggerID)
	}
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if param.Tag != "" {
		db = db.Where("tags = ?", param.Tag)
	}
	if param.FromType > 0 {
		db = db.Where("from_type = ? ", param.FromType)
	}
	if param.NotFromType > 0 {
		db = db.Where("from_type != ?", param.NotFromType)
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	res := make([]model.ImageList, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// serialize
	for i := range res {
		// 序列化v2
		if len(res[i].ManifestV2JSON) > 0 {
			maniFestv2 := new(model.ManifestV2)
			if err := json.Unmarshal(res[i].ManifestV2JSON, maniFestv2); err == nil {
				res[i].ManifestV2 = *maniFestv2
			} else {
				s.log.Debug().Msg(fmt.Sprintf("serialize Manifest error:%s", err.Error()))
			}
		}

		// 再序列化v1
		if len(res[i].ManifestV1JSON) > 0 {
			maniFestV1 := new(model.ManifestV1)
			if err := json.Unmarshal(res[i].ManifestV1JSON, maniFestV1); err == nil {
				res[i].ManifestV1 = *maniFestV1
				for _, his := range maniFestV1.History {
					for _, v := range his {
						hv1 := new(model.HistoryV1)
						if err := json.Unmarshal([]byte(v), hv1); err == nil {
							res[i].ManifestV1.HistoryV1 = append(res[i].ManifestV1.HistoryV1, *hv1)
						} else {
							s.log.Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.HistoryV1 error:%s", err.Error()))
						}
					}
				}
			} else {
				s.log.Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.ManifestJson error :%s", err.Error()))
			}
		}

		if len(res[i].ConfigJson) > 0 {
			configFile := new(model.ConfigFile)
			if err := json.Unmarshal(res[i].ConfigJson, configFile); err == nil {
				res[i].ConfigFile = *configFile
			} else {
				s.log.Debug().Msg(fmt.Sprintf("serialize ConfigFile error:%s", err.Error()))
			}
		}
	}

	return res, cnt, nil
}

func (s *ScannerOrm) SearchAssetsContainers(param SearchAssetsContainersParam, filter *model.Filter) ([]model.AssetContainer, int64, error) {
	// 这个查询的是mongo
	u := mongotools.Map{}
	if len(param.Digests) > 0 {
		u = u.M("digest", param.Digests, mongotools.IN)
	}
	if param.NotDeleted != "all" && param.NotDeleted != "" {
		u = u.M("isDeleted", param.NotDeleted != "true", mongotools.Equal)
	}
	collection := s.mongo.Database(VegetaDatabase).Collection(new(model.AssetContainer).TableName())
	// 先查总数
	cnt, err := collection.CountDocuments(s.ctx, u, options.Count().SetMaxTime(10*time.Second))
	if err != nil {
		return nil, 0, err
	}
	opt := options.Find().SetMaxTime(10 * time.Second)
	if filter != nil {
		if filter.PageSize > 0 {
			opt.SetLimit(filter.PageSize)
		}
		if filter.PageIndex > 0 {
			opt.SetSkip((filter.PageIndex - 1) * filter.PageSize)
		}
		if filter.SortFiled != "" && filter.SortBy != "" {
			opt.SetSort(bson.D{{filter.SortFiled, util.SortOrderToInt(filter.SortBy)}})
		}
	}

	cursor, err := collection.Find(s.ctx, u, opt)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("find error")
		return nil, cnt, err
	}
	res := make([]model.AssetContainer, 0)
	for cursor.Next(s.ctx) {
		r := new(model.AssetContainer)
		if err := cursor.Decode(r); err == nil {
			res = append(res, *r)
		}
	}

	return res, cnt, nil
}

func (s *ScannerOrm) InsertAdapterImageList(im model.ImageList) (int64, error) {
	tmp := model.ImageList{}
	res := s.psql.Where("full_repo_name=? AND digest = ? AND registry_id = ?", im.FullRepoName, im.Digest, im.RegistryId).First(&tmp)
	if res.RowsAffected < 1 {
		err := s.psql.Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := s.psql.Model(tmp).Updates(&im).Error
	return tmp.ID, err
}

func NewScannerOrm(mongo *mongo.Client, psql *gorm.DB) *ScannerOrm {
	return &ScannerOrm{
		mongo: mongo,
		ctx:   context.Background(),
		psql:  psql,
		log:   logging.GetLogger(),
	}
}
