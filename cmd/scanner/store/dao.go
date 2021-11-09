package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gorm.io/datatypes"
	"gorm.io/gorm/clause"
)

const (
	VegetaDatabase   = "vegeta"
	TrueString       = "true"
	ImageTable       = "tensor_image_list"
	ImageRelateTable = "image_relate"
	ImageContainer   = "tensor_containers"
	ImageScanTable   = "scan_images"
)

type ScannerDalInterface interface {
	SearchImage(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
	DeleteImage(ctx context.Context, param DeleteImageParam) error
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}) error
	CreateImage(ctx context.Context, data *model.ImageList) (*model.ImageList, error)
	SearchImageWithScan(ctx context.Context, param SearchImageWithScanParam, filter *model.Filter) ([]*model.ImageResponse, int64, error)

	SearchScanLayer(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]model.ScanLayer, int64, error)
	SearchScanImage(ctx context.Context, param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error)
	DeleteScanImage(ctx context.Context, param DeleteScanImageParam) error

	InsertScanImage(ctx context.Context, sis []model.ScanImage) (int64, error)
	InsertAdapterImageList(ctx context.Context, im model.ImageList) (int64, error)
	SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
	GetImageOverView(ctx context.Context, param GetImageOverViewParm) ([]ImageGroup, error)

	SearchRejectVuln(ctx context.Context, param SearchRejectRejectVulnParam) ([]model.RejectVuln, error)
	CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error)
	CreateRejectPolicy(ctx context.Context, data model.RejectPolicy) (int64, error)

	GetScanimageFromImageList(ctx context.Context, imgId int64) (model.ScanImage, model.ImageList)

	GetTaskFromImageList(ctx context.Context, imgId int64, fromUrl string, auth string) (model.ScanTask, model.VirusScanTask, error)
	SearchScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus
	GetVulnTotal(ctx context.Context) (int, error)
	GetVulnSeverityCount(ctx context.Context) (model.SeverityCount, error)
	GetVulnTop5(ctx context.Context) ([]model.ImageRiskScore, error)

	SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error)
	GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error)
	GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error)

	GetOnlineImage(ctx context.Context, parm GetOnlineImageParam) ([]OnlineImage, error)

	SetImageStatus(ctx context.Context, ids []int64, status string) error

	GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail

	OverviewForInterval(ctx context.Context, interval int, intervalType string) ([]IntervalDateGroup, error)
	OverviewReasonTopN(ctx context.Context, param OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error)
	SearchRejectRecord(ctx context.Context, param SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error)
	CreateImageWhitelist(ctx context.Context, data model.ImageWhitelist) (*model.ImageWhitelist, error)
	SearchImageWhitelist(ctx context.Context, param SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error)
	UpdateImageWhitelist(ctx context.Context, where string, update map[string]interface{}) error
	DeleteImageWhitelist(ctx context.Context, param DeleteImageWhitelistParam) error

	SearchRejectPolicy(ctx context.Context, param SearchRejectPolicyParam) ([]model.RejectPolicy, error)
	GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error)
	AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error)
	UpdatePolicy(ctx context.Context, param SearchRejectPolicyParam, updater map[string]interface{}) error
	UpdateGlobalPolicy(ctx context.Context, updater map[string]interface{}) error
	DeletePolicy(ctx context.Context, policyId int64) error
	IsInRegistry(ctx context.Context, library string) bool

	GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList
	AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy)
	GetGlobalPolicyConfig(ctx context.Context) ([]model.RejectPolicy, error)

	ScanTaskInterface
	TrustedImageInterface
}

type ScanTaskInterface interface {
	CreateTasks(ctx context.Context, tasks ...model.Task) error
	UpdateTask(ctx context.Context, task model.Task, param SearchTaskParam) error
	UpdateTasksInfo(ctx context.Context, param SearchTaskParam, updateInfo map[string]interface{}) error
	UpdateTasksStatus(ctx context.Context, updateIds []int64, status int) error
	UpdateSubTask(ctx context.Context, subtask model.SubTask) error
	GetTasks(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error)
	GetTotalTaskNum(ctx context.Context) (int64, error)
	GetImageInfo(ctx context.Context, imgId int64) (*model.ImageList, error)
	GetRegistryInfo(ctx context.Context, Id int64) (*model.Registry, error)
	AddTask(ctx context.Context, task model.Task) (int64, error)
	AddSubTask(ctx context.Context, subtask []model.SubTask) error
	GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error)

	SearchSubTasksWithScanStatus(ctx context.Context, imageIds []int64, status []int) ([]model.SubTask, error)

	UpdateTaskStatus(ctx context.Context, id int64, status uint8) error
	GetTaskList(ctx context.Context, limit, offset int) ([]*model.Task, int64, error)
	GetSubTaskListWithImage(ctx context.Context, taskId int64, limit, offset int) ([]model.SubTask, int64, error)

	GetAllScanStrategyEnv(ctx context.Context) ([]model.ScanStrategy, error)
	// GetStrategyForEnv(ctx context.Context, envName string) ([]model.ScanStrategy, error)
	SetSingleStrategy(ctx context.Context, envName string, policyId []int64) error
}

type ScannerOrm struct {
	psql *rdbtools.GormWrapper
}

func (s *ScannerOrm) SearchSubTasksWithScanStatus(ctx context.Context, imageIds []int64, status []int) ([]model.SubTask, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	in := ""
	for i := range status {
		if i == len(status)-1 {
			in = in + fmt.Sprintf("%d ", status[i])
		} else {
			in = in + fmt.Sprintf("%d, ", status[i])
		}
	}

	idin := ""
	for i := range imageIds {
		if i == len(imageIds)-1 {
			idin = idin + fmt.Sprintf("%d ", imageIds[i])
		} else {
			idin = idin + fmt.Sprintf("%d, ", imageIds[i])
		}
	}

	sql := "select  a.task_id,  a.image_id, a.status, a.created_at from tensor_scan_subtask as a where (a.image_id, a.created_at) in (select b.image_id, max(b.created_at) from tensor_scan_subtask b group by b.image_id) "

	if len(status) > 0 {
		sql = sql + fmt.Sprintf("AND a.status IN ( %s )", in)
	}
	if len(imageIds) > 0 {
		sql = sql + fmt.Sprintf("AND a.image_id IN ( %s )", idin)
	}
	sql = sql + ";"
	db := s.psql.Get().WithContext(ctx).Debug()
	res := make([]model.SubTask, 0)
	if err := db.Raw(sql).Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) CreateImage(ctx context.Context, im *model.ImageList) (*model.ImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	tmp := model.ImageList{}
	res := s.psql.Get().WithContext(ctx).Where("full_repo_name = ? AND tags = ? AND from_type = ? AND registry_id = ?", im.FullRepoName, im.Tags, im.FromType, im.RegistryId).First(&tmp)
	if res.Error != nil {
		err := s.psql.Get().WithContext(ctx).Create(im).Error
		return im, err
	}

	err := s.psql.Get().WithContext(ctx).Model(tmp).Updates(im).Error
	im.ID = tmp.ID
	return im, err
}

type ImageListWithScan struct {
	ID             int64     `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	FullRepoName   string    `json:"full_repo_name"`
	Tags           string    `json:"tags"`
	Digest         string    `json:"digest"`
	OS             string    `json:"os"`
	Library        string    `json:"library"`
	ImageUUID      uint32    `json:"image_uuid"`
	CompleteTime   string    `json:"complete_time"`
	RegistryId     int64     `json:"registry_id"`
	FromType       int64     `json:"from_type"`
	NodeIp         string    `json:"node_ip"`
	NodeHostname   string    `json:"node_hostname"`
	ImageType      int64     `json:"image_type"`
	IsReinforce    int64     `json:"is_reinforce"`
	PrivilegedBoot int64     `json:"privileged_boot"`
	HasFixedVuln   int64     `json:"has_fixed_vuln"`
}

// SearchImageWithScan scan_list和scan_image join搜索
func (s *ScannerOrm) SearchImageWithScan(ctx context.Context, param SearchImageWithScanParam, filter *model.Filter) ([]*model.ImageResponse, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := make([]ImageListWithScan, 0)
	db := s.psql.Get().WithContext(ctx).Model(new(model.ImageList)).Joins("left join scan_images on tensor_image_list.id=scan_images.image_id").Debug()

	if param.SearchWord != "" {
		if param.FromType == model.ImageFromTypeNormal {
			db = db.Where("tensor_image_list.full_repo_name LIKE ? OR tensor_image_list.tags LIKE ? ", fmt.Sprintf("%%%s%%", param.SearchWord), fmt.Sprintf("%%%s%%", param.SearchWord))
		} else if param.FromType == model.RegistryUseSafeNode {
			db = db.Where("tensor_image_list.node_hostname LIKE ?  ", fmt.Sprintf("%%%s%%", param.SearchWord))
		}
	}

	if param.ImageType != "" {
		if param.ImageType == consts.BaseImageTypeString {
			db = db.Where("tensor_image_list.image_type = 1 ")
		} else if param.ImageType == consts.AppImageTypeString {
			db = db.Where("tensor_image_list.image_type = 0 ")
		}
	}

	if param.Kind != "" {
		split := strings.Split(param.Kind, ",")
		for _, k := range split {
			if k == strconv.Itoa(model.QUESTION_VULN) {
				db = db.Where("scan_images.vuln_score != 0 ")
			}
			if k == strconv.Itoa(model.QUESTION_SENSITIVE) {
				db = db.Where("scan_images.sensitive_file_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_VIRUS) {
				db = db.Where("scan_images.malicious_info_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_WEB_SHELL) {
				db = db.Where("scan_images.webshell_info_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_SOFTWARE) {
				db = db.Where("scan_images.software_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_ENV) {
				db = db.Where("scan_images.env_json is not null ")
			}
			if k == strconv.Itoa(model.QUESTION_PRIORITY) {
				db = db.Where("tensor_image_list.privileged_boot = ?", consts.PrivilegedBootImage)
			}

			if k == strconv.Itoa(model.QUESTION_LICENSE) {
				db = db.Where("scan_images.license_info_json is not null ")
			}
		}
	}

	if param.FromType > 0 {
		db = db.Where("tensor_image_list.from_type = ? ", param.FromType)
	}

	if len(param.InIDs) > 0 {
		db = db.Where("tensor_image_list.id  IN ? ", param.InIDs)
	}

	if len(param.NotInIDs) > 0 {
		db = db.Where("tensor_image_list.id  NOT IN ? ", param.NotInIDs)
	}
	if len(param.InDigests) > 0 {
		db = db.Where("tensor_image_list.digest  IN ? ", param.InDigests)
	}

	if len(param.NotInDigests) > 0 {
		db = db.Where("tensor_image_list.digest  NOT IN ? ", param.NotInDigests)
	}
	if param.HasFixedVulu == consts.HasFixedvulnStringd {
		db = db.Where("scan_images.has_fixed_vuln =  ? ", consts.HasFixedvuln)
	} else if param.HasFixedVulu == consts.NotHasFixedvulnString {
		db = db.Where("scan_images.has_fixed_vuln =  ? ", consts.NotHasFixedvuln)
	}

	if param.IsReinforce == consts.IsReinforceImageString {
		db = db.Where("tensor_image_list.is_reinforce =  ? ", consts.IsReinforceImage)
	} else if param.IsReinforce == consts.IsNotReinforceImageString {
		db = db.Where("tensor_image_list.is_reinforce =  ? ", consts.IsNotReinforceImage)
	}

	if param.FromType == model.ImageFromSafeNode && param.NodeHostname != "" {
		db = db.Where("tensor_image_list.node_hostname =  ? ", param.NodeHostname)
	}

	fields := []string{"tensor_image_list.id", "tensor_image_list.privileged_boot", "tensor_image_list.created_at", "tensor_image_list.full_repo_name",
		"tensor_image_list.tags", "tensor_image_list.digest", "tensor_image_list.os", "tensor_image_list.library",
		"tensor_image_list.image_uuid", "tensor_image_list.complete_time", "scan_images.status", "scan_images.has_fixed_vuln", "tensor_image_list.is_reinforce",
		"tensor_image_list.registry_id", "tensor_image_list.from_type",
		"tensor_image_list.node_ip", "tensor_image_list.node_hostname", "tensor_image_list.image_type"}

	db = db.Select(fields)

	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	ans := make([]*model.ImageResponse, 0)
	for i := range res {
		ir := model.ImageResponse{
			ID:             res[i].ID,
			Digest:         res[i].Digest,
			Library:        res[i].Library,
			NodeIp:         res[i].NodeIp,
			CompleteTime:   res[i].CompleteTime,
			FullRepoName:   res[i].FullRepoName,
			Tags:           res[i].Tags,
			ImageType:      res[i].ImageType,
			RegistryId:     res[i].RegistryId,
			FromType:       res[i].FromType,
			HasFixedVulu:   res[i].HasFixedVuln,
			Os:             res[i].OS,
			NodeHostname:   res[i].NodeHostname,
			IsReinforce:    res[i].IsReinforce,
			PrivilegedBoot: res[i].PrivilegedBoot,
		}
		if ir.CompleteTime == "" {
			ir.CompleteTime = res[i].CreatedAt.Format("2006-01-02 15:04:05")
		}

		ans = append(ans, &ir)
	}

	return ans, cnt, nil
}
func (s *ScannerOrm) CreateRejectPolicy(ctx context.Context, data model.RejectPolicy) (int64, error) {
	if len(data.EnvsJson) == 0 && len(data.Envs) > 0 {
		bys, err := json.Marshal(data.Envs)
		if err == nil {
			data.EnvsJson = string(bys)
		} else {
			logging.GetLogger().Error().Err(err).Msg("CreateRejectPolicy")
		}
	}

	if len(data.SensitiveFileJson) == 0 && len(data.SensitiveFile) > 0 {
		bys, err := json.Marshal(data.SensitiveFile)
		if err == nil {
			data.SensitiveFileJson = string(bys)
		} else {
			logging.GetLogger().Error().Err(err).Msg("CreateRejectPolicy")
		}
	}

	if len(data.Library) > 0 && len(data.LibraryJSON) == 0 {
		bytes, err := json.Marshal(data.Library)
		if err != nil {
			return 0, err
		}
		data.LibraryJSON = bytes
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := s.psql.Get().WithContext(ctx).Model(new(model.RejectPolicy)).Create(&data).Error; err != nil {
		return 0, err
	}
	// 自定义漏洞
	if len(data.RejectVulns) > 0 && !data.IsGlobal {
		tmpVuln := data.RejectVulns
		for k := range tmpVuln {
			tmpVuln[k].RejectPolicyID = data.ID
		}
		if err := s.psql.Get().WithContext(ctx).Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
			return 0, err
		}
	}
	return data.ID, nil
}

func NewScannerOrm(psql *rdbtools.GormWrapper) *ScannerOrm {
	return &ScannerOrm{
		psql: psql,
	}
}

func (s *ScannerOrm) GetImage(ctx context.Context, param GetImageParam) (*model.ImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ImageList)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	db = db.Where("status = ? ", param.Status)
	if param.Digest != "" {
		db = db.Where("digest = ? ", param.Digest)
	}
	if param.Id > 0 {
		db = db.Where("id = ?", param.Id)
	}
	if param.Library != "" {
		db = db.Where("library = ? ", param.Library)
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
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

	res := new(model.ImageList)
	if err := db.First(&res).Error; err != nil {
		return nil, err
	}
	// serialize
	// 序列化v2
	if len(res.ManifestV2JSON) > 0 {
		maniFestv2 := new(model.ManifestV2)
		if err := json.Unmarshal(res.ManifestV2JSON, maniFestv2); err == nil {
			res.ManifestV2 = *maniFestv2
		} else {
			logging.GetLogger().Debug().Msg(fmt.Sprintf("serialize Manifest error:%s", err.Error()))
		}
	}

	// 再序列化v1
	if len(res.ManifestV1JSON) > 0 {
		maniFestV1 := new(model.ManifestV1)
		if err := json.Unmarshal(res.ManifestV1JSON, maniFestV1); err == nil {
			res.ManifestV1 = *maniFestV1
			for _, his := range maniFestV1.History {
				for _, v := range his {
					hv1 := new(model.HistoryV1)
					if err := json.Unmarshal([]byte(v), hv1); err == nil {
						res.ManifestV1.HistoryV1 = append(res.ManifestV1.HistoryV1, *hv1)
					} else {
						logging.GetLogger().Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.HistoryV1 error:%s", err.Error()))
					}
				}
			}
		} else {
			logging.GetLogger().Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.ManifestJson error :%s", err.Error()))
		}
	}

	if len(res.ConfigJson) > 0 {
		configFile := new(model.ConfigFile)
		if err := json.Unmarshal(res.ConfigJson, configFile); err == nil {
			res.ConfigFile = *configFile
		} else {
			logging.GetLogger().Debug().Msg(fmt.Sprintf("serialize ConfigFile error:%s", err.Error()))
		}
	}
	return res, nil
}

func (s *ScannerOrm) UpdateImageWhitelist(ctx context.Context, where string, updater map[string]interface{}) error {
	if where == "" {
		return errors.New("no where for update condition")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ImageWhitelist)).WithContext(ctx).Where(where).Updates(updater)
	return db.Error

}

func (s *ScannerOrm) DeleteImage(ctx context.Context, param DeleteImageParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ImageList)).WithContext(ctx)
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

func (s *ScannerOrm) DeleteScanImage(ctx context.Context, param DeleteScanImageParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ScanImage)).WithContext(ctx)
	db = db.Where("image_id = ? ", param.ImageId)
	err := db.Delete(&model.ScanImage{}).Error
	return err
}

func (s *ScannerOrm) IsInRegistry(ctx context.Context, library string) bool {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	res := s.psql.Get().WithContext(ctx).Model(model.Registry{}).Where("url = ? AND use_type!=0", library).First(&model.Registry{})
	return res.Error == nil
}

func (s *ScannerOrm) GetScanimageFromImageList(ctx context.Context, imgId int64) (model.ScanImage, model.ImageList) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	resScanImage := model.ScanImage{}
	s.psql.Get().WithContext(ctx).Model(model.ScanImage{}).Where("image_id = ?", imgId).First(&resScanImage)
	resImageList := model.ImageList{}
	s.psql.Get().Model(model.ImageList{}).Where("id = ?", imgId).First(&resImageList)
	return resScanImage, resImageList
}

func (s *ScannerOrm) GetGlobalPolicyConfig(ctx context.Context) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	res := []model.RejectPolicy{}
	err := s.psql.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("is_global = ?", true).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	res := s.psql.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", true).First(&model.RejectPolicy{})
	if res.Error != nil {
		s.psql.Get().WithContext(ctx).Model(model.RejectPolicy{}).Create(&policy)
	} else {
		s.psql.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", true).Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
	}
	s.psql.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", false).Omit("is_global").Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
}

func (s *ScannerOrm) SearchRejectPolicy(ctx context.Context, param SearchRejectPolicyParam) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.RejectPolicy)).WithContext(ctx)
	res := make([]model.RejectPolicy, 0)
	if param.Global == consts.TrueString {
		db = db.Where("is_global = ? ", true)
	}
	if param.Global == consts.FalseString {
		db = db.Where("is_global = ?", false)
	}

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	// 序列化
	for i := range res {
		libs := make([]string, 0)
		if len(res[i].LibraryJSON) > 0 {
			if err := json.Unmarshal(res[i].LibraryJSON, &libs); err == nil {
				res[i].Library = libs
			}
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
		vulns, err := s.SearchRejectVuln(ctx, SearchRejectRejectVulnParam{RejectID: res[i].ID})
		if err != nil {
			logging.GetLogger().Err(err).Msg("Error querying custom vulnerabilities")
			continue
		}
		res[i].RejectVulns = vulns
	}
	// 自定义异常文件
	for i := range res {
		if len(res[i].SensitiveFileJson) > 0 {
			ses := make([]model.SensitiveFilePolicy, 0)
			if err := json.Unmarshal([]byte(res[i].SensitiveFileJson), &ses); err == nil {
				res[i].SensitiveFile = ses
			} else {
				logging.GetLogger().Error().Err(err).Msg("SearchRejectPolicy")
			}
		}

		if len(res[i].EnvsJson) > 0 {
			ses := make([]string, 0)
			if err := json.Unmarshal([]byte(res[i].EnvsJson), &ses); err == nil {
				res[i].Envs = ses
			} else {
				logging.GetLogger().Error().Err(err).Msg("SearchRejectPolicy")
			}
		}
	}

	return res, nil
}

func (s *ScannerOrm) SearchRejectVuln(ctx context.Context, param SearchRejectRejectVulnParam) ([]model.RejectVuln, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.RejectVuln)).WithContext(ctx)
	if param.RejectID > 0 {
		db = db.Where("reject_policy_id = ?", param.RejectID)
	}
	res := make([]model.RejectVuln, 0)
	err := db.Find(&res).Error
	return res, err
}

func (s ScannerOrm) GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	var id int64
	// 如果传了digest就先查digest
	if image.Digest != "" {
		s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").
			Where("digest = ? AND library = ?", image.Digest, image.Library).First(&id)
		if id != 0 {
			image.ID = id
			return &image
		}
	}
	var ids []int64
	res := s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").
		Where("full_repo_name = ? AND tags = ? AND library = ?", image.FullRepoName, image.Tags, image.Library).Order("updated_at desc").Find(&ids)
	if res.Error == nil && len(ids) > 0 {
		for k := range ids {
			tmp := []model.ScanImage{}
			resScan := s.psql.Get().Model(model.ScanImage{}).Where("image_id = ? AND status != ?", ids[k], model.ScanStatusInProgress).Find(&tmp)
			if resScan.Error == nil {
				image.ID = ids[k]
				return &image
			}
		}
		image.ID = ids[0] // 随便返回一个，避免返回未在仓库中，后续会返回镜像未扫描的
		return &image
	}

	return nil
}

func (s ScannerOrm) DeletePolicy(ctx context.Context, policyId int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := s.psql.Get().WithContext(ctx).Model(model.RejectVuln{}).Where("reject_policy_id = ? ", policyId).Delete(model.RejectVuln{}).Error; err != nil {
		return err
	}
	if err := s.psql.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("id = ? ", policyId).Delete(model.RejectPolicy{}).Error; err != nil {
		return err
	}
	return nil

}

func (s ScannerOrm) UpdatePolicy(ctx context.Context, param SearchRejectPolicyParam, updater map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().Model(new(model.RejectPolicy)).Omit("is_global")
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.Global == consts.TrueString {
		db = db.Where("is_global = ?", true)
		// .Select("cicd_enable", "k8s_enable", "mode", "online_monitor")
	}
	if param.Global == consts.FalseString {
		db = db.Where("is_global = ?", false)
	}

	if err := db.Updates(updater).Error; err != nil {
		return err
	}

	// 更新自定义漏洞
	if param.UpdateRejectVulns && param.ID > 0 {
		if err := s.psql.Get().WithContext(ctx).Model(model.RejectVuln{}).Where("reject_policy_id = ? ", param.ID).Delete(model.RejectVuln{}).Error; err != nil {
			return err
		}
		tmpVuln := param.RejectVulns
		for k := range tmpVuln {
			tmpVuln[k].RejectPolicyID = param.ID
		}
		if len(tmpVuln) > 0 { // 不判断会报错： empty slice found
			if err := s.psql.Get().Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// UpdateGlobalPolicy 更新全局策略时更新整张表
func (s ScannerOrm) UpdateGlobalPolicy(ctx context.Context, updater map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.RejectPolicy)).Omit("is_global").WithContext(ctx)
	// begin a transaction
	tx := db.Begin()

	// do some database operations in the transaction (use 'tx' from this point, not 'db')
	if err := tx.Where("is_global = ?  ", true).Updates(updater).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Where("is_global = ?  ", false).Updates(updater).Error; err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func (s ScannerOrm) AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	if err := s.psql.Get().WithContext(ctx).Model(model.RejectPolicy{}).Create(&policy).Error; err != nil {
		return 0, err
	}
	tmpVuln := policy.RejectVulns
	for k := range tmpVuln {
		tmpVuln[k].RejectPolicyID = policy.ID
	}
	if err := s.psql.Get().WithContext(ctx).Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
		return 0, err
	}
	return policy.ID, nil
}

func (s ScannerOrm) GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmpPolicies := []model.RejectPolicy{}
	err := s.psql.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("deleted_at = 0 And is_global != true").Find(&tmpPolicies).Error
	if err != nil {
		return []model.RejectPolicy{}, nil
	}
	if getVuln {
		for k := range tmpPolicies {
			s.psql.Get().Model(model.RejectVuln{}).Where("reject_policy_id = ?", tmpPolicies[k].ID).Find(&tmpPolicies[k].RejectVulns)
		}
	}
	return tmpPolicies, nil
}

func (s ScannerOrm) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	var imageId int
	var librarys []string
	librarys = append(librarys, library)
	librarys = append(librarys, "http://"+library)
	librarys = append(librarys, "https://"+library)
	res := s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").Where("tags = ? AND library In ? AND full_repo_name = ?", tag, librarys, fullRepoName).First(&imageId)
	if res.Error != nil {
		return model.SimpleImageDetail{}
	}
	resDetail := model.SimpleImageDetail{}
	tmpScanImage := model.ScanImage{}
	res = s.psql.Get().WithContext(ctx).Model(model.ScanImage{}).Select("vuln_info_json,sensitive_file_json").Where("image_id = ?", imageId).First(&tmpScanImage)
	if res.Error != nil {
		return model.SimpleImageDetail{}
	}
	if len(tmpScanImage.VulnInfoJSON) > 0 {
		if err := json.Unmarshal(tmpScanImage.VulnInfoJSON, &resDetail.Vulnerabilities); err != nil {
			logging.GetLogger().Err(err).Msg("json.Unmarshal Vulnerabilities")
		}
	}
	if len(tmpScanImage.SensitiveFileJSON) > 0 {
		if err := json.Unmarshal(tmpScanImage.SensitiveFileJSON, &resDetail.Sensitives); err != nil {
			logging.GetLogger().Err(err).Msg("json.Unmarshal Vulnerabilities SensitiveFileJSON")
		}
	}
	return resDetail
}

func (s *ScannerOrm) SetImageStatus(ctx context.Context, ids []int64, status string) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().WithContext(ctx).Model(model.ScanImage{}).Where("status != ?", model.ScanStatusInProgress)
	if len(ids) > 0 {
		db = db.Where("image_id IN ?", ids)
	}

	err := db.Update("status", status).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *ScannerOrm) GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	tmpImageID := []int{}
	resImageLists := []model.VulnImageList{}
	// 查询这个vuln关联的imageid
	err := s.psql.Get().WithContext(ctx).Model(model.VulnImage{}).Select("image_id").Where("vuln_name = ? ", name).Find(&tmpImageID).Error
	if err != nil {
		return resImageLists, err
	}
	// 查询image具体信息
	err = s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Select("full_repo_name,digest,library,id,tags").Where("id IN ? ", tmpImageID).Find(&resImageLists).Error
	return resImageLists, err
}

func (s *ScannerOrm) GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	tmp := model.Vuln{}
	// 取出对应vuln信息
	err := s.psql.Get().WithContext(ctx).Model(model.Vuln{}).Where("name = ?", name).Find(&tmp).Error
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
	if len(tmp.LinkJSON) > 0 {
		if err := json.Unmarshal(tmp.LinkJSON, &res.VulninfoApi.Links); err != nil {
			logging.GetLogger().Err(err).Msg("json.Unmarshal LinkJSON")
		}
	}

	res.VulninfoApi.Fixedby = tmp.FixedBy
	res.VulninfoApi.Description = tmp.Description
	tmpImageID := make([]int, 0)
	tmpImageLists := make([]model.VulnImageList, 0)
	// 查询这个vuln关联的imageid
	s.psql.Get().WithContext(ctx).Model(model.VulnImage{}).Select("image_id").Where("vuln_name = ? ", name).Find(&tmpImageID)
	// 查询image具体信息
	s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Select("full_repo_name,digest,library,id").Where("id IN ? ", tmpImageID).Find(&tmpImageLists)
	return res, nil
}

func (s *ScannerOrm) SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().WithContext(ctx).Model(model.Vuln{}).Select("name,severity,pkg_name,pkg_version").Order("severity_int desc")
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
	return resVulnList, int(count), nil
}

func (s *ScannerOrm) GetOnlineImage(ctx context.Context, param GetOnlineImageParam) ([]OnlineImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	res := make([]OnlineImage, 0)
	db := s.psql.Get().WithContext(ctx)
	if err := db.Raw(param.SQL).Scan(&res).Error; err != nil {
		return nil, err
	}
	return res, nil

}

func (s *ScannerOrm) SearchScanLayer(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]model.ScanLayer, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(new(model.ScanLayer)).WithContext(ctx)
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
			vulns := make([]model.SingleScanDetail, 0)
			if err := json.Unmarshal(res[i].VulnInfoJSON, &vulns); err == nil {
				res[i].VulnInfo = vulns
			} else {
				logging.GetLogger().Error().Err(err).Msg("serialize VulnInfoJSON")
			}
		}
		if len(res[i].SensitiveFileJSON) > 0 {
			sensitives := make([]model.Sensitive, 0)
			if err := json.Unmarshal(res[i].SensitiveFileJSON, &sensitives); err == nil {
				res[i].SensitiveFile = sensitives
			} else {
				logging.GetLogger().Error().Err(err).Msg("serialize SensitiveFile")
			}
		}
		if len(res[i].MaliciousInfoJSON) > 0 {
			malicious := make([]model.Malicious, 0)
			if err := json.Unmarshal(res[i].MaliciousInfoJSON, &malicious); err == nil {
				res[i].MaliciousInfo = malicious
			} else {
				logging.GetLogger().Error().Err(err).Msg("serialize MaliciousInfo")
			}
		}
		if len(res[i].WebshellInfoJSON) > 0 {
			webshell := make([]model.Webshell, 0)
			if err := json.Unmarshal(res[i].WebshellInfoJSON, &webshell); err == nil {
				res[i].WebshellInfo = webshell
			} else {
				logging.GetLogger().Error().Err(err).Msg("serialize WebshellInfoJSON")
			}
		}
	}

	return res, cnt, nil
}

func (s *ScannerOrm) GetVulnTop5(ctx context.Context) ([]model.ImageRiskScore, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	type tmpRes struct {
		ImageID               int     `json:"image_id"`
		ImageType             int64   `json:"image_type"`
		VulnScore             float64 `json:"vuln_score"`
		SeverityHistogramJSON datatypes.JSON
		// FromType              int64  `json:"from_type"`
		// NodeIp                string `json:"node_ip"`       // 结点的Ip
		// NodeHostname          string `json:"node_hostname"` // 结点的
		// Os                    string `json:"os"`
	}
	// tensor_image_list.image_type,tensor_image_list.from_type,tensor_image_list.node_ip,tensor_image_list.node_hostname,tensor_image_list.os").

	tmp := []tmpRes{}
	err := s.psql.Get().WithContext(ctx).Model(model.ScanImage{}).Select("scan_images.image_id,scan_images.vuln_score,scan_images.severity_histogram_json").
		Joins("join tensor_image_list on tensor_image_list.id=scan_images.image_id").
		Where("scan_images.status = ?", model.ScanStatusSucceeded).Limit(5).Order("scan_images.vuln_score desc").Find(&tmp).Error
	if err != nil {
		return []model.ImageRiskScore{}, nil
	}
	res := make([]model.ImageRiskScore, 0)
	for _, v := range tmp {
		tmpRiskScore := model.ImageRiskScore{}
		tmpInfo := new(model.ImageList)
		err = s.psql.Get().WithContext(ctx).Model(model.ImageList{}).Where("id = ?", v.ImageID).Find(&tmpInfo).Error
		if err != nil {
			continue
		}
		tmpRiskScore.ImageType = tmpInfo.ImageType
		tmpRiskScore.FromType = tmpInfo.FromType
		tmpRiskScore.Name = tmpInfo.FullRepoName
		tmpRiskScore.Score = v.VulnScore
		tmpRiskScore.Tag = tmpInfo.Tags
		tmpRiskScore.ImageId = v.ImageID
		tmpRiskScore.ImageType = v.ImageType
		if len(v.SeverityHistogramJSON) > 0 {
			if err := json.Unmarshal(v.SeverityHistogramJSON, &tmpRiskScore.SeverityHistogramInfo); err != nil {
				logging.GetLogger().Err(err).Msg("json.Unmarshal SeverityHistogramInfo")
			}
		}
		if tmpInfo.FromType == model.ImageFromSafeNode {
			// hostname + ip + 镜像名就可以了
			// tensorsecurity/clusterKey/namespace/podName/linux/registry.t-appagile.com/google_containers/coredns
			split := strings.Split(tmpRiskScore.Name, "/")
			if len(split) <= 6 {
				continue
			}
			tmpRiskScore.Name = fmt.Sprintf("%s-%s-%s", tmpInfo.NodeHostname, tmpInfo.NodeIp, strings.Join(split[5:], "/"))
		}
		res = append(res, tmpRiskScore)
	}
	return res, nil
}

func (s *ScannerOrm) GetVulnSeverityCount(ctx context.Context) (model.SeverityCount, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	tmp := []string{}
	err := s.psql.Get().WithContext(ctx).Model(model.Vuln{}).Select("severity").Scan(&tmp).Error
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
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var total int
	err := s.psql.Get().WithContext(ctx).Model(model.Vuln{}).Select("Count(*)").Scan(&total).Error
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (s *ScannerOrm) InsertScanImage(ctx context.Context, sis []model.ScanImage) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	if len(sis) == 0 {
		return 0, nil
	}
	db := s.psql.Get().WithContext(ctx).Create(&sis)
	return db.RowsAffected, db.Error
}

func (s *ScannerOrm) UpdateImage(ctx context.Context, where string, updater map[string]interface{}) error {
	if where == "" {
		return errors.New("no where")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ImageList)).WithContext(ctx).Where(where).Updates(updater)
	return db.Error
}

func (s *ScannerOrm) SearchScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var status harbor.ScanAllStatus
	var tmpScanImage []model.ScanImage
	var total int
	var doingNum, errorNum, successNum, pendingNum int
	s.psql.Get().WithContext(ctx).Model(&model.ScanImage{}).Select("scan_images.image_id,scan_images.status").Joins("join tensor_image_list on tensor_image_list.id=scan_images.image_id").
		Where(fmt.Sprintf("tensor_image_list.from_type = %d and scan_images.id >0", fromType)).Find(&tmpScanImage) // 可能分段查询更好,todo
	total = len(tmpScanImage)
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

func (s *ScannerOrm) GetAuthFromRegistry(ctx context.Context, registryID int64) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmp := model.Registry{}
	res := s.psql.Get().WithContext(ctx).Where("id = ?", registryID).First(&tmp)
	if res.Error != nil {
		return ""
	}
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
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var tmp model.ImageList
	res := s.psql.Get().WithContext(ctx).Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.Error != nil {
		return -1, nil
	}
	return tmp.ID, nil
}

func (s *ScannerOrm) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.ScanImage{}
	res := s.psql.Get().WithContext(ctx).Where(&model.ScanImage{ImageId: ScanImage.ImageId}).First(&tmp)
	if res.Error != nil {
		err := s.psql.Get().Create(ScanImage).Error
		if err != nil {
			return err
		}
	} else {
		err := s.UpdateToScanImage(ctx, ScanImage, tmp.ID)
		ScanImage.ID = tmp.ID
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ScannerOrm) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	tmpImage := model.ScanImage{ID: tableID}
	err := s.psql.Get().WithContext(ctx).Model(tmpImage).Updates(ScanImage).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *ScannerOrm) GetTaskFromImageList(ctx context.Context, imgId int64, fromUrl string, auth string) (model.ScanTask, model.VirusScanTask, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.ImageList{}
	if err := s.psql.Get().WithContext(ctx).Where("id = ? ", imgId).First(&tmp).Error; err != nil {
		return model.ScanTask{}, model.VirusScanTask{}, fmt.Errorf("未找到对应镜像记录: %+v", err)
	}
	// 支持多仓库，而且有节点镜像，所以这里的URL最好通过regestryID去查
	logging.GetLogger().Info().Msgf("GetTaskFromImageList:Tem:%+v", tmp)
	regs, _, err := s.SearchRegistry(ctx, SearchRegistryParam{Id: tmp.RegistryId}, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("GetTaskFromImageList imageID:%d,regestryId:%d", imgId, tmp.RegistryId)
		return model.ScanTask{}, model.VirusScanTask{}, err
	}
	if len(regs) == 0 {
		logging.GetLogger().Info().Msgf("GetTaskFromImageList not find registry imageID:%d,registryId:%d", imgId, tmp.RegistryId)
		return model.ScanTask{}, model.VirusScanTask{}, fmt.Errorf("not find registry")
	}

	// return tmp, nil
	task := model.ScanTask{
		Status:        model.ScanStatusInProgress,
		StartedAt:     time.Now().Unix(),
		Repository:    tmp.FullRepoName,
		Tag:           tmp.Tags,
		URL:           regs[0].Url,
		HarborURL:     "",
		Authorization: regs[0].AuthStr,
		ImageDigest:   tmp.Digest,
	}
	// 插入待扫描的任务进postgres
	imageID := tmp.ID
	ttmp := &model.ScanImage{}
	if imageID != -1 {
		ttmp.StartedAt = time.Now().Unix()
		ttmp.ImageId = imageID
		ttmp.Status = model.ScanStatusInProgress
		err := s.InsertToScanImage(ctx, ttmp)
		if err != nil {
			return model.ScanTask{}, model.VirusScanTask{}, err
		}
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
		URL:           regs[0].AuthStr,
		HarborURL:     "",
		Authorization: regs[0].Url,
		ImageDigest:   tmp.Digest,
	}
	virustask.ImageID = tmp.ID
	virustask.TableID = ttmp.ID
	return task, virustask, nil
}

func (s *ScannerOrm) SearchScanOneStatus(ctx context.Context, param SearchScanOneStatusParam, filter *model.Filter) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	tmp := model.ImageList{}
	res := s.psql.Get().WithContext(ctx).Where(&model.ImageList{FullRepoName: param.RepositoryName, Tags: param.Tag, Digest: param.Digest}).First(&tmp)
	if res.Error != nil {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = s.psql.Get().WithContext(ctx).Where(&model.ScanImage{ImageId: tmp.ID}).First(&tmpScanImage)
	if res.Error != nil {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (s *ScannerOrm) GetImageOverView(ctx context.Context, param GetImageOverViewParm) ([]ImageGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	res := make([]ImageGroup, 0)
	db := s.psql.Get().WithContext(ctx)
	if err := db.Raw(param.SQL).Scan(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) SearchScanImage(ctx context.Context, param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ScanImage)).WithContext(ctx)
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
			if k == strconv.Itoa(model.QUESTION_WEB_SHELL) {
				db = db.Where("webshell_info_json is not null ")
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
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
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
	for i := range res {
		vulnInfo := make([]model.SingleScanDetail, 0)
		if len(res[i].VulnInfoJSON) > 0 {
			if err := json.Unmarshal(res[i].VulnInfoJSON, &vulnInfo); err == nil {
				res[i].VulnInfo = vulnInfo
			}
		}

		perLayerReport := make([]model.VulnerabilityLayerReport, 0)
		if len(res[i].PerLayerReportJSON) > 0 {
			if err := json.Unmarshal(res[i].PerLayerReportJSON, &perLayerReport); err == nil {
				res[i].PerLayerReport = perLayerReport
			}
		}

		severityHistogram := new(model.SeverityHistogramInfo)
		if len(res[i].SeverityHistogramJSON) > 0 {
			if err := json.Unmarshal(res[i].SeverityHistogramJSON, severityHistogram); err == nil {
				res[i].SeverityHistogram = *severityHistogram
			}
		}

		sensitiveFile := make([]model.Sensitive, 0)
		if len(res[i].SensitiveFileJSON) > 0 {
			if err := json.Unmarshal(res[i].SensitiveFileJSON, &sensitiveFile); err == nil {
				res[i].SensitiveFile = sensitiveFile
			}
		}

		maliciousInfo := make([]model.Malicious, 0)
		if len(res[i].MaliciousInfoJSON) > 0 {
			if err := json.Unmarshal(res[i].MaliciousInfoJSON, &maliciousInfo); err == nil {
				res[i].MaliciousInfo = maliciousInfo
			}
		}

		webShellInfo := make([]model.Webshell, 0)
		if len(res[i].WebshellInfoJSON) > 0 {
			if err := json.Unmarshal(res[i].WebshellInfoJSON, &webShellInfo); err == nil {
				res[i].WebshellInfo = webShellInfo
			}
		}

		envInfo := make([]model.EnvKeyValue, 0)
		if len(res[i].EnvJSON) > 0 {
			if err := json.Unmarshal(res[i].EnvJSON, &webShellInfo); err == nil {
				res[i].EnvKeyValue = envInfo
			}
		}
	}

	return res, cnt, nil
}

func (s *ScannerOrm) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.Registry)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	if len(param.RegistryIds) > 0 {
		if len(param.RegistryIds) == 1 {
			db = db.Where("id = ? ", param.RegistryIds[0])
		} else {
			db = db.Where("id IN ? ", param.RegistryIds)
		}
	}
	if param.Id > 0 {
		db = db.Where("id = ? ", param.Id)
	}
	if param.LibraryUrl != "" {
		db = db.Where("url = ? ", param.LibraryUrl)
	}
	if param.UseType > 0 {
		db = db.Where("use_type = ? ", param.UseType)
	}
	if len(param.UseTypes) > 0 {
		db = db.Where("use_type IN ? ", param.UseTypes)
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

func (s *ScannerOrm) SearchImage(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.ImageList)).WithContext(ctx)
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
			db = db.Where("id = ? ", param.Ids[0])
		} else {
			db = db.Where("id IN ? ", param.Ids)
		}
	}
	if len(param.NodeHostnames) > 0 {
		db = db.Where("node_hostname IN ? ", param.NodeHostnames)
	}

	if len(param.RegistryIds) > 0 {
		if len(param.RegistryIds) == 1 {
			db = db.Where("registry_id = ? ", param.RegistryIds[0])
		} else {
			db = db.Where("registry_id IN ? ", param.RegistryIds)
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
	if param.StartId > 0 {
		db = db.Where("id > ?", param.StartId)
	}
	if param.LastId > 0 {
		db = db.Where("id < ?", param.LastId)
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
	if param.ImageType == consts.AppImageTypeString {
		db = db.Where("image_type = ? ", consts.AppImageType)
	} else if param.ImageType == consts.BaseImageTypeString {
		db = db.Where("image_type = ? ", consts.BaseImageType)
	}
	if param.LayersPrefix != "" {
		db = db.Where("layers LIKE ?", fmt.Sprintf("%s%%", param.LayersPrefix))
	}

	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
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
				logging.GetLogger().Debug().Msg(fmt.Sprintf("serialize Manifest error:%s", err.Error()))
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
							logging.GetLogger().Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.HistoryV1 error:%s", err.Error()))
						}
					}
				}
			} else {
				logging.GetLogger().Debug().Msg(fmt.Sprintf("Unmarshal ManifestV1.ManifestJson error :%s", err.Error()))
			}
		}

		if len(res[i].ConfigJson) > 0 {
			configFile := new(model.ConfigFile)
			if err := json.Unmarshal(res[i].ConfigJson, configFile); err == nil {
				res[i].ConfigFile = *configFile
			} else {
				logging.GetLogger().Debug().Msg(fmt.Sprintf("serialize ConfigFile error:%s", err.Error()))
			}
		}
	}

	return res, cnt, nil
}

func (s *ScannerOrm) InsertAdapterImageList(ctx context.Context, im model.ImageList) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.ImageList{}
	res := s.psql.Get().WithContext(ctx).Where("full_repo_name=? AND digest = ? AND registry_id = ?", im.FullRepoName, im.Digest, im.RegistryId).First(&tmp)
	if res.Error != nil {
		err := s.psql.Get().Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := s.psql.Get().Model(tmp).Updates(&im).Error
	return tmp.ID, err
}

// CreateRejectRecord 创建记录，
func (s *ScannerOrm) CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	// if data.Library == "" {
	// 	return nil, errors.New("no library")
	// }
	if data.FullRepoName == "" {
		return nil, errors.New("no full repo name")
	}
	// if data.Tag == "" {
	// 	return nil, errors.New("no tag")
	// }
	if len(data.RejectReason) <= 0 && len(data.RejectReasonJson) <= 0 {
		return nil, errors.New("no reject reason")
	}
	if data.RejectDetail == "" {
		return nil, errors.New("no reject detail")
	}
	if len(data.RejectReasonJson) == 0 && len(data.RejectReason) > 0 {
		reasonMap := make(map[int64]int64)
		reasons := make([]int64, 0)

		for i := range data.RejectReason {
			if reasonMap[data.RejectReason[i]] < 1 {
				reasons = append(reasons, data.RejectReason[i])
				reasonMap[data.RejectReason[i]]++
			}
		}
		reasonsDuplication := make(map[string]string)
		for _, r := range reasons {
			reasonsDuplication[strconv.Itoa(int(r))] = strconv.Itoa(int(r))
		}
		if bys, err := json.Marshal(reasonsDuplication); err == nil {
			data.RejectReasonJson = bys
		}
	}

	err := s.psql.Get().WithContext(ctx).Create(&data).Debug().Error
	return &data, err
}

func (s *ScannerOrm) OverviewForInterval(ctx context.Context, interval int, intervalType string) ([]IntervalDateGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	if interval < 1 {
		return nil, errors.New("interval must more than 1")
	}

	var (
		startAt   time.Time
		sql       string
		timeParse string
	)
	now := time.Now().UTC()
	switch intervalType {
	case consts.IntervalHour:
		startAt = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-time.Duration(interval-1) * time.Hour).UTC()
		sql = fmt.Sprintf("select to_char(reject_at, 'YYYY-MM-DD HH24') as interval_date,count(id)  as  cnt from  %s  where reject_at <= ?  AND reject_at >= ?  group by interval_date  order by interval_date ;", new(model.RejectRecord).TableName())
		timeParse = consts.TimeFormatWithHour

	case consts.IntervalDay:
		startAt = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(interval - 1)).UTC()
		sql = fmt.Sprintf("select to_char(reject_at, 'YYYY-MM-DD') as interval_date,count(id)  as  cnt from  %s  where reject_at <= ?  AND reject_at >= ?  group by interval_date  order by interval_date ;", new(model.RejectRecord).TableName())
		timeParse = consts.TimeFormatWithDay
	}

	logging.GetLogger().WithContext(ctx).Infof("OverviewForInterval sql:%s", sql)
	res := make([]IntervalDateGroup, 0)
	err := s.psql.Get().Debug().Raw(sql, now, startAt).Scan(&res).Error
	if err != nil {
		return res, err
	}
	for i := range res {
		if tm, err := time.Parse(timeParse, res[i].IntervalDate); err == nil {
			res[i].IntervalDateTime = tm
		}
	}
	sort.Sort(IntervalDateGroups(res))
	return res, err
}

func (s *ScannerOrm) OverviewReasonTopN(ctx context.Context, param OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	res := make([]model.RejectReasonStatistic, 0)
	// 取全表数据
	records, _, err := s.SearchRejectRecord(ctx, SearchRejectRecordParam{
		Fields: []string{"reject_reason_json"},
	}, &model.Filter{Limit: math.MaxInt64})
	if err != nil {
		return res, err
	}
	// 统计
	statistics := make(map[int64]int64)
	for _, rec := range records {
		for _, re := range rec.RejectReason {
			statistics[re]++
		}
	}
	// 生成结果
	for ke, va := range statistics {
		res = append(res, model.RejectReasonStatistic{
			RejectReason: ke,
			Count:        va,
		})
	}
	// 排序
	sort.Sort(model.RejectReasonStatistics(res))
	// 生成中英文
	for i := range res {
		res[i].RejectReasonStringCN = model.GetRejectReason(model.LangZh)[res[i].RejectReason]
		res[i].RejectReasonStringEN = model.GetRejectReason(model.LangEn)[res[i].RejectReason]
	}
	// 取结果
	if len(res) > param.TopN {
		return res[:param.TopN], nil
	}
	return res, err
}

func (s *ScannerOrm) SearchRejectRecord(ctx context.Context, param SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.RejectRecord)).WithContext(ctx).Debug()
	if !param.StartAt.IsZero() {
		db = db.Where("reject_at >= ?", param.StartAt)
	}
	if !param.EndAt.IsZero() {
		db = db.Where("reject_at <= ?", param.EndAt)
	}
	if param.Search != "" {
		db = db.Where("full_repo_name LIKE ? OR tag LIKE ?  ", fmt.Sprintf("%%%s%%", param.Search), fmt.Sprintf("%%%s%%", param.Search))
	}
	if len(param.RejectReasons) > 0 {
		sqls := make([]string, 0)
		for _, rej := range param.RejectReasons {
			sqls = append(sqls, fmt.Sprintf("reject_reason_json ->>'%s' ::text = '%s'", strconv.Itoa(int(rej)), strconv.Itoa(int(rej))))
		}
		db = db.Where(strings.Join(sqls, " OR "))
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}

	if len(param.Libraries) > 0 {
		if len(param.Libraries) == 1 {
			db = db.Where("library = ? ", param.Libraries[0])
		} else {
			db = db.Where("library IN ? ", param.Libraries)
		}
	}
	if param.Library != "" {
		db = db.Where("library = ? ", param.Library)
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tag = ? ", param.Tag)
	}

	// 计算count
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.RejectRecord, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// 序列化数据
	// 因为要对这个字段做查询，所以数据库只能存{"1":"1"}的方式
	for i := range res {
		re := make([]int64, 0)
		reasonMap := make(map[string]string)
		if len(res[i].RejectReasonJson) > 0 {
			if err := json.Unmarshal(res[i].RejectReasonJson, &reasonMap); err != nil {
				logging.GetLogger().WithContext(ctx).Errorf(err, "SearchRejectRecord json Unmarshal error")
			}
		}
		for k := range reasonMap {
			if i, err := strconv.ParseInt(k, 10, 64); err == nil {
				re = append(re, i)
			}
		}
		res[i].RejectReason = re
	}
	return res, cnt, nil
}

func (s *ScannerOrm) CreateImageWhitelist(ctx context.Context, data model.ImageWhitelist) (*model.ImageWhitelist, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	if data.FullRepoName == "" {
		return nil, errors.New("no full repo name")
	}
	if data.Tag == "" {
		return nil, errors.New("no tag")
	}
	if data.Library == "" {
		return nil, errors.New("no library")
	}
	err := s.psql.Get().WithContext(ctx).Create(&data).Error
	return &data, err
}

func (s *ScannerOrm) SearchImageWhitelist(ctx context.Context, param SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(new(model.ImageWhitelist))
	if param.SearchWord != "" {
		db = db.Where("full_repo_name LIKE ? OR tag LIKE ?  ", fmt.Sprintf("%%%s%%", param.SearchWord), fmt.Sprintf("%%%s%%", param.SearchWord))
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ?", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tag = ?", param.Tag)
	}
	if param.Library != "" {
		db = db.Where("library = ?", param.Library)
	}
	if param.Digest != "" {
		db = db.Where("digest = ?", param.Digest)
	}

	// 计算count
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.ImageWhitelist, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	return res, cnt, nil
}

func (s *ScannerOrm) DeleteImageWhitelist(ctx context.Context, param DeleteImageWhitelistParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	err := s.psql.Get().WithContext(ctx).Where("id = ?", param.WhiteId).Delete(&model.ImageWhitelist{}).Error
	return err
}

func (s *ScannerOrm) UpdateTasksInfo(ctx context.Context, param SearchTaskParam, updateInfo map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(model.Task{})
	if len(param.Ids) > 0 {
		db = db.Where("id IN ? ", param.Ids)
	}
	if len(param.Statuses) > 0 {
		db = db.Where("status IN ? ", param.Statuses)
	}

	db = db.Updates(updateInfo)
	return db.Error
}

func (s *ScannerOrm) UpdateTask(ctx context.Context, task model.Task, param SearchTaskParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(model.Task{}).Where("id = ?", task.ID)
	if len(param.ExcludeStatus) != 0 {
		db = db.Where("status NOT IN ? ", param.ExcludeStatus)
	}
	db = db.Updates(&task)
	return db.Error
}

func (s *ScannerOrm) UpdateTasksStatus(ctx context.Context, updateIds []int64, status int) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	res := map[string]interface{}{"status": status}
	db := s.psql.Get().WithContext(ctx).Model(model.Task{}).Where("id IN ?", updateIds).Updates(res)
	return db.Error
}

func (s *ScannerOrm) UpdateSubTasksInfo(ctx context.Context, param SearchSubTaskParam, updateInfo map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(model.SubTask{})
	if len(param.Ids) > 0 {
		db = db.Where("id IN ? ", param.Ids)
	}
	if len(param.Statuses) > 0 {
		db = db.Where("status IN ? ", param.Statuses)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("task_id In ? ", param.TaskIds)
	}

	db = db.Updates(updateInfo)
	return db.Error
}

func (s *ScannerOrm) UpdateSubTask(ctx context.Context, subtask model.SubTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(model.SubTask{}).Where("id = ?", subtask.ID).Updates(&subtask)
	return db.Error
}

func (s *ScannerOrm) GetTasks(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(new(model.Task))
	if param.StrategyID > 0 {
		db = db.Where("policy_id = ? ", param.StrategyID)
	}
	if len(param.Statuses) > 0 {
		db = db.Where("status IN ? ", param.Statuses)
	}
	if len(param.Ids) > 0 {
		db = db.Where("id IN ? ", param.Ids)
	}
	db = db.Order("created_at DESC")

	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.Task, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	return res, cnt, nil
}

func (s *ScannerOrm) GetTotalTaskNum(ctx context.Context) (int64, error) {
	db := s.psql.Get().WithContext(ctx).Model(new(model.Task))
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return 0, err
	}
	return cnt, nil
}

func (s *ScannerOrm) GetImageInfo(ctx context.Context, imgId int64) (*model.ImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.ImageList{}
	if err := s.psql.Get().WithContext(ctx).Where("id = ? ", imgId).First(&tmp).Error; err != nil {
		return nil, fmt.Errorf("not find image:%v", err)
	}

	return &tmp, nil
}

func (s *ScannerOrm) GetRegistryInfo(ctx context.Context, Id int64) (*model.Registry, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.Registry{}
	if err := s.psql.Get().WithContext(ctx).Where("id = ? ", Id).First(&tmp).Error; err != nil {
		return nil, fmt.Errorf("not find registry:%v", err)
	}

	return &tmp, nil
}
func (s *ScannerOrm) AddTask(ctx context.Context, task model.Task) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	if err := s.psql.Get().WithContext(ctx).Model(model.Task{}).Create(&task).Error; err != nil {
		return 0, err
	}

	return task.ID, nil
}
func (s *ScannerOrm) AddSubTask(ctx context.Context, subtask []model.SubTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	if err := s.psql.Get().WithContext(ctx).Model(model.SubTask{}).Create(&subtask).Error; err != nil {
		return err
	}

	return nil
}
func (s *ScannerOrm) GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(new(model.SubTask))
	if len(param.Statuses) > 0 {
		db = db.Where("status in  ?  ", param.Statuses)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("task_id in ? ", param.TaskIds)
	}
	if len(param.Ids) > 0 {
		db = db.Where("id in ? ", param.Ids)
	}
	db = db.Order("created_at DESC")

	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.SubTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}

	return res, cnt, nil
}

func (s *ScannerOrm) CreateTasks(ctx context.Context, tasks ...model.Task) error {
	return s.psql.Get().Model(model.Task{}).CreateInBatches(tasks, 100).Error
}

func (s *ScannerOrm) UpdateTaskStatus(ctx context.Context, id int64, status uint8) (err error) {
	var data model.Task
	begin := s.psql.Get().WithContext(ctx).Begin()

	defer func() {
		if err != nil {
			begin.Rollback()
		}
	}()

	err = begin.Model(data).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&data).Error
	if err != nil {
		return
	}

	if err = StatusCheck(uint8(data.Status), status); err != nil {
		return
	}

	err = begin.Model(data).Where("id = ?", id).UpdateColumn("status", status).Error
	if err != nil {
		return
	}

	err = begin.Commit().Error
	if err != nil {
		return
	}

	return
}

func (s *ScannerOrm) GetTaskList(ctx context.Context, limit, offset int) ([]*model.Task, int64, error) {
	var (
		count int64
		err   error
	)

	db := s.psql.Get().WithContext(ctx)

	err = db.Model(model.Task{}).Where("status != ?", consts.Unknown).Count(&count).Error
	if err != nil {
		return nil, 0, errors.Wrap(err, "get task total count failed")
	}

	data := make(
		[]struct {
			model.Task
			ScanStrategyName string `gorm:"column:name"`
		},
		0,
		limit,
	)

	err = db.
		Model(model.Task{}).
		Select("tensor_scan_task.*, t.name").
		Joins("INNER JOIN tensor_scan_strategy as t ON t.id=tensor_scan_task.policy_id").
		Where("status != ?", consts.Unknown).
		Limit(limit).
		Offset(offset).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "created_at"}, Desc: true}).
		Find(&data).
		Error

	if err != nil {
		return nil, 0, errors.Wrap(err, "get task data failed")
	}

	taskIds := make([]int64, 0, len(data))
	taskIdsMap := make(map[int64]*model.Task, len(data))
	var datas = make([]*model.Task, 0, len(data))
	for i := range data {
		taskIds = append(taskIds, data[i].ID)
		taskIdsMap[data[i].ID] = &data[i].Task
		data[i].Task.ScanStrategyName = data[i].ScanStrategyName
		datas = append(datas, &data[i].Task)
	}

	type SubTaskCount struct {
		SuccessCount int   `gorm:"column:sc"`
		TaskId       int64 `gorm:"column:task_id"`
	}

	c := make([]SubTaskCount, 0, len(data))

	err = db.
		Model(model.SubTask{}).
		Select("task_id, count(*) as sc").
		Where("task_id in ?", taskIds).
		Where("status = ?", consts.ImageScanSuccess).
		Group("task_id").
		Find(&c).
		Error
	if err != nil {
		return nil, 0, errors.Wrap(err, "get success subtasks failed")
	}

	// 数据做聚合
	for i := range c {
		taskIdsMap[c[i].TaskId].SuccessSubTaskCount = c[i].SuccessCount
	}

	return datas, count, nil
}

func (s *ScannerOrm) GetSubTaskListWithImage(ctx context.Context, taskId int64, limit, offset int) ([]model.SubTask, int64, error) {
	var (
		data  = make([]model.SubTask, 0, limit)
		count int64
		err   error
	)

	db := s.psql.Get().WithContext(ctx)

	err = db.Model(model.SubTask{}).
		Where("task_id = ?", taskId).
		Count(&count).
		Error
	if err != nil {
		return nil, 0, errors.Wrap(err, "get subtask total count failed")
	}

	err = db.
		Model(model.SubTask{}).
		Where("task_id = ?", taskId).
		Limit(limit).
		Offset(offset).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "finished_at"}, Desc: true}).
		Find(&data).
		Error

	if err != nil {
		return nil, 0, errors.Wrap(err, "get subtask data failed")
	}

	var imagesId = make([]int64, 0, len(data))
	var imagesInfo = make([]model.ImageList, 0, len(data))
	var imagesIdMap = make(map[int64]*model.SubTask, len(data))

	for i := range data {
		imagesId = append(imagesId, data[i].ImageId)
		imagesIdMap[data[i].ImageId] = &data[i]
	}

	// 不用join，直接查询吧
	err = db.
		Model(model.ImageList{}).
		Select("id, full_repo_name, tags, node_ip, library, os, node_hostname, from_type").
		Where("id in ?", imagesId).
		Find(&imagesInfo).
		Error
	if err != nil {
		return nil, 0, errors.Wrap(err, "get images info failed")
	}

	for i := range imagesInfo {
		imagesIdMap[imagesInfo[i].ID].ImageInfo.Tag = imagesInfo[i].Tags
		if imagesInfo[i].FromType == model.ImageFromSafeNode {
			split := strings.SplitN(imagesInfo[i].FullRepoName, "/", 6)
			imagesIdMap[imagesInfo[i].ID].ImageInfo.FullRepoName = split[len(split)-1]
			imagesIdMap[imagesInfo[i].ID].ImageInfo.Library = fmt.Sprintf("%s(%s)%s",
				imagesInfo[i].NodeHostname, imagesInfo[i].NodeIp, imagesInfo[i].OS)
		} else {
			imagesIdMap[imagesInfo[i].ID].ImageInfo.FullRepoName = imagesInfo[i].FullRepoName
			imagesIdMap[imagesInfo[i].ID].ImageInfo.Library = imagesInfo[i].Library
		}

	}

	return data, count, nil
}

func (s *ScannerOrm) SetSingleStrategy(ctx context.Context, envName string, policyId []int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := []model.ScanStrategy{}
	err := s.psql.Get().WithContext(ctx).Where("is_default != ? and id in ?", true, policyId).Find(&res).Error
	if err != nil {
		return err
	}
	for k := range res {
		var resEnv []string
		if len(res[k].EnvsJson) != 0 {
			err = json.Unmarshal([]byte(res[k].EnvsJson), &resEnv)
			if err != nil {
				return err
			}
		}

		resEnv = append(resEnv, envName)
		envByte, err := json.Marshal(resEnv)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("marshal env form db error")
			continue
		}
		envStr := string(envByte)
		err = s.psql.Get().Model(&model.ScanStrategy{}).Where("id = ?", res[k].ID).Update("envs", envStr).Error
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("updata env form db error")
			continue
		}
	}
	return nil
}

func (s *ScannerOrm) GetAllScanStrategyEnv(ctx context.Context) ([]model.ScanStrategy, error) { // 这个接口留待下版本优化
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := []model.ScanStrategy{}
	err := s.psql.Get().WithContext(ctx).Select("id", "envs", "name").Where("is_default != ?", true).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}
