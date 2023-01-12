package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/databases"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScannerDalInterface interface {
	SearchImage(ctx context.Context, param SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error)
	UpdateImageScanStatus(ctx context.Context, imageID int64, status uint64) error
	DeleteImage(ctx context.Context, imageId int64) error
	UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error
	CreateImage(ctx context.Context, data *model.ImageList) (*model.ImageList, error)
	CreateImageAndUpdate(ctx context.Context, im *model.ImageList) (*model.ImageList, error)

	SearchScanLayer(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]*model.ScanLayer, int64, error)
	SearchScanImage(ctx context.Context, param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error)
	DeleteScanImage(ctx context.Context, imageIds []int64) error

	InsertScanImage(ctx context.Context, sis []model.ScanImage) (int64, error)
	InsertAdapterImageList(ctx context.Context, im model.ImageList) (int64, error)
	SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
	GroupImageFlags(ctx context.Context, param GetImageOverViewParam) ([]model.ImageFlagGroup, error)
	GroupRegistryProject(ctx context.Context, param GroupRegistryRepoParam) ([]RegProject, error)

	SearchRejectVuln(ctx context.Context, param SearchRejectRejectVulnParam) ([]model.RejectVuln, error)
	CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error)
	CreateRejectPolicy(ctx context.Context, data model.RejectPolicy) (int64, error)

	GetScanimageFromImageList(ctx context.Context, imgID int64) (model.ScanImage, model.ImageList)

	GetTaskFromImageList(ctx context.Context, imgID int64, fromURL string, auth string) (model.ScanTask, model.VirusScanTask, error)
	SearchScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus

	GroupVulnSeverity(ctx context.Context, param GroupVulnSeverityParam) ([]model.SeverityGroup, error)

	GetImagesFromVuln(ctx context.Context, uniqueVuln uint64) ([]model.VulnImageList, error)

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
	GetInprogressTaskAndSetStatus(ctx context.Context, maxInprogress, dequeNum int64, regIds []int64) ([]model.Task, error)
	SearchRejectPolicy(ctx context.Context, param SearchRejectPolicyParam) ([]model.RejectPolicy, error)
	GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error)
	AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error)
	UpdatePolicy(ctx context.Context, param SearchRejectPolicyParam, updater map[string]interface{}) error
	UpdateGlobalPolicy(ctx context.Context, updater map[string]interface{}) error
	DeletePolicy(ctx context.Context, policyID int64) error
	IsInRegistry(ctx context.Context, library string) bool

	GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList
	AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy)
	GetGlobalPolicyConfig(ctx context.Context) ([]model.RejectPolicy, error)

	ScanTaskInterface
	ScanReportInterface
	TrustedImageDal
}

type ScanTaskInterface interface {
	CreateTasks(ctx context.Context, tasks ...model.Task) error
	UpdateTask(ctx context.Context, task model.Task, param SearchTaskParam) error
	UpdateTasksInfo(ctx context.Context, param SearchTaskParam, updateInfo map[string]interface{}) error
	UpdateTasksStatus(ctx context.Context, updateIds []int64, status int) error
	UpdateSubTasksInfo(ctx context.Context, param SearchSubTaskParam, updateInfo map[string]interface{}) error
	AddSubTasksRetryCount(ctx context.Context, ids []int64) error
	GetTotalTaskNum(ctx context.Context) (int64, error)
	GetRegistryInfo(ctx context.Context, ID int64) (*model.Registry, error)

	AddTaskAndSubTask(ctx context.Context, task model.Task, subtask []model.SubTask) (int64, error)
	AddTask(ctx context.Context, task model.Task) (int64, error)
	AddSubTask(ctx context.Context, subtask []model.SubTask) error
	GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error)

	SearchSubTasksWithScanStatus(ctx context.Context, imageIds []int64, status []int) ([]model.SubTask, error)

	UpdateTaskStatus(ctx context.Context, id int64, status uint8) ([]int64, error)
	GetTaskList(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error)
	GroupSubtask(ctx context.Context, taskGroupIds int64) ([]GroupSubtaskRes, error)
	GetSubTaskListWithImage(ctx context.Context, param GetSubTaskListWithImageParam, fileter *model.Filter) ([]model.SubTask, int64, error)

	GetAllScanStrategyEnv(ctx context.Context) ([]model.ScanStrategy, error)
	SetSingleStrategy(ctx context.Context, envName string, policyID []int64) error
}

type ScannerOrm struct {
	rdb *databases.RDBInstance
}

func (s *ScannerOrm) GroupRegistryProject(ctx context.Context, param GroupRegistryRepoParam) ([]RegProject, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*15)
	defer cancelFunc()
	db := s.rdb.Get().WithContext(ctx).Model(&model.ImageList{})
	db = db.Where("from_type = ?", model.UserRegistry)
	if param.RegID > 0 {
		db = db.Where("registry_id = ?", param.RegID)
	}

	if param.ProjectKeyword != "" {
		db = db.Where("project LIKE ?", fmt.Sprintf("%%%s%%", param.ProjectKeyword))
	}
	db = db.Select("distinct registry_id,project")

	res := make([]RegProject, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) SearchSubTasksWithScanStatus(ctx context.Context, imageIds []int64, status []int) ([]model.SubTask, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*15)
	defer cancelFunc()

	res := make([]model.SubTask, 0)
	db := s.rdb.Get().WithContext(ctx)
	subQuery := db.Table(model.SubTask{}.TableName()).Select("max(id)  as id").Group("image_id")
	if len(imageIds) > 0 {
		subQuery = subQuery.Where("image_id IN ?", imageIds)
	}
	if len(status) > 0 {
		subQuery = subQuery.Where("status IN ?", status)
	}
	// 指定查询的字段
	db = db.Model(&model.SubTask{}).Select("ivan_scanner_scan_subtask.id", "image_id", "status", "finished_at")
	err := db.Joins(fmt.Sprintf("join ( ? ) as q on %s.id=q.id ", model.SubTask{}.TableName()), subQuery).Find(&res).Error

	return res, err
}

func (s *ScannerOrm) CreateImageAndUpdate(ctx context.Context, im *model.ImageList) (*model.ImageList, error) {
	// 先查一下
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	im.Layers = im.GetLayerString()
	im.UniqueImage = im.GenUniqueImage()
	im.CheckSum = im.GenImageCheckSum()
	im.GenImageFlag()

	imageLists, _, err := s.SearchImage(ctx, SearchImageParam{UniqueImage: im.UniqueImage}, nil)
	if err != nil {
		return nil, err
	}
	if len(imageLists) == 0 {
		return s.CreateImage(ctx, im)
	}
	im.ID = imageLists[0].ID
	if err := s.UpdateImage(ctx, fmt.Sprintf("id = %d", im.ID), nil, im); err != nil {
		return nil, err
	}
	return im, nil
}

func (s *ScannerOrm) CreateImage(ctx context.Context, im *model.ImageList) (*model.ImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	im.Layers = im.GetLayerString()
	im.UniqueImage = im.GenUniqueImage()
	im.CheckSum = im.GenImageCheckSum()
	im.GenImageFlag()

	err := s.rdb.Get().WithContext(ctx).Create(im).Error
	if err != nil {
		return nil, err
	}

	return im, nil
}

type ImageListWithScan struct {
	ID             int64     `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	FullRepoName   string    `json:"full_repo_name"`
	FinishAt       int64     `json:"finish_at"`
	Tags           string    `json:"tags"`
	Digest         string    `json:"digest"`
	OS             string    `json:"os"`
	Library        string    `json:"library"`
	ImageUUID      uint32    `json:"image_uuid"`
	CompleteTime   string    `json:"complete_time"`
	RegistryID     int64     `json:"registry_id"`
	FromType       int64     `json:"from_type"`
	NodeIP         string    `json:"node_ip"`
	NodeHostname   string    `json:"node_hostname"`
	ImageType      int64     `json:"image_type"`
	IsReinforce    int64     `json:"is_reinforce"`
	PrivilegedBoot int64     `json:"privileged_boot"`
	HasFixedVuln   int64     `json:"has_fixed_vuln"`
}

func (s *ScannerOrm) CreateRejectPolicy(ctx context.Context, data model.RejectPolicy) (int64, error) {
	if len(data.EnvsJson) == 0 && len(data.Envs) > 0 {
		bys, err := json.Marshal(data.Envs)
		if err == nil {
			data.EnvsJson = string(bys)
		} else {
			logging.GetLogger().Err(err).Msg("CreateRejectPolicy")
		}
	}

	if len(data.SensitiveFileJson) == 0 && len(data.SensitiveFile) > 0 {
		bys, err := json.Marshal(data.SensitiveFile)
		if err == nil {
			data.SensitiveFileJson = string(bys)
		} else {
			logging.GetLogger().Err(err).Msg("CreateRejectPolicy")
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
	if err := s.rdb.Get().WithContext(ctx).Model(new(model.RejectPolicy)).Create(&data).Error; err != nil {
		return 0, err
	}
	// 自定义漏洞
	if len(data.RejectVulns) > 0 && !data.IsGlobal {
		tmpVuln := data.RejectVulns
		for k := range tmpVuln {
			tmpVuln[k].RejectPolicyID = data.ID
		}
		if err := s.rdb.Get().WithContext(ctx).Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
			return 0, err
		}
	}
	return data.ID, nil
}

func NewScannerOrm(sql *databases.RDBInstance) *ScannerOrm {
	return &ScannerOrm{
		rdb: sql,
	}
}

func (s *ScannerOrm) UpdateImageWhitelist(ctx context.Context, where string, updater map[string]interface{}) error {
	if where == "" {
		return errors.New("no where for update condition")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.ImageWhitelist)).WithContext(ctx).Where(where).Updates(updater)
	return db.Error

}

func (s *ScannerOrm) DeleteImage(ctx context.Context, imageId int64) error {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.ImageList)).WithContext(ctx)
	db = db.Where("id = ?", imageId)
	err := db.Delete(&model.ImageList{}).Error
	return err
}

func (s *ScannerOrm) DeleteScanImage(ctx context.Context, imageIds []int64) error {
	if len(imageIds) == 0 {
		return nil
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.ScanImage)).WithContext(ctx)
	db = db.Where("image_id IN ? ", imageIds)
	return db.Delete(&model.ScanImage{}).Error
}

func (s *ScannerOrm) IsInRegistry(ctx context.Context, library string) bool {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	res := s.rdb.Get().WithContext(ctx).Model(model.Registry{}).Where("url = ? AND use_type!=0", library).First(&model.Registry{})
	return res.Error == nil
}

func (s *ScannerOrm) GetScanimageFromImageList(ctx context.Context, imgID int64) (model.ScanImage, model.ImageList) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	resScanImage := model.ScanImage{}
	s.rdb.Get().WithContext(ctx).Model(model.ScanImage{}).Where("image_id = ?", imgID).First(&resScanImage)
	resImageList := model.ImageList{}
	s.rdb.Get().Model(model.ImageList{}).Where("id = ?", imgID).First(&resImageList)
	return resScanImage, resImageList
}

func (s *ScannerOrm) GetGlobalPolicyConfig(ctx context.Context) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	res := []model.RejectPolicy{}
	err := s.rdb.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("is_global = ?", true).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	res := s.rdb.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", true).First(&model.RejectPolicy{})
	if res.Error != nil {
		s.rdb.Get().WithContext(ctx).Model(model.RejectPolicy{}).Create(&policy)
	} else {
		s.rdb.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", true).Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
	}
	s.rdb.Get().WithContext(ctx).Model(&model.RejectPolicy{}).Where("is_global = ?", false).Omit("is_global").Select("cicd_enable", "k8s_enable", "mode", "online_monitor").Updates(&policy)
}

func (s *ScannerOrm) SearchRejectPolicy(ctx context.Context, param SearchRejectPolicyParam) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.RejectPolicy)).WithContext(ctx)
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
				logging.GetLogger().Err(err).Msg("SearchRejectPolicy")
			}
		}

		if len(res[i].EnvsJson) > 0 {
			ses := make([]string, 0)
			if err := json.Unmarshal([]byte(res[i].EnvsJson), &ses); err == nil {
				res[i].Envs = ses
			} else {
				logging.GetLogger().Err(err).Msg("SearchRejectPolicy")
			}
		}
	}

	return res, nil
}

func (s *ScannerOrm) SearchRejectVuln(ctx context.Context, param SearchRejectRejectVulnParam) ([]model.RejectVuln, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.RejectVuln)).WithContext(ctx)
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
		s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").
			Where("digest = ? AND library = ?", image.Digest, image.Library).First(&id)
		if id != 0 {
			image.ID = id
			return &image
		}
	}
	var ids []int64
	res := s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").
		Where("full_repo_name = ? AND tags = ? AND library = ?", image.FullRepoName, image.Tags, image.Library).Order("updated_at desc").Find(&ids)
	if res.Error == nil && len(ids) > 0 {
		for k := range ids {
			tmp := []model.ScanImage{}
			resScan := s.rdb.Get().Model(model.ScanImage{}).Where("image_id = ? AND status != ?", ids[k], model.ScanStatusInProgress).Find(&tmp)
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

func (s ScannerOrm) DeletePolicy(ctx context.Context, policyID int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	if err := s.rdb.Get().WithContext(ctx).Model(model.RejectVuln{}).Where("reject_policy_id = ? ", policyID).Delete(model.RejectVuln{}).Error; err != nil {
		return err
	}
	if err := s.rdb.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("id = ? ", policyID).Delete(model.RejectPolicy{}).Error; err != nil {
		return err
	}
	return nil

}

func (s ScannerOrm) UpdatePolicy(ctx context.Context, param SearchRejectPolicyParam, updater map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.rdb.Get().Model(new(model.RejectPolicy)).Omit("is_global")
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
		if err := s.rdb.Get().WithContext(ctx).Model(model.RejectVuln{}).Where("reject_policy_id = ? ", param.ID).Delete(model.RejectVuln{}).Error; err != nil {
			return err
		}
		tmpVuln := param.RejectVulns
		for k := range tmpVuln {
			tmpVuln[k].RejectPolicyID = param.ID
		}
		if len(tmpVuln) > 0 { // 不判断会报错： empty slice found
			if err := s.rdb.Get().Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
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
	db := s.rdb.Get().Model(new(model.RejectPolicy)).Omit("is_global").WithContext(ctx)
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
	return tx.Commit().Error
}

func (s ScannerOrm) AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	if err := s.rdb.Get().WithContext(ctx).Model(model.RejectPolicy{}).Create(&policy).Error; err != nil {
		return 0, err
	}
	tmpVuln := policy.RejectVulns
	for k := range tmpVuln {
		tmpVuln[k].RejectPolicyID = policy.ID
	}
	if err := s.rdb.Get().WithContext(ctx).Model(model.RejectVuln{}).Create(&tmpVuln).Error; err != nil {
		return 0, err
	}
	return policy.ID, nil
}

func (s ScannerOrm) GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmpPolicies := []model.RejectPolicy{}
	err := s.rdb.Get().WithContext(ctx).Model(model.RejectPolicy{}).Where("deleted_at = 0 And is_global != true").Find(&tmpPolicies).Error
	if err != nil {
		return []model.RejectPolicy{}, nil
	}
	if getVuln {
		for k := range tmpPolicies {
			s.rdb.Get().Model(model.RejectVuln{}).Where("reject_policy_id = ?", tmpPolicies[k].ID).Find(&tmpPolicies[k].RejectVulns)
		}
	}
	return tmpPolicies, nil
}

func (s ScannerOrm) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	var imageID int
	librarys := []string{library, "http://" + library, "https://" + library}

	res := s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Select("id").Where("tags = ? AND library In ? AND full_repo_name = ?", tag, librarys, fullRepoName).First(&imageID)
	if res.Error != nil {
		return model.SimpleImageDetail{}
	}
	resDetail := model.SimpleImageDetail{}
	tmpScanImage := model.ScanImage{}
	res = s.rdb.Get().WithContext(ctx).Model(model.ScanImage{}).Select("vuln_info_json,sensitive_file_json").Where("image_id = ?", imageID).First(&tmpScanImage)
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
	db := s.rdb.Get().WithContext(ctx).Model(model.ScanImage{}).Where("status != ?", model.ScanStatusInProgress)
	if len(ids) > 0 {
		db = db.Where("image_id IN ?", ids)
	}

	err := db.Update("status", status).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *ScannerOrm) GetImagesFromVuln(ctx context.Context, uniqueVuln uint64) ([]model.VulnImageList, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()
	tmpImageID := make([]int, 0, 10)
	// 查询这个vuln关联的imageid
	err := s.rdb.Get().WithContext(ctx).Model(model.VulnImage{}).Select("image_id").Where("unique_vuln  = ? ", uniqueVuln).Find(&tmpImageID).Error
	if err != nil {
		return nil, err
	}
	// 查询image具体信息
	resImageLists := make([]model.VulnImageList, 0, len(tmpImageID))
	err = s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Select("full_repo_name,digest,library,id,tags").Where("id IN ? ", tmpImageID).Find(&resImageLists).Error
	return resImageLists, err
}

func (s *ScannerOrm) GetOnlineImage(ctx context.Context, param GetOnlineImageParam) ([]OnlineImage, error) {
	// 中移的环境中资产的数据较多，这里设置一下较大的值
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()
	res := make([]OnlineImage, 0)
	db := s.rdb.Get().WithContext(ctx)
	if err := db.Raw(param.SQL).Scan(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) SearchScanLayer(ctx context.Context, param SearchScanLayerParam, filter *model.Filter) ([]*model.ScanLayer, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(new(model.ScanLayer)).WithContext(ctx)
	if len(param.LayerDigests) > 0 {
		db = db.Where("layer_digest IN ? ", param.LayerDigests)
	}
	if param.ImageId > 0 {
		db = db.Where("image_id = ? ", param.ImageId)
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	res := make([]*model.ScanLayer, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// serialize
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *ScannerOrm) GroupVulnSeverity(ctx context.Context, param GroupVulnSeverityParam) ([]model.SeverityGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	group := make([]model.SeverityGroup, 0)
	db := s.rdb.Get().WithContext(ctx).Model(model.Vuln{})

	if len(param.ImageIds) > 0 {
		sub := s.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Select("distinct unique_vuln").Where("image_id IN ?", param.ImageIds)
		db = db.Where("unique_vuln IN (?)", sub)
	}

	err := db.Select("count(unique_vuln) as cnt", "severity_int").Group("severity_int").Find(&group).Error
	return group, err
}

func (s *ScannerOrm) InsertScanImage(ctx context.Context, sis []model.ScanImage) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	if len(sis) == 0 {
		return 0, nil
	}
	db := s.rdb.Get().WithContext(ctx).Create(&sis)
	return db.RowsAffected, db.Error
}

func (s *ScannerOrm) UpdateImage(ctx context.Context, where string, updater map[string]interface{}, image *model.ImageList) error {
	if len(where) == 0 {
		return fmt.Errorf("no where condition")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	var err error
	db := s.rdb.Get().Model(new(model.ImageList)).WithContext(ctx).Where(where)

	if len(updater) > 0 {
		err = db.Updates(updater).Error
	} else if image != nil {
		err = db.Select("*").Omit("id", "created_at").Updates(image).Error
	}
	return err
}

func (s *ScannerOrm) SearchScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var status harbor.ScanAllStatus
	var tmpScanImage []model.ScanImage
	var total int
	var doingNum, errorNum, successNum, pendingNum int
	s.rdb.Get().WithContext(ctx).Model(&model.ScanImage{}).Select("ivan_scanner_scan_images.image_id,ivan_scanner_scan_images.status").Joins("join ivan_scanner_image_list on ivan_scanner_image_list.id=ivan_scanner_scan_images.image_id").
		Where(fmt.Sprintf("ivan_scanner_image_list.from_type = %d and ivan_scanner_scan_images.id >0", fromType)).Find(&tmpScanImage) // 可能分段查询更好,todo
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
	res := s.rdb.Get().WithContext(ctx).Where("id = ?", registryID).First(&tmp)
	if res.Error != nil {
		return ""
	}
	decryPass, err := util.DesDecrypt(tmp.Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		logging.GetLogger().Err(err).Msg("NewCipher Error")
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
	res := s.rdb.Get().WithContext(ctx).Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.Error != nil {
		return -1, nil
	}
	return tmp.ID, nil
}

func (s *ScannerOrm) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.ScanImage{}
	res := s.rdb.Get().WithContext(ctx).Where(&model.ScanImage{ImageID: ScanImage.ImageID}).First(&tmp)
	if res.Error != nil {
		err := s.rdb.Get().Create(ScanImage).Error
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
	err := s.rdb.Get().WithContext(ctx).Model(tmpImage).Updates(ScanImage).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *ScannerOrm) GetTaskFromImageList(ctx context.Context, imgID int64, fromURL string, auth string) (model.ScanTask, model.VirusScanTask, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.ImageList{}
	if err := s.rdb.Get().WithContext(ctx).Where("id = ? ", imgID).First(&tmp).Error; err != nil {
		return model.ScanTask{}, model.VirusScanTask{}, fmt.Errorf("未找到对应镜像记录: %+v", err)
	}
	// 支持多仓库，而且有节点镜像，所以这里的URL最好通过regestryID去查
	logging.GetLogger().Info().Msgf("GetTaskFromImageList:Tem:%+v", tmp)
	regs, _, err := s.SearchRegistry(ctx, SearchRegistryParam{ID: tmp.RegistryID}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("GetTaskFromImageList imageID:%d,regestryId:%d", imgID, tmp.RegistryID)
		return model.ScanTask{}, model.VirusScanTask{}, err
	}
	if len(regs) == 0 {
		logging.GetLogger().Info().Msgf("GetTaskFromImageList not find registry imageID:%d,registryId:%d", imgID, tmp.RegistryID)
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
		ttmp.ImageID = imageID
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
	res := s.rdb.Get().WithContext(ctx).Where(&model.ImageList{FullRepoName: param.RepositoryName, Tags: param.Tag, Digest: param.Digest}).First(&tmp)
	if res.Error != nil {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = s.rdb.Get().WithContext(ctx).Where(&model.ScanImage{ImageID: tmp.ID}).First(&tmpScanImage)
	if res.Error != nil {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (s *ScannerOrm) GroupImageFlags(ctx context.Context, param GetImageOverViewParam) ([]model.ImageFlagGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := s.rdb.Get().WithContext(ctx).Model(new(model.ImageList))
	res := make([]model.ImageFlagGroup, 0)
	db = db.Select("count(*) as cnt", "flag").Group("flag")
	if param.FlagMore > 0 {
		db = db.Where("flag > ?", param.FlagMore)
	}
	if param.FlagLess > 0 {
		db = db.Where("flag < ?", param.FlagLess)
	}
	if param.FromType > 0 {
		db = db.Where("from_type = ?", param.FromType)
	}

	if param.Online == consts.TrueString {
		db = db.Where("image_uuid IN ( ? )", GetOnlineImageUUIDSub(ctx, s.rdb.Get()))
	}

	if len(param.ImageUUIDs) > 0 {
		db = db.Where("image_uuid IN ?", param.ImageUUIDs)
	}
	if len(param.RegistryIds) > 0 {
		db = db.Where("registry_id IN ?", param.RegistryIds)
	}

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) SearchScanImage(ctx context.Context, param SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*30)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.ScanImage)).WithContext(ctx)

	if len(param.Ids) > 0 {
		if len(param.Ids) == 1 {
			db = db.Where("id = ? ", param.Ids[0])
		} else {
			db = db.Where("id IN ? ", param.Ids)
		}
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("scan_task_id IN ? ", param.TaskIds)
	}
	if param.Online == consts.TrueString {
		db = db.Where("image_id IN ( ? )", GetOnlineImageIdSub(ctx, s.rdb.Get()))
	}
	if len(param.ImageIds) > 0 {
		db = db.Where("image_id IN ? ", param.ImageIds)
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
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *ScannerOrm) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.Registry)).WithContext(ctx)
	// 默认查询没有删除的,如果不传就是0
	if len(param.RegistryIds) > 0 {
		db = db.Where("id IN ? ", param.RegistryIds)
	}
	if param.ID > 0 {
		db = db.Where("id = ? ", param.ID)
	}
	if param.LibraryURL != "" {
		db = db.Where("url = ? ", param.LibraryURL)
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

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := s.rdb.Get().Model(new(model.ImageList)).WithContext(ctx)

	if param.Keyword != "" && strings.Contains(param.Keyword, ":") {
		split := strings.Split(param.Keyword, ":")
		if len(split) >= 2 {
			param.RepoKeyword = split[0]
			param.TagKeyword = split[1]
			param.Keyword = ""
		}
	}

	if len(param.Digests) > 0 {
		db = db.Where("digest IN ? ", param.Digests)
	}
	if len(param.UUIDs) > 0 {
		db = db.Where("image_uuid IN ? ", param.UUIDs)
	}
	if len(param.Projects) > 0 {
		where := make([]string, 0)
		for i := range param.Projects {
			if param.Projects[i].Project == "" {
				where = append(where, fmt.Sprintf("(registry_id = %d)", param.Projects[i].RegistryID))
			} else {
				where = append(where, fmt.Sprintf("(registry_id = %d  AND project = '%s')", param.Projects[i].RegistryID, param.Projects[i].Project))
			}
		}
		db = db.Where(strings.Join(where, " OR "))
	}

	if len(param.Libraries) > 0 {
		db = db.Where("library IN ? ", param.Libraries)
	}

	if len(param.InIds) > 0 {
		db = db.Where("id IN ? ", param.InIds)
	}
	if len(param.NotInIds) > 0 {
		db = db.Where("id NOT IN ? ", param.NotInIds)
	}
	if len(param.NodeHostnames) > 0 {
		db = db.Where("node_hostname IN ? ", param.NodeHostnames)
	}

	if len(param.RegistryIds) > 0 {
		db = db.Where("registry_id IN ? ", param.RegistryIds)
	}

	if len(param.Libraries) > 0 {
		db = db.Where("library IN  ? ", param.Libraries)
	}

	if param.Keyword != "" {
		db = db.Where("full_repo_name LIKE ?  OR tags LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}

	if param.RepoKeyword != "" {
		db = db.Where("full_repo_name LIKE ?  ", fmt.Sprintf("%%%s%%", param.RepoKeyword))
	}
	if param.TagKeyword != "" {
		db = db.Where(" tags LIKE ? ", fmt.Sprintf("%%%s%%", param.TagKeyword))
	}

	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tags = ? ", param.Tag)
	}

	if param.UniqueImage > 0 {
		db = db.Where("unique_image = ?", param.UniqueImage)
	}
	if len(param.Where) > 0 {
		db = db.Where(param.Where)
	}

	if param.LayersPrefix != "" {
		db = db.Where("layers LIKE ?", fmt.Sprintf("%s%%", param.LayersPrefix))
	}

	// 属性取交集
	if param.AttrIntersection == consts.AndString {
		if param.AttrFlag > 0 {
			db = db.Where("flag & ? = ?", param.AttrFlag, param.AttrFlag)
		}
		if param.TrustedImage == consts.FalseString {
			sub := s.rdb.Get().WithContext(ctx).Model(new(model.TrustedImages)).Select("distinct digest").Where("is_trusted > 0 ")
			db = db.Where("digest NOT  IN ( ? )", sub)
		}
	}
	// 属性取并集
	if param.AttrIntersection == consts.OrString {
		where := make([]string, 0)
		if param.AttrFlag > 0 {
			where = append(where, fmt.Sprintf("(flag & %d > 0)", param.AttrFlag))
		}
		// 非可信镜像单处理
		if param.TrustedImage == consts.FalseString {
			where = append(where, fmt.Sprintf("(flag & %d = 0)", util.SetBit1(0, model.FlagImageTrusted)))
		}

		if len(where) > 0 {
			db = db.Where(strings.Join(where, " OR "))
		}
	}

	// 安全问题取交集
	if param.IssueIntersection == consts.AndString && param.SecurityIssueFlag > 0 {
		db = db.Where("flag & ? = ?", param.SecurityIssueFlag, param.SecurityIssueFlag)
	}

	// 安全问题取并集
	if param.IssueIntersection == consts.OrString && param.SecurityIssueFlag > 0 {
		db = db.Where("flag & ? > 0", param.SecurityIssueFlag)
	}
	// 扫描状态
	if param.ScanStatusFlag > 0 {
		db = db.Where("flag & ? > 0 ", param.ScanStatusFlag)
	}

	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if len(param.OmitFields) > 0 {
		db = db.Omit(param.OmitFields...)
	}
	if param.OnlineImage == consts.TrueString || param.OnlineImage == consts.FalseString {
		sub := GetOnlineImageUUIDSub(ctx, s.rdb.Get())
		if param.OnlineImage == consts.TrueString {
			db = db.Where("image_uuid IN ( ? )", sub)
		} else {
			db = db.Where("image_uuid NOT IN ( ? )", sub)
		}
	}

	// 先查总数
	var cnt int64
	if !param.NotCount {
		if err := db.Count(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}
	if param.JustCount {
		return nil, cnt, nil
	}

	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}

	db = model.AddFilter(db, filter)

	res := make([]model.ImageList, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// serialize
	for i := range res {
		res[i].Serialize()
		res[i].Deserialize(!param.NotParseNodeImage)
	}

	return res, cnt, nil
}

func (s *ScannerOrm) InsertAdapterImageList(ctx context.Context, im model.ImageList) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.ImageList{}
	res := s.rdb.Get().WithContext(ctx).Where("full_repo_name=? AND digest = ? AND registry_id = ?", im.FullRepoName, im.Digest, im.RegistryID).First(&tmp)
	if res.Error != nil {
		err := s.rdb.Get().Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := s.rdb.Get().Model(tmp).Updates(&im).Error
	return tmp.ID, err
}

// CreateRejectRecord 创建记录，
func (s *ScannerOrm) CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	data.ReasonFlag = data.GenReasonFlag()
	// if data.Library == "" {
	// 	return nil, errors.New("no library")
	// }
	if data.FullRepoName == "" {
		return nil, errors.New("no full repo name")
	}
	// if data.Tag == "" {
	// 	return nil, errors.New("no tag")
	// }
	if data.ReasonFlag <= 0 {
		return nil, errors.New("no reject reason")
	}
	if data.RejectDetail == "" {
		return nil, errors.New("no reject detail")
	}

	err := s.rdb.Get().WithContext(ctx).Create(&data).Error
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
		timeParse string
	)
	records := make([]model.RejectRecord, 0)
	res := make([]IntervalDateGroup, 0)
	interMap := make(map[string]*IntervalDateGroup)
	now := time.Now()

	switch intervalType {

	case consts.IntervalHour:

		startAt = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-time.Duration(interval-1) * time.Hour).UTC()
		timeParse = consts.TimeFormatWithHour
	case consts.IntervalDay:
		startAt = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(interval - 1)).UTC()
		timeParse = consts.TimeFormatWithDay
	}

	db := s.rdb.Get().WithContext(ctx)
	if err := db.Where("reject_at >= ?", startAt).Find(&records).Error; err != nil {
		return nil, err
	}

	for i := range records {
		key := records[i].RejectAt.Format(timeParse)
		idt, err := time.Parse(timeParse, key)
		if err != nil {
			return nil, err
		}
		if _, ok := interMap[key]; !ok {
			interMap[key] = &IntervalDateGroup{
				IntervalDate:     key,
				Count:            0,
				IntervalDateTime: idt,
			}
		}
		interMap[key].Count++
	}

	for _, v := range interMap {
		res = append(res, *v)
	}
	sort.Sort(IntervalDateGroups(res))
	return res, nil
}

func (s *ScannerOrm) OverviewReasonTopN(ctx context.Context, param OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	res := make([]model.RejectReasonStatistic, 0)
	// 取全表数据
	db := s.rdb.Get().WithContext(ctx)
	type group struct {
		Count      int64  `gorm:"column:cnt" json:"count"`
		ReasonFlag uint64 `gorm:"column:reason_flag" json:"reason_flag"`
	}
	records := make([]group, 0)
	if err := db.Model(new(model.RejectRecord)).Select("count(*) as cnt", "reason_flag").
		Group("reason_flag").Find(&records).Error; err != nil {
		return res, err
	}
	// 统计
	statistics := make(map[int64]int64)
	for _, rec := range records {
		rrs := model.GetRejectReason(model.LangZh)

		for re := range rrs {
			if model.ExistFlag(rec.ReasonFlag, uint64(re)) {
				statistics[re] += rec.Count
			}
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
	return res, nil
}

func (s *ScannerOrm) SearchRejectRecord(ctx context.Context, param SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*15)
	defer cancelFunc()
	db := s.rdb.Get().Model(new(model.RejectRecord)).WithContext(ctx)
	if !param.StartAt.IsZero() {
		db = db.Where("reject_at >= ?", param.StartAt)
	}
	if !param.EndAt.IsZero() {
		db = db.Where("reject_at <= ?", param.EndAt)
	}
	if param.Search != "" {
		db = db.Where("full_repo_name LIKE ? OR tag LIKE ?  ", fmt.Sprintf("%%%s%%", param.Search), fmt.Sprintf("%%%s%%", param.Search))
	}

	if len(param.Libraries) > 0 {
		db = db.Where("library IN ? ", param.Libraries)
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tag = ? ", param.Tag)
	}
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	// 计算count
	var cnt int64

	if param.RejectReasons > 0 {
		db = db.Where("reason_flag & ? = ?", param.RejectReasons, param.RejectReasons)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	if param.JustCount {
		return nil, cnt, nil
	}
	db = model.AddFilter(db, filter)
	res := make([]model.RejectRecord, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// 序列化数据
	for i := range res {
		res[i].Deserialize()
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
	err := s.rdb.Get().WithContext(ctx).Create(&data).Error
	return &data, err
}

func (s *ScannerOrm) SearchImageWhitelist(ctx context.Context, param SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(new(model.ImageWhitelist))
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

	err := s.rdb.Get().WithContext(ctx).Where("id = ?", param.WhiteID).Delete(&model.ImageWhitelist{}).Error
	return err
}

func (s *ScannerOrm) GetInprogressTaskAndSetStatus(ctx context.Context, maxInprogress int64, dequeNum int64, regIds []int64) ([]model.Task, error) {
	if len(regIds) == 0 {
		return nil, fmt.Errorf("no regids")
	}
	if maxInprogress <= 0 {
		return nil, fmt.Errorf("maxInprogress less than 0")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.rdb.Get().WithContext(ctx).Model(&model.Task{})
	tx := db.Begin()

	var inp int64
	if err := tx.Where("status = ?", consts.InProgress).Count(&inp).Error; err != nil {
		return nil, err
	}

	if inp >= maxInprogress {
		return []model.Task{}, nil
	}
	ans := make([]model.Task, 0)

	limit := maxInprogress - inp
	if limit >= dequeNum {
		limit = dequeNum
	}

	if err := tx.Where("status = ?", consts.Pending).Where("registry_id IN ?", regIds).Limit(int(limit)).Find(&ans).Error; err != nil {
		return nil, err
	}
	ids := make([]int64, 0)
	for i := range ans {
		ids = append(ids, ans[i].ID)
	}
	if len(ids) == 0 {
		return []model.Task{}, nil
	}
	updateInfo := make(map[string]interface{})
	updateInfo["heart_beat"] = time.Now()
	updateInfo["status"] = consts.InProgress
	updateInfo["scanner_id"] = global.ScannerPodID

	if err := tx.Where("id IN ?", ids).Updates(updateInfo).Error; err != nil {
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return ans, nil
}

func (s *ScannerOrm) UpdateTasksInfo(ctx context.Context, param SearchTaskParam, updateInfo map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(model.Task{})
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

	db := s.rdb.Get().WithContext(ctx).Model(model.Task{}).Where("id = ?", task.ID)
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
	db := s.rdb.Get().WithContext(ctx).Model(model.Task{}).Where("id IN ?", updateIds).Updates(res)
	return db.Error
}

func (s *ScannerOrm) UpdateSubTasksInfo(ctx context.Context, param SearchSubTaskParam, updateInfo map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(model.SubTask{})
	if len(param.Ids) > 0 {
		db = db.Where("id IN ? ", param.Ids)
	}
	if len(param.Statuses) > 0 {
		db = db.Where("status IN ? ", param.Statuses)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("task_id In ? ", param.TaskIds)
	}
	if param.GreaterThanRetryCount > 0 {
		db = db.Where("retry_count >= ? ", param.GreaterThanRetryCount)
	}
	if param.ImageID > 0 {
		db = db.Where("image_id =  ?", param.ImageID)
	}

	db = db.Updates(updateInfo)
	return db.Error
}

func (s *ScannerOrm) AddSubTasksRetryCount(ctx context.Context, ids []int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(model.SubTask{}).Where("id IN ? ", ids).
		UpdateColumn("retry_count", gorm.Expr("retry_count + ?", 1))

	return db.Error
}

func (s *ScannerOrm) GetTotalTaskNum(ctx context.Context) (int64, error) {
	db := s.rdb.Get().WithContext(ctx).Model(new(model.Task))
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return 0, err
	}
	return cnt, nil
}

func (s *ScannerOrm) GetRegistryInfo(ctx context.Context, ID int64) (*model.Registry, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.Registry{}
	if err := s.rdb.Get().WithContext(ctx).Where("id = ? ", ID).First(&tmp).Error; err != nil {
		return nil, fmt.Errorf("not find registry:%v", err)
	}

	return &tmp, nil
}

func (s *ScannerOrm) AddTaskAndSubTask(ctx context.Context, task model.Task, subtask []model.SubTask) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Minute*10) // 对于定时任务，要扫描的镜像很多
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx)
	tx := db.Begin()

	if err := tx.Model(model.Task{}).Create(&task).Error; err != nil {
		tx.Rollback()
		return 0, err
	}

	// fill taskId to subTask
	for k := range subtask {
		subtask[k].TaskID = task.ID
	}

	if err := tx.Model(model.SubTask{}).CreateInBatches(&subtask, consts.SubTaskBatchInsertCount).Error; err != nil {
		tx.Rollback()
		return 0, err
	}

	err := tx.Commit().Error
	if err != nil {
		return 0, err
	}
	return task.ID, nil
}

func (s *ScannerOrm) AddTask(ctx context.Context, task model.Task) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	if err := s.rdb.Get().WithContext(ctx).Model(model.Task{}).Create(&task).Error; err != nil {
		return 0, err
	}

	return task.ID, nil
}

func (s *ScannerOrm) AddSubTask(ctx context.Context, subtask []model.SubTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*30)
	defer cancelFunc()
	if err := s.rdb.Get().WithContext(ctx).Model(model.SubTask{}).CreateInBatches(&subtask, consts.SubTaskBatchInsertCount).Error; err != nil {
		return err
	}

	return nil
}

func (s *ScannerOrm) GetSubTasks(ctx context.Context, param SearchSubTaskParam, filter *model.Filter) ([]model.SubTask, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(new(model.SubTask))
	if len(param.Statuses) > 0 {
		db = db.Where("status in  ?  ", param.Statuses)
	}
	if len(param.TaskIds) > 0 {
		db = db.Where("task_id in ? ", param.TaskIds)
	}
	if len(param.Ids) > 0 {
		db = db.Where("id in ? ", param.Ids)
	}
	if param.LessThanRetryCount > 0 {
		db = db.Where("retry_count < ? ", param.LessThanRetryCount)
	}
	if param.LastID > 0 {
		db = db.Where("id > ? ", param.LastID)
	}
	if param.ImageID > 0 {
		db = db.Where("image_id = ? ", param.ImageID)
	}
	if param.LessThanRetryCount > 0 {
		db = db.Where("retry_count >= ? ", param.GreaterThanRetryCount)
	}

	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	if param.JustCount {
		return nil, cnt, nil
	}
	db = model.AddFilter(db, filter)
	res := make([]model.SubTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}

	return res, cnt, nil
}

func (s *ScannerOrm) CreateTasks(ctx context.Context, tasks ...model.Task) error {
	return s.rdb.Get().Model(model.Task{}).CreateInBatches(tasks, 100).Error
}

func (s *ScannerOrm) UpdateTaskStatus(ctx context.Context, groupID int64, status uint8) ([]int64, error) {
	data := make([]model.Task, 0)
	begin := s.rdb.Get().WithContext(ctx).Begin()
	var err error

	defer func() {
		if err != nil {
			begin.Rollback()
		}
	}()

	err = begin.Model(data).Clauses(clause.Locking{Strength: "UPDATE"}).Where("group_id = ?", groupID).Find(&data).Error
	if err != nil {
		return nil, err
	}

	taskIds := make([]int64, 0)
	for i := range data {
		if err = StatusCheck(uint8(data[i].Status), status); err == nil {
			taskIds = append(taskIds, data[i].ID)
		} else {
			logging.GetLogger().Info().Int64("taskID", data[i].ID).Int64("groupID", groupID).Msg("UpdateTaskStatus StatusCheck")
		}
	}
	if len(taskIds) == 0 {
		return taskIds, nil
	}

	err = begin.Model(&model.Task{}).Where("id IN  ?", taskIds).UpdateColumn("status", status).Error

	if err != nil {
		return nil, err
	}

	err = begin.Commit().Error
	if err != nil {
		return taskIds, nil
	}

	return taskIds, nil
}

func (s *ScannerOrm) GetTaskList(ctx context.Context, param SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx).Model(model.Task{})

	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	if len(param.ExcludeStatus) > 0 {
		db = db.Where("status NOT IN ?", param.ExcludeStatus)
	}
	if len(param.Statuses) > 0 {
		db = db.Where("status IN ?", param.Statuses)
	}
	if param.StrategyID > 0 {
		db = db.Where("policy_id =  ?", param.StrategyID)
	}
	if param.GroupID > 0 {
		db = db.Where("group_id =  ?", param.GroupID)
	}
	if param.DistinctFiled != "" {
		db = db.Distinct(param.DistinctFiled)
	}
	if len(param.RegIds) > 0 {
		db = db.Where("registry_id IN ? ", param.RegIds)
	}
	var cnt int64
	// 先找出所有的taskID，然后求得subtask的数量
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.Task, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	return res, cnt, nil
}

type GroupSubtaskRes struct {
	Count  int64 `gorm:"column:cnt" json:"count"`
	Status int64 `gorm:"column:status" json:"status"`
}

func (s *ScannerOrm) GroupSubtask(ctx context.Context, taskGroupId int64) ([]GroupSubtaskRes, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := s.rdb.Get().WithContext(ctx)

	res := make([]GroupSubtaskRes, 0)

	sql := fmt.Sprintf("select count(b.id) as cnt,b.status from %s a join %s b on a.id=b.task_id where a.group_id = %d group by b.status,a.group_id;",
		model.Task{}.TableName(), model.SubTask{}.TableName(), taskGroupId)

	err := db.Raw(sql).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScannerOrm) GetSubTaskListWithImage(ctx context.Context, param GetSubTaskListWithImageParam, filter *model.Filter) ([]model.SubTask, int64, error) {

	data := make([]model.SubTask, 0)
	var count int64

	db := s.rdb.Get().WithContext(ctx).Model(model.SubTask{}).Where("task_id IN ?", param.TaskIds)
	if len(param.Status) > 0 {
		db = db.Where("status IN ?", param.Status)
	}

	if err := db.Count(&count).Error; err != nil {
		return nil, 0, errors.Wrap(err, "get subtask total count failed")
	}
	db = model.AddFilter(db, filter)
	if err := db.Find(&data).Error; err != nil {
		return nil, 0, errors.Wrap(err, "get subtask data failed")
	}

	return data, count, nil
}

func (s *ScannerOrm) SetSingleStrategy(ctx context.Context, envName string, policyID []int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := make([]model.ScanStrategy, 0)
	err := s.rdb.Get().WithContext(ctx).Where("is_default != ? and id in ?", true, policyID).Find(&res).Error
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
			logging.GetLogger().Err(err).Msgf("marshal env form db error")
			continue
		}
		envStr := string(envByte)
		err = s.rdb.Get().Model(&model.ScanStrategy{}).Where("id = ?", res[k].ID).Update("envs", envStr).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("updata env form db error")
			continue
		}
	}
	return nil
}

func (s *ScannerOrm) GetAllScanStrategyEnv(ctx context.Context) ([]model.ScanStrategy, error) { // 这个接口留待下版本优化

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := []model.ScanStrategy{}
	err := s.rdb.Get().WithContext(ctx).Select("id", "envs", "name").Where("is_default != ?", true).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

// 可能会有并发冲突，但是不影响最后的结果，只保存最后的扫描状态
func (s *ScannerOrm) UpdateImageScanStatus(ctx context.Context, imageID int64, status uint64) error {
	// 查出镜像
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	images := make([]model.ImageList, 0)
	if err := s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Where("id = ?", imageID).Find(&images).Error; err != nil {
		return err
	}

	if len(images) == 0 {
		return fmt.Errorf("not fond image:%d", imageID)
	}

	image := images[0]
	logging.GetLogger().Info().Uint64("PreFlag", image.Flag).Uint64("scanStatus", status).Int64("imageID", imageID).Msg("UpdateImageScanStatus")

	image.SetScanStatusFlag(status)

	logging.GetLogger().Info().Uint64("AfterFlag", image.Flag).Uint64("scanStatus", status).Int64("imageID", imageID).Msg("UpdateImageScanStatus")
	// 更新状态
	updater := map[string]interface{}{"flag": image.Flag}
	if err := s.rdb.Get().WithContext(ctx).Model(model.ImageList{}).Where("id = ?", imageID).Updates(updater).Error; err != nil {
		return err
	}
	return nil
}
