package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type WebshellDalInterface interface {
	SearchWebshell(ctx context.Context, params SearchWebshellParam, filter model.Filter) ([]scannermodel.Webshell, int64, error)
	SearchWebshellImage(ctx context.Context, params SearchWebshellParam, filter model.Filter) ([]model.ScanIssueToImageWebshell, int64, error)
	SearchRegistry(ctx context.Context, images []int64) ([]scannermodel.WebshellImage, error)
	// SearchVulnImage(ctx context.Context, param SearchVulnImageParam, filter *model.Filter) ([]*model.VulnImage, int64, error)
	// SearchVulnPkg(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error)
	CreateWebshell(ctx context.Context, webshells []scannermodel.Webshell) error
	// UpdateVuln(ctx context.Context, where string, updater map[string]interface{}, vuln *model.Vuln) error
	CreateWebshellImage(ctx context.Context, imageID int64, webshells []scannermodel.Webshell) error
	// GroupImageVuln(ctx context.Context, images []int64) ([]GroupImageVuln, error)
	// DeleteVulnImage(ctx context.Context, imageIds []int64) error
}

type WebshellDao struct {
	rdb *databases.RDBInstance
}

var singeWebshellDao *WebshellDao

func NewWebsehllDao(rdb *databases.RDBInstance) *WebshellDao {
	if singeWebshellDao != nil {
		return singeWebshellDao
	}
	singeWebshellDao = &WebshellDao{rdb: rdb}
	return singeWebshellDao
}

func GetSingeWebsehllDao() *WebshellDao {
	if singeWebshellDao != nil {
		return singeWebshellDao
	}
	singeWebshellDao = &WebshellDao{rdb: GetScannerWrapperDb()}
	return singeWebshellDao
}

func (w *WebshellDao) CreateWebshell(ctx context.Context, webshells []scannermodel.Webshell) error {
	nowIds := []uint64{}
	for k := range webshells {
		webshells[k].UniqueID = webshells[k].GenUniqueVuln()
		nowIds = append(nowIds, webshells[k].UniqueID)
	}
	inTable, _, err := w.SearchWebshell(ctx, SearchWebshellParam{UUIDS: nowIds}, model.Filter{})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("search Webshell error")
		return err
	}
	mp := make(map[uint64]struct{}, 0)
	for k := range inTable {
		mp[inTable[k].UniqueID] = struct{}{}
	}
	// 同样digest的文件应该不会变 暂时不做checkSum机制
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()
	for k, v := range webshells {
		if _, ok := mp[v.UniqueID]; ok {
			continue
		}
		err := w.rdb.Get().WithContext(ctx).Model(scannermodel.Webshell{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "uuid"}},
			DoNothing: true,
		}).Create(&webshells[k]).Error
		if err != nil {
			logging.GetLogger().Err(err).Msg("CreateWebsehll")
			return err
		}
	}
	return nil
}

func (w *WebshellDao) CreateWebshellImage(ctx context.Context, imageID int64, webshells []scannermodel.Webshell) error {
	nowIds := []uint64{}
	for k := range webshells {
		webshells[k].UniqueID = webshells[k].GenUniqueVuln()
		nowIds = append(nowIds, webshells[k].UniqueID)
	}
	inTable, _, err := w.SearchWebshellImage(ctx, SearchWebshellParam{UUIDS: nowIds}, model.Filter{})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("search Webshell error")
		return err
	}
	mp := make(map[uint64]struct{}, 0)
	isCreate := make(map[uint64]struct{})
	for k := range inTable {
		mp[inTable[k].UniqueTarget] = struct{}{}
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()
	for _, v := range webshells {
		if _, ok := mp[v.UniqueID]; ok {
			continue
		}
		if _, ok := isCreate[v.UniqueID]; ok {
			continue
		}
		tmp := model.ScanIssueToImageWebshell{}
		tmp.SecurityIssue = model.FlagHasWebshell
		tmp.UniqueTarget = v.UniqueID
		tmp.LayerDigest = v.LayerDigest
		tmp.ImageID = imageID
		tmp.UniqueID = tmp.GenUniqueVuln()
		err := w.rdb.Get().WithContext(ctx).Model(model.ScanIssueToImageWebshell{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "unique_target"}},
			DoNothing: true,
		}).Create(&tmp).Error
		if err != nil {
			logging.GetLogger().Err(err).Msg("CreateWebsehllImage")
			return err
		}
		isCreate[v.UniqueID] = struct{}{}
	}
	return nil
}

func (w *WebshellDao) SearchWebshell(ctx context.Context, params SearchWebshellParam, filter model.Filter) ([]scannermodel.Webshell, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := w.rdb.Get().WithContext(ctx).Model(scannermodel.Webshell{})
	if len(params.UUIDS) > 0 {
		db = db.Where("unique_id in ?", params.UUIDS)
		//	db = db.Select("unique_id")
	}

	if len(params.Level) != 0 {
		db = db.Where("level in ?", params.Level)
	}

	if params.Search != "" {
		db = db.Where("file_name like ? ", fmt.Sprintf("%%%s%%", params.Search))
	}

	if params.Md5 != "" {
		db = db.Where("file_md5 = ?", params.Md5)
		//	db = db.Select("unique_id")
	}

	if params.LayerDigest != "" {
		db = db.Where("layer_digest = ?", params.LayerDigest)
	}

	res := []scannermodel.Webshell{}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Count Webshell error")
		return nil, 0, err
	}
	if filter.Limit != 0 {
		db = db.Limit(int(filter.Limit))
	}

	if filter.Offset != 0 {
		db = db.Offset(int(filter.Offset))
	}

	err = db.Find(&res).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Find Webshell error")
		return nil, 0, err
	}
	return res, cnt, err
}

// func (w *WebshellDao) SearchWebshellImage(ctx context.Context, params SearchWebshellParam) ([]scannermodel.WebshellImage, int64, error) {
// 	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
// 	defer cancelFunc()
// 	db := w.rdb.Get().WithContext(ctx).Model(scannermodel.WebshellImage{})
// 	if len(params.UUIDS) > 0 {
// 		db.Where("uuid in ?", params.UUIDS)
// 	}
// 	res := []scannermodel.WebshellImage{}
// 	var cnt int64
// 	err := db.Count(&cnt).Error
// 	if err != nil {
// 		logging.GetLogger().Err(err).Msg("Count WebshellImage error")
// 		return nil, 0, err
// 	}

// 	err = db.Find(&res).Error
// 	if err != nil {
// 		logging.GetLogger().Err(err).Msg("Find WebshellImage error")
// 		return nil, 0, err
// 	}
// 	return res, cnt, err
// }

func (w *WebshellDao) SearchWebshellImage(ctx context.Context, params SearchWebshellParam, filter model.Filter) ([]model.ScanIssueToImageWebshell, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := w.rdb.Get().WithContext(ctx).Model(model.ScanIssueToImageWebshell{})
	db = db.Where("security_issue = ?", model.FlagHasWebshell)
	if params.ImageID != 0 {
		db = db.Where("image_id = ?", params.ImageID)
		db = db.Select("unique_target")
	}
	if len(params.UUIDS) > 0 {
		db = db.Where("unique_target in ?", params.UUIDS)
		db = db.Select("image_id")
	}
	res := []model.ScanIssueToImageWebshell{}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Count Webshell error")
		return nil, 0, err
	}

	err = db.Find(&res).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get issue list error")
		return nil, 0, err
	}
	return res, cnt, err
}

func (w *WebshellDao) SearchRegistry(ctx context.Context, images []int64) ([]scannermodel.WebshellImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := w.rdb.Get().WithContext(ctx).Model(model.ImageList{})
	db = db.Where("id in ?", images)
	tmpImages := []model.ImageList{}
	db = db.Select("full_repo_name,registry_id,tags")
	err := db.Find(&tmpImages).Error
	logging.GetLogger().Info().Msgf("select images:%v", tmpImages)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get images error")
		return nil, err
	}
	dbb := w.rdb.Get().WithContext(ctx).Model(model.Registry{})
	allRegisty := []model.Registry{}
	err = dbb.Find(&allRegisty).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get registry error")
		return nil, err
	}
	mp := make(map[int64]string, 0)
	for k := range allRegisty {
		mp[allRegisty[k].ID] = fmt.Sprintf("%s(%s)", allRegisty[k].Name, allRegisty[k].Url)
	}
	logging.GetLogger().Info().Msgf("mp is :%v", mp)
	res := []scannermodel.WebshellImage{}
	for k := range tmpImages {
		webshellImage := scannermodel.WebshellImage{}
		webshellImage.Image = fmt.Sprintf("%s:%s", tmpImages[k].FullRepoName, tmpImages[k].Tags)
		if v, ok := mp[tmpImages[k].RegistryID]; ok {
			webshellImage.Registry = v
		}
		res = append(res, webshellImage)
	}
	return res, nil
}
