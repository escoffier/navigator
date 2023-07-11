package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type VersionDal interface {
	CreateVersion(ctx context.Context, version scannermodel.ScanDBVersion) error
	SearchVersion(ctx context.Context, params SearchVersionParam, filter model.Filter) ([]scannermodel.ScanDBVersion, int64, error)
	UpdateVersion(ctx context.Context, value any, objType string) error
	SearchVersionMate(ctx context.Context, params SearchVersionMateParam, filter model.Filter) ([]scannermodel.ScanDbMateData, int64, error)
	CreateVersionMate(ctx context.Context, versionMate []scannermodel.ScanDbMateData) error
	UpdateVersionMate(ctx context.Context, versionMate scannermodel.ScanDbMateData) error
	SearchVersionHistory(ctx context.Context, params SearchVersionHistoryParam, filter model.Filter) ([]scannermodel.ScanDBUpdateHistroy, int64, error)
	CreateVersionHistory(ctx context.Context, versionHistroy scannermodel.ScanDBUpdateHistroy) error
	UpdateVersionHistory(ctx context.Context, versionHistory scannermodel.ScanDBUpdateHistroy) error
	Update(ctx context.Context, value []byte, param string) error
	Create(ctx context.Context, value []byte, param any) error
}

type SearchVersionParam struct {
	ClusterKey string
}

type SearchVersionMateParam struct {
	UUID []uint64
}

type SearchVersionHistoryParam struct {
	UUID   []uint64
	Search string
	DBType []string
}

type VersionDao struct {
	rdb *databases.RDBInstance
}

var singeVersionDao *VersionDao

func NewVersionDao(rdb *databases.RDBInstance) *VersionDao {
	if singeVersionDao != nil {
		return singeVersionDao
	}
	singeVersionDao = &VersionDao{rdb: rdb}
	return singeVersionDao
}

func GetSingeVersionDao() *VersionDao {
	if singeVersionDao != nil {
		return singeVersionDao
	}
	singeVersionDao = &VersionDao{rdb: GetScannerWrapperDb()}
	return singeVersionDao
}

func (v *VersionDao) CreateVersion(ctx context.Context, version scannermodel.ScanDBVersion) error {
	err := v.rdb.Get().Model(&scannermodel.ScanDBVersion{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key_path"}},
		DoNothing: true,
	}).Create(&version).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("create version err key_path:%v", version.KeyPath)
		return err
	}
	return nil
}

func (v *VersionDao) UpdateVersion(ctx context.Context, value any, objType string) error {
	version, ok := value.(scannermodel.ScanDBVersion)
	if !ok {
		return fmt.Errorf("value not scanDBVersion")
	}
	_, cnt, _ := v.SearchVersion(ctx, SearchVersionParam{version.KeyPath}, model.Filter{})
	if cnt == 0 {
		err := v.CreateVersion(ctx, version)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init version error data:%v", version)
			return err
		}
	} else {
		logging.GetLogger().Info().Msgf("update version ops %v value:%v", objType, version)
		db := v.rdb.Get().Model(&scannermodel.ScanDBVersion{})
		if objType == scannermodel.ClamavDB {
			db = db.Omit("vuln_db_version")
			db = db.Omit("avira_db_version")
		}
		if objType == scannermodel.TrivyDB {
			db = db.Omit("avira_db_version")
			db = db.Omit("clamav_db_version")
		}
		if objType == scannermodel.AviraDB {
			db = db.Omit("clamav_db_version")
			db = db.Omit("vuln_db_version")
		}
		err := db.Where("key_path = ?", version.KeyPath).Updates(&version).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("update version error data:%v", version)
			return err
		}
	}
	return nil
}

func (v *VersionDao) SearchVersion(ctx context.Context, params SearchVersionParam, filter model.Filter) ([]scannermodel.ScanDBVersion, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().Model(&scannermodel.ScanDBVersion{}).WithContext(ctx)
	if params.ClusterKey != "" {
		db = db.Where("key_path = ?", params.ClusterKey)
	}
	res := []scannermodel.ScanDBVersion{}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Count DBVersion error")
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
		logging.GetLogger().Err(err).Msgf("find version error")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (v *VersionDao) SearchVersionMate(ctx context.Context, params SearchVersionMateParam, filter model.Filter) ([]scannermodel.ScanDbMateData, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().Model(&scannermodel.ScanDbMateData{}).WithContext(ctx)
	if len(params.UUID) != 0 {
		db = db.Where("uuid in ?", params.UUID)
	}
	res := []scannermodel.ScanDbMateData{}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Count DBVersion error")
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
		logging.GetLogger().Err(err).Msgf("find version error")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (v *VersionDao) CreateVersionMate(ctx context.Context, versionMate []scannermodel.ScanDbMateData) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	for k := range versionMate {
		if versionMate[k].UUID == 0 {
			versionMate[k].UUID = versionMate[k].GetUUID()
		}
		err := v.rdb.Get().Model(&scannermodel.ScanDbMateData{}).WithContext(ctx).Create(&versionMate[k]).Error
		if err != nil {
			logging.GetLogger().Err(err).Msg("create new scanDBMateDate error")
			return err
		}
	}
	return nil
}

func (v *VersionDao) UpdateVersionMate(ctx context.Context, versionMate scannermodel.ScanDbMateData) error {
	_, cnt, _ := v.SearchVersionMate(ctx, SearchVersionMateParam{UUID: []uint64{versionMate.GetUUID()}}, model.Filter{})
	if cnt == 0 {
		err := v.CreateVersionMate(ctx, []scannermodel.ScanDbMateData{versionMate})
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init version error data:%v", versionMate)
			return err
		}
	} else {
		err := v.rdb.Get().Model(&scannermodel.ScanDBVersion{}).Where("uuid = ?", versionMate.UUID).Updates(&versionMate).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("update version error data:%v", versionMate)
			return err
		}
	}
	return nil
}

func (v *VersionDao) SearchVersionHistory(ctx context.Context, params SearchVersionHistoryParam, filter model.Filter) ([]scannermodel.ScanDBUpdateHistroy, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().Model(&scannermodel.ScanDBUpdateHistroy{}).WithContext(ctx)
	if len(params.UUID) != 0 {
		db = db.Where("uuid in ?", params.UUID)
	}
	if params.Search != "" {
		db = db.Where("compress_db_version like ?", fmt.Sprintf("%%%s%%", params.Search))
	}

	if len(params.DBType) != 0 {
		db = db.Where("db_type in ?", params.DBType)
	}

	res := []scannermodel.ScanDBUpdateHistroy{}
	var cnt int64
	err := db.Count(&cnt).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("Count DBVersion error")
		return nil, 0, err
	}
	if filter.Limit != 0 {
		db = db.Limit(int(filter.Limit))
	}

	if filter.Offset != 0 {
		db = db.Offset(int(filter.Offset))
	}
	db.Order("updated_at DESC")
	err = db.Find(&res).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("find version error")
		return nil, 0, err
	}
	return res, cnt, nil
}

func (v *VersionDao) CreateVersionHistory(ctx context.Context, versionHistory scannermodel.ScanDBUpdateHistroy) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	err := v.rdb.Get().Model(&scannermodel.ScanDBUpdateHistroy{}).WithContext(ctx).Create(&versionHistory).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("create new scanDBMateDate error")
		return err
	}
	return nil
}

func (v *VersionDao) UpdateVersionHistory(ctx context.Context, versionHistory scannermodel.ScanDBUpdateHistroy) error {
	_, cnt, _ := v.SearchVersionHistory(ctx, SearchVersionHistoryParam{UUID: []uint64{versionHistory.GetUUID()}}, model.Filter{})
	if cnt == 0 {
		err := v.CreateVersionHistory(ctx, versionHistory)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init version error data:%v", versionHistory)
			return err
		}
	} else {
		err := v.rdb.Get().Model(&scannermodel.ScanDBVersion{}).Where("uuid = ?", versionHistory.UUID).Updates(&versionHistory).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("update version error data:%v", versionHistory)
			return err
		}
	}
	return nil
}

func (v *VersionDao) Update(ctx context.Context, value []byte, param string) error {
	resV := scannermodel.ScanDBVersion{}
	err := json.Unmarshal(value, &resV)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("mashal to scanDBVersion error")
		return err
	}

	err = v.UpdateVersion(ctx, resV, param)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("update version error")
		return err
	}
	trivyMata := scannermodel.ScanDbMateData{DBMata: resV.VulnDBVersion.TrivyVersion, DBType: scannermodel.TrivyDB}
	customMata := scannermodel.ScanDbMateData{DBMata: resV.VulnDBVersion.CustomDBVersion, DBType: scannermodel.CustomDB}
	clamavMata := scannermodel.ScanDbMateData{DBMata: resV.ClamavDBVersion.ClamavVersion, DBType: scannermodel.ClamavDB}
	aviraMata := scannermodel.ScanDbMateData{DBMata: resV.AviraDBVersion.AvriaVersion, DBType: scannermodel.AviraDB}
	matas := []scannermodel.ScanDbMateData{trivyMata, customMata, clamavMata, aviraMata}
	err = v.CreateVersionMate(ctx, matas)
	if err != nil {
		logging.GetLogger().Err(err).Msg("CreateVersionMate error")
	}
	return nil
}

func (v *VersionDao) Create(ctx context.Context, value []byte, param any) error {
	resV := scannermodel.ScanDBVersion{}
	err := json.Unmarshal(value, &resV)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("mashal to scanDBVersion error")
		return err
	}
	return v.UpdateVersion(ctx, resV, "")
}
