package imagesecStore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像扫描结果
type ScanResultDal interface {
	// 病毒
	CreateMalware(ctx context.Context, data []*imagesecModel.Malware) error
	SearchMalware(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Malware, int64, error)
	// webshell
	CreateWebshell(ctx context.Context, data []*imagesecModel.Webshell) error
	SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Webshell, int64, error)
	// 敏感文件
	CreateSensitive(ctx context.Context, data []*imagesecModel.SensitiveFile) error
	SearchSensitive(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.SensitiveFile, int64, error)
	// 软件包
	CreatePkg(ctx context.Context, data []*imagesecModel.Pkg) error
	SearchPkg(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Pkg, int64, error)
	// 环境变量
	CreateImageEnv(ctx context.Context, imageID uint64, data []*imagesecModel.ImageEnv) error
	SearchImageEnv(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.ImageEnv, int64, error)

	// License
	CreateLicense(ctx context.Context, data []*imagesecModel.License) error
	SearchLicense(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.License, int64, error)

	// 漏洞
	CreateVuln(ctx context.Context, param imagesecModel.CreateVulnParam) error
	SearchVuln(ctx context.Context, param imagesecModel.SearchVulnDalParam) ([]*imagesecModel.Vuln, int64, error)
	CreateVulnPkg(ctx context.Context, data2 []*imagesecModel.VulnToPkg) error
	DeleteOnlineVuln(ctx context.Context, data2 []uint64) error

	CreateWebFrameInfo(ctx context.Context, imageUuid uint32, data []model.WebFrameInfo) error

	CreateScanLayerData(ctx context.Context, data []*imagesecModel.ScanLayerData) error
	SearchScanLayerData(ctx context.Context, param imagesecModel.SearchScanLayerParam) ([]*imagesecModel.ScanLayerData, error)
	DeleteScanLayerData(ctx context.Context, param imagesecModel.SearchScanLayerParam) error
	CreateScanLayerFile(ctx context.Context, data2 []*imagesecModel.LayerFile) error
}

type ScanResultDao struct {
	db *databases.RDBInstance
}

func NewScanResultDao(db *databases.RDBInstance) *ScanResultDao {
	return &ScanResultDao{db: db}
}

func (dal *ScanResultDao) CreateMalware(ctx context.Context, data2 []*imagesecModel.Malware) error {
	data := make([]*imagesecModel.Malware, 0)

	for i := range data2 {
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("malware", data2[i]).Msg("CreateMalware")
			continue
		}
		data = append(data, data2[i])
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchMalware(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.Malware, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.Malware{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchMalware(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.Malware, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	scanModel, issueModel := &imagesecModel.Malware{}, &imagesecModel.MalwareToImage{}
	scanTableName, issueTableName := scanModel.TableName(), issueModel.TableName()

	db := dal.db.Get().WithContext(ctx).Table(scanTableName)
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	if param.Keyword != "" {
		db = db.Where("filename LIKE ? OR filepath LIKE ? OR name LIKE ? ",
			fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	// 查单个镜像
	if param.ImageUniqueID > 0 {
		sub := dal.db.Get().WithContext(ctx).Table(issueTableName).
			Select("distinct unique_target").Where("image_unique_id = ?", param.ImageUniqueID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*imagesecModel.Malware, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, nil
}

func (dal *ScanResultDao) CreateWebshell(ctx context.Context, data2 []*imagesecModel.Webshell) error {

	data := make([]*imagesecModel.Webshell, 0)

	for i := range data2 {
		data2[i].Serialize()
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("webshell", data2[i]).Msg("CreateWebshell")
			continue
		}
		data = append(data, data2[i])
	}
	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].GenUniqueID())
	}

	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.Webshell, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.Webshell{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.Webshell, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	scanModel, issueModel := &imagesecModel.Webshell{}, &imagesecModel.WebshellToImage{}
	scanTableName, issueTableName := scanModel.TableName(), issueModel.TableName()

	db := dal.db.Get().WithContext(ctx).Table(scanTableName)
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	if param.Keyword != "" {
		db = db.Where("filename LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if len(param.WebshellRiskLevel) > 0 {
		db = db.Where("risk_level IN ?", param.WebshellRiskLevel)
	}
	// 查单个镜像
	if param.ImageUniqueID > 0 {
		sub := dal.db.Get().WithContext(ctx).Table(issueTableName).
			Select("distinct unique_target").Where("image_unique_id = ?", param.ImageUniqueID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*imagesecModel.Webshell, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ScanResultDao) CreateSensitive(ctx context.Context, data2 []*imagesecModel.SensitiveFile) error {
	data := make([]*imagesecModel.SensitiveFile, 0)
	for i := range data2 {
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("sensitive", data2[i]).Msg("CreateSensitive")
			continue
		}
		data = append(data, data2[i])
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchSensitive(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.SensitiveFile, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.SensitiveFile{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchSensitive(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.SensitiveFile, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	scanModel, issueModel := &imagesecModel.SensitiveFile{}, &imagesecModel.SensitiveToImage{}
	scanTableName, issueTableName := scanModel.TableName(), issueModel.TableName()

	db := dal.db.Get().WithContext(ctx).Table(scanTableName)
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	if param.Keyword != "" {
		db = db.Where("filename LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	// 查单个镜像
	if param.ImageUniqueID > 0 {
		sub := dal.db.Get().WithContext(ctx).Table(issueTableName).
			Select("distinct unique_target").Where("image_unique_id = ?", param.ImageUniqueID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*imagesecModel.SensitiveFile, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (dal *ScanResultDao) CreatePkg(ctx context.Context, data2 []*imagesecModel.Pkg) error {

	data := make([]*imagesecModel.Pkg, 0)

	for i := range data2 {
		data2[i].Serialize()
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("pkg", data2[i]).Msg("CreatePkg")
			continue
		}
		data = append(data, data2[i])
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchPkg(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.Pkg, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.Pkg{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchPkg(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.Pkg, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	scanModel, issueModel := &imagesecModel.Pkg{}, &imagesecModel.PkgToImage{}
	scanTableName, issueTableName := scanModel.TableName(), issueModel.TableName()

	db := dal.db.Get().WithContext(ctx).Table(scanTableName)
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	if param.Keyword != "" {
		db = db.Where("name LIKE ? OR version LIKE ? OR license LIKE ?", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.VulnName != "" {
		ov := imagesecModel.VulnToPkg{}
		sub := dal.db.Get().WithContext(ctx).Table(ov.TableName()).
			Select("pkg_unique_id").Where("vuln_name = ?", param.VulnName)
		db = db.Where("unique_id IN ( ? )", sub)
	}

	// 查单个镜像
	if param.ImageUniqueID > 0 {
		sub := dal.db.Get().WithContext(ctx).Table(issueTableName).
			Select("distinct unique_target").Where("image_unique_id = ?", param.ImageUniqueID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*imagesecModel.Pkg, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, nil
}

func (dal *ScanResultDao) CreateImageEnv(ctx context.Context, imageID uint64, data2 []*imagesecModel.ImageEnv) error {
	data := make([]*imagesecModel.ImageEnv, 0)
	for i := range data2 {
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("env", data2[i]).Msg("CreateImageEnv")
			continue
		}
		data = append(data, data2[i])
	}
	if len(data) == 0 {
		return nil
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()

	tableName := data[0].TableName()
	dbPre := make([]*imagesecModel.ImageEnv, 0)
	if err := dal.db.Get().Table(tableName).Where("image_unique_id = ?", imageID).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*imagesecModel.ImageEnv, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).Delete(&imagesecModel.ImageEnv{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(createData[i]).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchImageEnv(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.ImageEnv, int64, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	m := &imagesecModel.ImageEnv{}
	tableName := m.TableName()

	db := dal.db.Get().WithContext(ctx).Table(tableName)

	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	if param.Keyword != "" {
		db = db.Where("`key` LIKE ? OR `value` LIKE ? ",
			fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}

	// 查单个镜像
	if param.ImageUniqueID > 0 {
		db = db.Where("image_unique_id = ?", param.ImageUniqueID)
	}

	res := make([]*imagesecModel.ImageEnv, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ScanResultDao) CreateLicense(ctx context.Context, data2 []*imagesecModel.License) error {

	data := make([]*imagesecModel.License, 0)

	for i := range data2 {
		data2[i].Serialize()
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("license", data2[i]).Msg("CreateLicense")
			continue
		}
		data = append(data, data2[i])
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchLicense(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.License, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.License{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ScanResultDao) SearchLicense(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.License, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	scanModel, issueModel := &imagesecModel.License{}, &imagesecModel.LicenseToImage{}
	scanTableName, issueTableName := scanModel.TableName(), issueModel.TableName()

	db := dal.db.Get().WithContext(ctx).Table(scanTableName)

	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}

	if param.Keyword != "" {
		db = db.Where("filename LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}

	if len(param.LicenseSearch) > 0 {
		db = db.Where("name IN  ?  ", param.LicenseSearch)
	}
	// 查单个镜像
	if param.ImageUniqueID > 0 {
		sub := dal.db.Get().WithContext(ctx).Table(issueTableName).
			Select("distinct unique_target").Where("image_unique_id = ?", param.ImageUniqueID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	res := make([]*imagesecModel.License, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (dal *ScanResultDao) CreateVuln(ctx context.Context, param imagesecModel.CreateVulnParam) error {

	pkgVuln := make([]*imagesecModel.VulnToPkg, 0)

	data2 := param.Data

	data := make([]*imagesecModel.Vuln, 0)
	for i := range data2 {
		vu := data2[i]
		vu.Serialize()
		if err := vu.Check(); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Str("vulnName", vu.Name).Msg("CreateVuln")
			continue
		}
		if param.OnlineVuln {
			vu.OnlineVuln = true
		}
		data = append(data, vu)
	}

	uniqueIds := make([]uint64, 0)
	vulnNames := make([]string, 0)
	for i := range data {
		if param.OnlineVuln {
			vulnNames = append(vulnNames, data[i].Name)
		} else {
			uniqueIds = append(uniqueIds, data[i].UniqueID)
		}
		pv := &imagesecModel.VulnToPkg{
			VulnName:    data[i].Name,
			PkgUniqueID: data[i].PkgUniqueID,
		}

		pkgVuln = append(pkgVuln, pv)
	}
	if len(data) == 0 {
		return nil
	}
	mo := imagesecModel.Vuln{OnlineVuln: param.OnlineVuln}

	tableName := mo.TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{
		OnlineVuln:    param.OnlineVuln,
		VulnUniqueIds: uniqueIds,
		VulnNames:     vulnNames,
	})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.Vuln, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}
	logging.Get().Info().Int("deleteData", len(deleteData)).Int("dbPre", len(dbPre)).Int("createData", len(createData)).Int("allVUln", len(data)).Msg("CreateVuln")

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.SensitiveFile{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	// 存入漏洞和软件的关联关系
	if err := dal.CreateVulnPkg(ctx, pkgVuln); err != nil {
		return err
	}
	return nil
}

func (dal *ScanResultDao) SearchVuln(ctx context.Context, param imagesecModel.SearchVulnDalParam) (
	[]*imagesecModel.Vuln, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	mo := &imagesecModel.Vuln{OnlineVuln: param.OnlineVuln}

	tableName := mo.TableName()

	db := dal.db.Get().WithContext(ctx).Table(tableName)

	if len(param.VulnUniqueIds) > 0 {
		db = db.Where("unique_id IN  ?", param.VulnUniqueIds)
	}
	if len(param.VulnNames) > 0 {
		db = db.Where("name IN  ?", param.VulnNames)
	}
	if param.VulnUniqueID > 0 {
		db = db.Where("unique_id =?", param.VulnUniqueID)
	}
	if param.LanguageName != "" {
		// LanguagePath可能为空，前端是区分了这种情况，所以要一起查
		db = db.Where("`language` = ?", param.LanguageName).Where("target = ?", param.LanguagePath)
	}
	if param.VulnId > 0 {
		db = db.Where("id = ? ", param.VulnId)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if len(param.OmitFields) > 0 {
		db = db.Omit(param.OmitFields...)
	}

	if len(param.VulnIds) > 0 {
		db = db.Where("id IN ?", param.VulnIds)
	}

	if param.NeedKernelFlag > 0 {
		db = db.Where("flag & ? > 0", param.NeedKernelFlag)
	}

	if param.CanFixedFlag > 0 {
		db = db.Where("flag & ? > 0", param.CanFixedFlag)
	}

	if param.ClassTypeFlag > 0 {
		db = db.Where("flag & ? > 0", param.ClassTypeFlag)
	}

	if param.AttackPathFlag > 0 {
		db = db.Where("flag & ? > 0", param.AttackPathFlag)
	}

	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.ImageUniqueID > 0 {
		itv := &imagesecModel.VulnToImage{}
		vulnToImageTableName := itv.TableName()
		sub := dal.db.Get().WithContext(ctx).Table(vulnToImageTableName).Select("distinct unique_target").
			Where("image_unique_id =  ?", param.ImageUniqueID)
		if param.ImageLayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.ImageLayerDigest)
		}

		db = db.Where("unique_id IN (?)", sub)
	}
	if param.PkgUniqueID > 0 {
		db = db.Where("pkg_unique_id = ?", param.PkgUniqueID)
	}
	if len(param.PkgUniqueIds) > 0 {
		db = db.Where("pkg_unique_id IN ?", param.PkgUniqueIds)
	}

	if param.PkgKeyword != "" {
		db = db.Where("pkg_name LIKE ? OR pkg_version LIKE ? ",
			fmt.Sprintf("%%%s%%", param.PkgKeyword), fmt.Sprintf("%%%s%%", param.PkgKeyword))
	}
	if param.FrameKeyword != "" {
		db = db.Where("frame LIKE ? ", fmt.Sprintf("%%%s%%", param.FrameKeyword))
	}
	if param.LanguageKeyword != "" {
		db = db.Where("language LIKE ? ", fmt.Sprintf("%%%s%%", param.LanguageKeyword))
	}
	if param.TargetKeyword != "" {
		db = db.Where("target LIKE ? ", fmt.Sprintf("%%%s%%", param.TargetKeyword))
	}
	if param.VulnKeyword != "" {
		db = db.Where("name LIKE ? OR cnnvd_name LIKE ? ", fmt.Sprintf("%%%s%%", param.VulnKeyword),
			fmt.Sprintf("%%%s%%", param.VulnKeyword))
	}
	if len(param.SeverityInt) > 0 {
		db = db.Where("severity IN ? ", param.SeverityInt)
	}

	res := make([]*imagesecModel.Vuln, 0)
	var cnt int64
	if !param.NotReturnCount {
		db2 := db.Session(&gorm.Session{})
		// https://cloud.tencent.com/developer/article/1658068
		// 一般来说，mysql优化了count(*),count(*)也是性能更好的方式，但是我们环境中count(*)会耗时5s以上，用count(unique_vuln)到是很快，
		// 没有找到具体原因，后面需要持续关注
		if err := db2.Select("count(unique_id) as cnt").Find(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}

	if param.JustReturnCount {
		return nil, cnt, nil
	}

	db = imagesecModel.AddFilter(db, param.Filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	for i := range res {
		res[i].Deserialize()
		res[i].OnlineVuln = param.OnlineVuln
	}
	return res, cnt, nil
}

func (dal *ScanResultDao) CreateWebFrameInfo(ctx context.Context, imageUuid uint32, data []model.WebFrameInfo) error {
	if len(data) == 0 || imageUuid <= 0 {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*30)
	defer cancelFunc()
	tableName := new(model.WebFrameScan).TableName()

	_ = dal.db.Get().WithContext(ctx).Table(tableName).Where("image_uuid = ?", imageUuid).Delete(&model.WebFrameScan{}).Error

	bys, err := json.Marshal(data)
	if err != nil {
		return err
	}

	tmp := model.WebFrameScan{
		ImageUUID:        imageUuid,
		WebFrameInfoJSON: bys,
		WebFrameInfos:    data,
	}
	err = dal.db.Get().WithContext(ctx).Table(tableName).Create(&tmp).Error
	return err
}

func (dal *ScanResultDao) CreateVulnPkg(ctx context.Context, pkgs []*imagesecModel.VulnToPkg) error {

	if len(pkgs) == 0 {
		return nil
	}
	tableName := pkgs[0].TableName()
	uniqueIds := make([]uint64, 0)
	for i := range pkgs {
		pkgs[i].UniqueID = pkgs[i].GenUniqueID()
		uniqueIds = append(uniqueIds, pkgs[i].UniqueID)
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	createData := make([]*imagesecModel.VulnToPkg, 0)
	dbPre := make([]*imagesecModel.VulnToPkg, 0)

	if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("unique_id IN ?", uniqueIds).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need create
	for i := range pkgs {
		needCreate := true
		for j := range dbPre {
			if dbPre[j].UniqueID == pkgs[i].UniqueID {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, pkgs[i])
		}
	}

	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanResultDao) DeleteOnlineVuln(ctx context.Context, data2 []uint64) error {
	if len(data2) == 0 {
		return nil
	}
	mo := &imagesecModel.Vuln{OnlineVuln: true}
	tableName := mo.TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	err := dal.db.Get().WithContext(ctx).Table(tableName).Where("unique_id IN ?", data2).
		Delete(&imagesecModel.Vuln{OnlineVuln: true}).Error
	return err
}

func (dal *ScanResultDao) CreateScanLayerData(ctx context.Context, data2 []*imagesecModel.ScanLayerData) error {
	data := make([]*imagesecModel.ScanLayerData, 0)
	layerFiles := make([]*imagesecModel.LayerFile, 0)
	for i := range data2 {
		data2[i].Serialize()

		if err := data2[i].Check(); err != nil {
			logging.Get().Error().Interface("data", data2[i]).Msg("CreateScanLayerData")
			continue
		}

		data = append(data, data2[i])
		layerFiles = append(layerFiles, data2[i].GenLayerFile()...)
	}

	layers := make([]string, 0)
	for i := range data {
		layers = append(layers, data[i].Layer)
	}
	if len(data) == 0 || len(layers) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, err := dal.SearchScanLayerData(ctx, imagesecModel.SearchScanLayerParam{Layers: layers})
	if err != nil {
		return err
	}

	createData := make([]*imagesecModel.ScanLayerData, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	// 因为深度扫描的开关，所以要特殊处理
	for i := range dbPre {
		needDelete := false
		// 本次写入的数据不同
		for j := range data {
			if dbPre[i].UniqueID == data[j].UniqueID && !dbPre[i].Same(data[j]) {
				needDelete = true
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}

	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.Malware{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanResultDao) SearchScanLayerData(ctx context.Context, param imagesecModel.SearchScanLayerParam) ([]*imagesecModel.ScanLayerData, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	res := make([]*imagesecModel.ScanLayerData, 0)
	if len(param.Layers) == 0 {
		return res, nil
	}
	layer2 := make([]string, 0)
	for i := range param.Layers {
		layer2 = append(layer2, strings.TrimPrefix(param.Layers[i], "sha256:"))
	}

	mo := &imagesecModel.ScanLayerData{}

	tableName := mo.TableName()

	db := dal.db.Get().WithContext(ctx).Table(tableName)
	layer2 = util.DuplicateStringSlice(layer2)

	if len(layer2) > 0 {
		db = db.Where("layer IN  ?", layer2)
	}
	if param.Issue != "" {
		db = db.Where("issue = ?", param.Issue)
	}
	if param.FileM5d != "" {
		sub := dal.db.Get().WithContext(ctx).Model(new(imagesecModel.LayerFile)).Select("layer_unique_id")
		sub = sub.Where("file_md5 = ?", param.FileM5d)
		db = db.Where("unique_id IN ( ? )", sub)
	}

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}

	for i := range res {
		res[i].Deserialize(nil)
	}

	if param.AddDetail {
		all := &imagesecModel.ScanLayerData{}
		all.SetEmpty()

		lic := make([]uint64, 0)
		wss := make([]uint64, 0)
		mal := make([]uint64, 0)
		ses := make([]uint64, 0)
		vuln := make([]uint64, 0)
		pkg := make([]uint64, 0)
		for i := range res {
			lic = append(lic, res[i].LicenseUnique...)
			wss = append(wss, res[i].WebshellUnique...)
			ses = append(ses, res[i].SensitiveUnique...)
			mal = append(mal, res[i].MalwareUnique...)
			pkg = append(pkg, res[i].PkgUnique...)
			vuln = append(vuln, res[i].VulnUnique...)
		}
		if len(lic) > 0 {
			ans, _, err := dal.SearchLicense(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: lic})
			if err != nil {
				return nil, err
			}
			all.License = append(all.License, ans...)
		}

		if len(wss) > 0 {
			ans, _, err := dal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: wss})
			if err != nil {
				return nil, err
			}
			all.Webshell = append(all.Webshell, ans...)
		}

		if len(mal) > 0 {
			ans, _, err := dal.SearchMalware(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: mal})
			if err != nil {
				return nil, err
			}
			all.Malware = append(all.Malware, ans...)
		}
		if len(ses) > 0 {
			ans, _, err := dal.SearchSensitive(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: ses})
			if err != nil {
				return nil, err
			}
			all.Sensitive = append(all.Sensitive, ans...)
		}
		if len(pkg) > 0 {
			ans, _, err := dal.SearchPkg(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: ses})
			if err != nil {
				return nil, err
			}
			all.Pkg = append(all.Pkg, ans...)
		}

		if len(vuln) > 0 {
			ans, _, err := dal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{VulnUniqueIds: vuln})
			if err != nil {
				return nil, err
			}
			all.Vuln = append(all.Vuln, ans...)
		}

		for i := range res {
			res[i].Deserialize(all)
		}
	}

	return res, nil
}

func (dal *ScanResultDao) DeleteScanLayerData(ctx context.Context, param imagesecModel.SearchScanLayerParam) error {
	data, err := dal.SearchScanLayerData(ctx, param)
	if err != nil {
		return err
	}

	mod := &imagesecModel.ScanLayerData{}

	for i := range data {
		if err := dal.db.Get().WithContext(ctx).Table(mod.TableName()).Where("id =  ? ", data[i].ID).
			Delete(&imagesecModel.Malware{}).Error; err != nil {
			return err
		}
	}

	return nil
}

func (dal *ScanResultDao) CreateScanLayerFile(ctx context.Context, data2 []*imagesecModel.LayerFile) error {
	data := make([]*imagesecModel.LayerFile, 0)
	for i := range data2 {
		data2[i].Serialize()
		if err := data2[i].Check(); err != nil {
			logging.Get().Error().Interface("data", data2[i]).Msg("CreateScanLayerFile")
			continue
		}

		data = append(data, data2[i])
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	tableName := data[0].TableName()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()
	dbPre := make([]*imagesecModel.LayerFile, 0)
	db := dal.db.Get().WithContext(ctx).Model(new(imagesecModel.LayerFile)).Where("unique_id IN ?", uniqueIds)
	if err := db.Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*imagesecModel.LayerFile, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}

	for i := range data {
		needCreate := true
		for j := range dbPre {
			if data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Where("id IN  ? ", deleteData).
			Delete(&imagesecModel.Malware{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(tableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}
