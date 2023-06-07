package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageScanResultDal interface {
	CreateVirus(ctx context.Context, data []*model.ImageVirus) error
	SearchVirus(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageVirus, int64, error)

	CreateWebShell(ctx context.Context, data []*model.ImageWebShell) error
	SearchWebShell(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*scannermodel.Webshell, int64, error)

	CreateSensitive(ctx context.Context, data []*model.ImageSensitiveFile) error
	SearchSensitive(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageSensitiveFile, int64, error)

	CreateSoftware(ctx context.Context, data []*model.ImageSoftware) error
	SearchSoftware(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageSoftware, int64, error)

	CreateImageEnv(ctx context.Context, imageID int64, data []*model.ImageEnv) error
	SearchImageEnv(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageEnv, int64, error)

	CreateScanVirusToImage(ctx context.Context, imageID int64, data []*model.ScanVirusToImage) error
	CreateScanSensitiveToImage(ctx context.Context, imageID int64, data []*model.ScanSensitiveToImage) error
	CreateSoftwareToImage(ctx context.Context, imageID int64, data []*model.ScanSoftwareToImage) error

	SearchScanSoftwareToImage(ctx context.Context, imageID int64) ([]*model.ScanSoftwareToImage, error)

	SearchScanImage(ctx context.Context, param imagesec.ScanResultSearchParam) (*imagesec.ImageWithCorrelateData, error)
}

type ImageScanResultDao struct {
	rdb *databases.RDBInstance
}

func (dal *ImageScanResultDao) SearchScanImage(ctx context.Context, param imagesec.ScanResultSearchParam) (*imagesec.ImageWithCorrelateData, error) {

	if param.ImageID <= 0 {
		return nil, fmt.Errorf("not get imageID")
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	imageData := &imagesec.ImageWithCorrelateData{}

	virus := make([]*model.ImageVirus, 0)
	sensitive := make([]*model.ImageSensitiveFile, 0)
	envs := make([]*model.ImageEnv, 0)
	license := make([]string, 0)
	soft := make([]*model.ImageSoftware, 0)
	// 查层级
	if param.LayerDigest != "" {
		// 查层级
		db2 := dal.rdb.Get().Model(new(model.ScanLayer)).Where("image_id = ?", param.ImageID).Where("layer_digest = ?", param.LayerDigest)
		layers := make([]model.ScanLayer, 0)
		if err := db2.Find(&layers).Error; err != nil {
			return nil, err
		}
		if len(layers) == 0 {
			return imageData, nil
		}
		layer := layers[0]
		layer.Deserialize()

		for i := range layer.MaliciousInfo {
			if (param.Keyword != "" && strings.Contains(strings.ToLower(layer.MaliciousInfo[i].VirusInfo.VirusName), param.Keyword)) || param.Keyword == "" {
				virus = append(virus, &model.ImageVirus{
					Filename: layer.MaliciousInfo[i].VirusInfo.FileName,
					Filepath: layer.MaliciousInfo[i].VirusInfo.FilePath,
					Name:     layer.MaliciousInfo[i].VirusInfo.VirusName,
				})
			}
		}

		for i := range layer.SensitiveFile {
			if (param.Keyword != "" && strings.Contains(strings.ToLower(layer.SensitiveFile[i].Name), param.Keyword)) || param.Keyword == "" {
				sensitive = append(sensitive, &model.ImageSensitiveFile{
					Name:          layer.SensitiveFile[i].Name,
					Description:   layer.SensitiveFile[i].Description,
					DescriptionEn: layer.SensitiveFile[i].DescriptionEn,
					DescriptionZh: layer.SensitiveFile[i].DescriptionZh,
				})
			}
		}
	}

	// 查整个镜像
	if param.LayerDigest == "" {
		db := dal.rdb.Get().Model(new(model.ScanImage)).WithContext(ctx).Where("image_id = ? ", param.ImageID)

		res := make([]model.ScanImage, 0)
		if err := db.Find(&res).Error; err != nil {
			return nil, err
		}
		if len(res) == 0 {
			return imageData, nil
		}
		layer := res[0]
		layer.Deserialize()
		for i := range layer.LicenseInfo {
			param.LicenseSearch = append(param.LicenseSearch, layer.LicenseInfo[i].Name)
		}

		for i := range layer.MaliciousInfo {
			if (param.Keyword != "" && strings.Contains(strings.ToLower(layer.MaliciousInfo[i].VirusInfo.VirusName), param.Keyword)) || param.Keyword == "" {
				virus = append(virus, &model.ImageVirus{
					Filename: layer.MaliciousInfo[i].VirusInfo.FileName,
					Filepath: layer.MaliciousInfo[i].VirusInfo.FilePath,
					Name:     layer.MaliciousInfo[i].VirusInfo.VirusName,
				})
			}
		}

		for i := range layer.SensitiveFile {
			if (param.Keyword != "" && strings.Contains(strings.ToLower(layer.SensitiveFile[i].Name), param.Keyword)) || param.Keyword == "" {
				sensitive = append(sensitive, &model.ImageSensitiveFile{
					Name:          layer.SensitiveFile[i].Name,
					Description:   layer.SensitiveFile[i].Description,
					DescriptionEn: layer.SensitiveFile[i].DescriptionEn,
					DescriptionZh: layer.SensitiveFile[i].DescriptionZh,
				})
			}
		}
		// env
		for i := range layer.EnvKeyValue {
			if param.ExceptionEnv == consts.TrueString && layer.EnvKeyValue[i].IsAbnormal != consts.EnvIsAbnormal {
				continue
			}
			// env 统一大写
			if param.Keyword != "" && !strings.Contains(strings.ToUpper(layer.EnvKeyValue[i].Key), strings.ToUpper(param.Keyword)) {
				continue
			}
			envs = append(envs, &model.ImageEnv{
				ImageID: param.ImageID,
				Key:     layer.EnvKeyValue[i].Key,
				Value:   layer.EnvKeyValue[i].Value,
				Normal:  layer.EnvKeyValue[i].IsAbnormal == 0,
			})
		}

		for i := range layer.LicenseInfo {
			if layer.LicenseInfo[i].Name != "" {
				license = append(license, layer.LicenseInfo[i].Name)
			}
		}
		param.LicenseSearch = util.DuplicateStringSlice(license)

		// abnormal software
		softExit := make(map[string]bool)

		for i := range layer.Software {
			key := fmt.Sprintf("%s|%s", layer.Software[i].Name, layer.Software[i].Version)
			if !softExit[key] {
				softExit[key] = true

				soft = append(soft, &model.ImageSoftware{
					Name:    layer.Software[i].Name,
					Version: layer.Software[i].Version,
					Flag:    util.SetBit1(0, model.FlagHasExceptPKG),
				})
			}
		}

	}

	imageData.Sensitive = DuplicateSensitiveFile(sensitive)
	imageData.SensitiveCnt = int64(len(imageData.Sensitive))
	imageData.Virus = DuplicateVirus(virus)
	imageData.VirusCnt = int64(len(imageData.Virus))
	imageData.Env = DuplicateEnv(envs)
	imageData.EnvCnt = int64(len(imageData.Env))
	imageData.License = util.DuplicateStringSlice(license)
	imageData.Software = DuplicateSoft(soft)
	imageData.SoftwareCnt = int64(len(imageData.Software))

	return imageData, nil
}

func (dal *ImageScanResultDao) SearchScanSoftwareToImage(ctx context.Context, imageID int64) ([]*model.ScanSoftwareToImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSoftwareToImage)).Where("image_id = ?", imageID)
	res := make([]*model.ScanSoftwareToImage, 0)
	err := db.Find(&res).Error
	return res, err
}

func (dal *ImageScanResultDao) CreateImageEnv(ctx context.Context, imageID int64, data []*model.ImageEnv) error {
	for i := range data {
		vuln := data[i]
		vuln.UniqueID = vuln.GenUniqueID()
		data[i] = vuln
	}
	data = DuplicateEnv(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()

	dbPre := make([]*model.ImageEnv, 0)
	if err := dal.rdb.Get().Model(new(model.ImageEnv)).Where("image_id = ?", imageID).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.ImageEnv, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageEnv)).Where("id IN  ? ", deleteData).Delete(&model.ImageEnv{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageEnv)).Create(createData[i]).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ImageScanResultDao) SearchImageEnv(ctx context.Context, param SearchImageScanResultParam,
	filter *model.Filter) ([]*model.ImageEnv, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageEnv))

	param.Serialize()
	if len(param.UniqueTarget) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueTarget)
	}
	if param.Keyword != "" {
		db = db.Where("`key` LIKE ? OR `value` LIKE ? ",
			fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.NormalEnv == consts.TrueString {
		db = db.Where("normal = ?", true)
	} else if param.NormalEnv == consts.FalseString {
		db = db.Where("normal = ?", false)
	}

	// 查单个镜像
	if param.ImageID > 0 {
		db = db.Where("image_id = ?", param.ImageID)
	}

	res := make([]*model.ImageEnv, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ImageScanResultDao) CreateSoftware(ctx context.Context, data []*model.ImageSoftware) error {
	data = DuplicateSoft(data)
	if len(data) == 0 {
		return nil
	}

	uniqueIds := make([]uint64, 0)
	for i := range data {
		vuln := data[i]
		vuln.UniqueID = vuln.GenUniqueID()
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchSoftware(ctx, SearchImageScanResultParam{UniqueTarget: uniqueIds}, nil)
	if err != nil {
		return err
	}
	createData := make([]*model.ImageSoftware, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSoftware)).Where("id IN  ? ", deleteData).Delete(&model.ImageSoftware{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSoftware)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ImageScanResultDao) SearchSoftware(ctx context.Context, param SearchImageScanResultParam,
	filter *model.Filter) ([]*model.ImageSoftware, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSoftware))

	param.Serialize()
	if len(param.UniqueTarget) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueTarget)
	}
	if len(param.License) > 0 {
		db = db.Where("license IN ?", param.License)
	}
	if param.Keyword != "" {
		db = db.Where("name LIKE ? OR version LIKE ?", fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}
	// 查单个镜像
	if param.ImageID > 0 {
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSoftwareToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}
		if param.Flag > 0 {
			sub = sub.Where("flag & ? = ?", param.Flag, param.Flag)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}

	res := make([]*model.ImageSoftware, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ImageScanResultDao) CreateSensitive(ctx context.Context, data []*model.ImageSensitiveFile) error {

	uniqueIds := make([]uint64, 0)
	for i := range data {
		vuln := data[i]
		vuln.UniqueID = vuln.GenUniqueID()
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}

	data = DuplicateSensitiveFile(data)
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchSensitive(ctx, SearchImageScanResultParam{UniqueTarget: uniqueIds}, nil)
	if err != nil {
		return err
	}

	createData := make([]*model.ImageSensitiveFile, 0)
	deleteData := make([]int64, 0)

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range data {
			if dbPre[i].Same(data[j]) && dbPre[i].UniqueID == data[j].UniqueID {
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
			if data[i].Same(dbPre[j]) && dbPre[j].UniqueID == data[i].UniqueID {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSensitiveFile)).Where("id IN  ? ", deleteData).Delete(&model.ImageSensitiveFile{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSensitiveFile)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ImageScanResultDao) SearchSensitive(ctx context.Context, param SearchImageScanResultParam,
	filter *model.Filter) ([]*model.ImageSensitiveFile, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageSensitiveFile))

	param.Serialize()
	if len(param.UniqueTarget) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueTarget)
	}
	if param.Keyword != "" {
		db = db.Where("name LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}

	// 查单个镜像
	if param.ImageID > 0 {
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSensitiveToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*model.ImageSensitiveFile, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ImageScanResultDao) CreateVirus(ctx context.Context, data []*model.ImageVirus) error {

	uniqueIds := make([]uint64, 0)
	for i := range data {
		vuln := data[i]
		vuln.UniqueID = vuln.GenUniqueID()
		uniqueIds = append(uniqueIds, data[i].UniqueID)
	}
	data = DuplicateVirus(data)
	if len(data) == 0 || len(uniqueIds) == 0 {
		return nil
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000)
	defer cancelFunc()

	dbPre, _, err := dal.SearchVirus(ctx, SearchImageScanResultParam{UniqueTarget: uniqueIds}, nil)
	if err != nil {
		return err
	}

	createData := make([]*model.ImageVirus, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageVirus)).Where("id IN  ? ", deleteData).Delete(&model.ImageVirus{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageVirus)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func (dal *ImageScanResultDao) SearchVirus(ctx context.Context, param SearchImageScanResultParam,
	filter *model.Filter) ([]*model.ImageVirus, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ImageVirus))

	param.Serialize()
	if len(param.UniqueTarget) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueTarget)
	}
	if param.Keyword != "" {
		db = db.Where("filename LIKE ? OR filepath LIKE ? OR name LIKE ? ",
			fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword), fmt.Sprintf("%%%s%%", param.Keyword))
	}
	// 查单个镜像
	if param.ImageID > 0 {
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanVirusToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*model.ImageVirus, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ImageScanResultDao) CreateWebShell(ctx context.Context, data []*model.ImageWebShell) error {
	return nil
}

func (dal *ImageScanResultDao) SearchWebShell(ctx context.Context, param SearchImageScanResultParam,
	filter *model.Filter) ([]*scannermodel.Webshell, int64, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(scannermodel.Webshell))

	param.Serialize()
	if len(param.UniqueTarget) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueTarget)
	}
	if param.Keyword != "" {
		db = db.Where("file_name LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}

	// 查单个镜像
	if param.ImageID > 0 {
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImageWebshell)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID)
		// 查镜像的层级
		if param.LayerDigest != "" {
			sub = sub.Where("layer_digest = ?", param.LayerDigest)
		}

		db = db.Where("unique_id IN ( ? )", sub)
	}
	res := make([]*scannermodel.Webshell, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}

func (dal *ImageScanResultDao) CreateScanVirusToImage(ctx context.Context, imageID int64, data []*model.ScanVirusToImage) error {

	for i := range data {
		data[i].ImageID = imageID
		data[i].UniqueID = data[i].GenUniqueID()
	}

	data = DuplicateScanVirusToImage(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	dbPre := make([]*model.ScanVirusToImage, 0)
	if err := dal.rdb.Get().Model(new(model.ScanVirusToImage)).Where("image_id = ?", imageID).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.ScanVirusToImage, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanVirusToImage)).Where("id IN  ? ", deleteData).Delete(&model.ScanVirusToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanVirusToImage)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ImageScanResultDao) CreateScanSensitiveToImage(ctx context.Context, imageID int64, data []*model.ScanSensitiveToImage) error {

	for i := range data {
		data[i].ImageID = imageID
		data[i].UniqueID = data[i].GenUniqueVuln()
	}

	data = DuplicateScanSensitiveToImage(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	dbPre := make([]*model.ScanSensitiveToImage, 0)
	if err := dal.rdb.Get().Model(new(model.ScanSensitiveToImage)).Where("image_id = ?", imageID).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.ScanSensitiveToImage, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSensitiveToImage)).Where("id IN  ? ", deleteData).Delete(&model.ScanSensitiveToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSensitiveToImage)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ImageScanResultDao) CreateSoftwareToImage(ctx context.Context, imageID int64, data []*model.ScanSoftwareToImage) error {

	for i := range data {
		data[i].ImageID = imageID
		data[i].UniqueID = data[i].GenUniqueVuln()
	}

	data = DuplicateScanSoftwareToImage(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	dbPre := make([]*model.ScanSoftwareToImage, 0)
	if err := dal.rdb.Get().Model(new(model.ScanSoftwareToImage)).Where("image_id = ?", imageID).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.ScanSoftwareToImage, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSoftwareToImage)).Where("id IN  ? ", deleteData).Delete(&model.ScanSoftwareToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanSoftwareToImage)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

var SingeScanResultDAO *ImageScanResultDao

func GetSingeScanResultDAO() *ImageScanResultDao {
	if SingeScanResultDAO != nil {
		return SingeScanResultDAO
	}
	SingeScanResultDAO = NewImageScanResultDao(GetScannerWrapperDb())
	return SingeScanResultDAO
}

func NewImageScanResultDao(rdb *databases.RDBInstance) *ImageScanResultDao {
	return &ImageScanResultDao{rdb: rdb}
}

func DuplicateSoft(data []*model.ImageSoftware) []*model.ImageSoftware {
	exit := make(map[uint64]bool)
	after := make([]*model.ImageSoftware, 0)
	for i := range data {
		if data[i].UniqueID == 0 {
			data[i].UniqueID = data[i].GenUniqueID()
		}
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateEnv(data []*model.ImageEnv) []*model.ImageEnv {
	exit := make(map[uint64]bool)
	after := make([]*model.ImageEnv, 0)
	for i := range data {
		if data[i].UniqueID == 0 {
			data[i].UniqueID = data[i].GenUniqueID()
		}
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateVirus(data []*model.ImageVirus) []*model.ImageVirus {
	exit := make(map[uint64]bool)
	after := make([]*model.ImageVirus, 0)
	for i := range data {
		if data[i].UniqueID == 0 {
			data[i].UniqueID = data[i].GenUniqueID()
		}
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateSensitiveFile(data []*model.ImageSensitiveFile) []*model.ImageSensitiveFile {
	exit := make(map[uint64]bool)
	after := make([]*model.ImageSensitiveFile, 0)
	for i := range data {
		if data[i].UniqueID == 0 {
			data[i].UniqueID = data[i].GenUniqueID()
		}
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateScanVirusToImage(data []*model.ScanVirusToImage) []*model.ScanVirusToImage {
	exit := make(map[uint64]bool)
	after := make([]*model.ScanVirusToImage, 0)
	for i := range data {
		if data[i].UniqueID == 0 {
			data[i].UniqueID = data[i].GenUniqueID()
		}
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateScanSensitiveToImage(data []*model.ScanSensitiveToImage) []*model.ScanSensitiveToImage {
	exit := make(map[uint64]bool)
	after := make([]*model.ScanSensitiveToImage, 0)
	for i := range data {
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateScanSoftwareToImage(data []*model.ScanSoftwareToImage) []*model.ScanSoftwareToImage {
	exit := make(map[uint64]bool)
	after := make([]*model.ScanSoftwareToImage, 0)
	for i := range data {
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}
