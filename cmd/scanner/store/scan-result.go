package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageScanResultDal interface {
	CreateVirus(ctx context.Context, data []*model.ImageVirus) error
	SearchVirus(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageVirus, int64, error)

	CreateWebShell(ctx context.Context, data []*model.ImageWebShell) error
	SearchWebShell(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageWebShell, int64, error)

	CreateSensitive(ctx context.Context, data []*model.ImageSensitiveFile) error
	SearchSensitive(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageSensitiveFile, int64, error)

	CreateSoftware(ctx context.Context, data []*model.ImageSoftware) error
	SearchSoftware(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageSoftware, int64, error)

	CreateImageEnv(ctx context.Context, imageID int64, data []*model.ImageEnv) error
	SearchImageEnv(ctx context.Context, param SearchImageScanResultParam, filter *model.Filter) ([]*model.ImageEnv, int64, error)

	CreateScanIssueToImage(ctx context.Context, imageID int64, securityIssue int64, data []*model.ScanIssueToImage) error
	SearchScanIssueToImage(ctx context.Context, imageID int64, securityIssue int64) ([]*model.ScanIssueToImage, error)
}

type ImageScanResultDao struct {
	rdb *databases.RDBInstance
}

func (dal *ImageScanResultDao) SearchScanIssueToImage(ctx context.Context, imageID int64, securityIssue int64) ([]*model.ScanIssueToImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).Where("image_id = ?", imageID).Where("security_issue = ?", securityIssue)
	res := make([]*model.ScanIssueToImage, 0)
	err := db.Find(&res).Error
	return res, err
}

func (dal *ImageScanResultDao) CreateImageEnv(ctx context.Context, imageID int64, data []*model.ImageEnv) error {
	for i := range data {
		vuln := data[i]
		vuln.UniqueID = vuln.GenUniqueVuln()
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
		db.Where("unique_id IN ?", param.UniqueTarget)
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
		db.Where("image_id = ?", param.ImageID)
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
		vuln.UniqueID = vuln.GenUniqueVuln()
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
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID).
			Where("security_issue = ?", model.FlagHasSoftware)
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
		vuln.UniqueID = vuln.GenUniqueVuln()
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
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID).
			Where("security_issue = ?", model.FlagHasSensitive)
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
		vuln.UniqueID = vuln.GenUniqueVuln()
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
		sub := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).
			Select("distinct unique_target").Where("image_id = ?", param.ImageID).
			Where("security_issue = ?", model.FlagHasMalicious)
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
	filter *model.Filter) ([]*model.ImageWebShell, int64, error) {
	return make([]*model.ImageWebShell, 0), 0, nil
}

func (dal *ImageScanResultDao) CreateScanIssueToImage(ctx context.Context, imageID int64, securityIssue int64, data []*model.ScanIssueToImage) error {

	for i := range data {
		data[i].ImageID = imageID
		data[i].SecurityIssue = securityIssue
		data[i].UniqueID = data[i].GenUniqueVuln()
	}

	data = DuplicateIssueToImage(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	dbPre := make([]*model.ScanIssueToImage, 0)
	if err := dal.rdb.Get().Model(new(model.ScanIssueToImage)).Where("image_id = ?", imageID).
		Where("security_issue = ?", securityIssue).Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.ScanIssueToImage, 0)
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
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).Where("id IN  ? ", deleteData).Delete(&model.ScanIssueToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.rdb.Get().WithContext(ctx).Model(new(model.ScanIssueToImage)).Create(da).Error; err != nil {
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
		if !exit[data[i].UniqueID] {
			after = append(after, data[i])
			exit[data[i].UniqueID] = true
		}
	}
	return after
}

func DuplicateIssueToImage(data []*model.ScanIssueToImage) []*model.ScanIssueToImage {
	exit := make(map[string]bool)
	after := make([]*model.ScanIssueToImage, 0)
	for i := range data {
		key := fmt.Sprintf("%d-%d-%d-%s", data[i].SecurityIssue, data[i].ImageID, data[i].UniqueTarget, data[i].LayerDigest)
		if !exit[key] {
			after = append(after, data[i])
			exit[key] = true
		}
	}
	return after
}
