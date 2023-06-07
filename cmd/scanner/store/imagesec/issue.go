package imagesec

import (
	"context"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 扫描结果关联关系
type ScanIssueDal interface {
	CreateMalwareToImage(ctx context.Context, param imagesec.CreateMalwareToImageParam) error
	CreateSensitiveToImage(ctx context.Context, param imagesec.CreateSensitiveToImageParam) error
	CreatePkgToImage(ctx context.Context, param imagesec.CreatePkgToImageParam) error
	CreateVulnToImage(ctx context.Context, param imagesec.CreateVulnToImageParam) error
	CreateWebshellToImage(ctx context.Context, param imagesec.CreateWebshellToImageParam) error
	SearchPkgIssueToImage(ctx context.Context, imageID uint64) ([]*imagesec.PkgToImage, error)
}

type ScanIssueDao struct {
	db *databases.RDBInstance
}

func NewScanIssueDao(db *databases.RDBInstance) *ScanIssueDao {
	return &ScanIssueDao{db: db}
}

func (dal *ScanIssueDao) CreateMalwareToImage(ctx context.Context, param imagesec.CreateMalwareToImageParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	issueModel := &imagesec.MalwareToImage{}
	issueTableName := issueModel.TableName()

	dbPre, createData, deleteData := make([]*imagesec.MalwareToImage, 0), make([]*imagesec.MalwareToImage, 0), make([]int64, 0)
	if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("image_unique_id = ?",
		param.ImageUniqueID).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("id IN  ? ", deleteData).
			Delete(&imagesec.MalwareToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanIssueDao) CreateSensitiveToImage(ctx context.Context, param imagesec.CreateSensitiveToImageParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	issueModel := &imagesec.SensitiveToImage{}
	issueTableName := issueModel.TableName()

	dbPre, createData, deleteData := make([]*imagesec.SensitiveToImage, 0), make([]*imagesec.SensitiveToImage, 0), make([]int64, 0)
	if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("image_unique_id = ?", param.ImageUniqueID).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("id IN  ? ", deleteData).
			Delete(&imagesec.SensitiveToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanIssueDao) CreatePkgToImage(ctx context.Context, param imagesec.CreatePkgToImageParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	issueModel := &imagesec.PkgToImage{}
	issueTableName := issueModel.TableName()

	dbPre, createData, deleteData := make([]*imagesec.PkgToImage, 0), make([]*imagesec.PkgToImage, 0), make([]int64, 0)
	if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("image_unique_id = ?", param.ImageUniqueID).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("id IN  ? ", deleteData).
			Delete(&imagesec.PkgToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanIssueDao) CreateVulnToImage(ctx context.Context, param imagesec.CreateVulnToImageParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	issueModel := &imagesec.VulnToImage{}
	issueTableName := issueModel.TableName()

	dbPre, createData, deleteData := make([]*imagesec.VulnToImage, 0), make([]*imagesec.VulnToImage, 0), make([]int64, 0)
	if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("image_unique_id = ?", param.ImageUniqueID).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("id IN  ? ", deleteData).
			Delete(&imagesec.VulnToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanIssueDao) CreateWebshellToImage(ctx context.Context, param imagesec.CreateWebshellToImageParam) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	issueModel := &imagesec.WebshellToImage{}
	issueTableName := issueModel.TableName()

	dbPre, createData, deleteData := make([]*imagesec.WebshellToImage, 0), make([]*imagesec.WebshellToImage, 0), make([]int64, 0)
	if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("image_unique_id = ?", param.ImageUniqueID).Find(&dbPre).Error; err != nil {
		return err
	}

	// find need delete data
	for i := range dbPre {
		needDelete := true
		for j := range param.Data {
			if dbPre[i].Same(param.Data[j]) {
				needDelete = false
				break
			}
		}
		if needDelete {
			deleteData = append(deleteData, dbPre[i].ID)
		}
	}
	// find need create
	for i := range param.Data {
		needCreate := true
		for j := range dbPre {
			if param.Data[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, param.Data[i])
		}
	}

	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Where("id IN  ? ", deleteData).
			Delete(&imagesec.WebshellToImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := dal.db.Get().WithContext(ctx).Table(issueTableName).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}

	return nil
}

func (dal *ScanIssueDao) SearchIssueToImage(ctx context.Context, param imagesec.SearchIssueToImageParam, filter *model.Filter) error {
	if err := param.Check(); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	db := dal.db.Get().WithContext(ctx).Table(param.TableName)
	if len(param.ImageIds) > 0 {
		db = db.Where("image_id IN ?", param.ImageIds)
	}
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return err
	}
	db = model.AddFilter(db, filter)
	res := param.Res
	if err := db.Find(&res).Error; err != nil {
		return err
	}
	param.Res = res
	param.Count = cnt
	return nil
}

func (dal *ScanIssueDao) SearchPkgIssueToImage(ctx context.Context, imageID uint64) ([]*imagesec.PkgToImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	m := imagesec.PkgToImage{}

	db := dal.db.Get().WithContext(ctx).Table(m.TableName()).Where("image_id = ?", imageID)
	res := make([]*imagesec.PkgToImage, 0)
	err := db.Find(&res).Error
	return res, err
}
