package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type VulnDalInterface interface {
	SearchVuln(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error)
	SearchVulnImage(ctx context.Context, param SearchVulnImageParam, filter *model.Filter) ([]*model.VulnImage, int64, error)
	SearchVulnPkg(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error)
	CreateVuln(ctx context.Context, data []*model.Vuln) error
	UpdateVuln(ctx context.Context, where string, updater map[string]interface{}, vuln *model.Vuln) error
	CreateVulnImage(ctx context.Context, imageID int64, data []*model.VulnImage) error
	GroupImageVuln(ctx context.Context, images []int64) ([]GroupImageVuln, error)
	DeleteVulnImage(ctx context.Context, imageIds []int64) error
}

type VulnDao struct {
	rdb *databases.RDBInstance
}

func (v *VulnDao) GroupImageVuln(ctx context.Context, images []int64) ([]GroupImageVuln, error) {
	if len(images) == 0 {
		return nil, fmt.Errorf("no imageIds")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	res := make([]GroupImageVuln, 0)
	err := v.rdb.Get().WithContext(ctx).Model(&model.VulnImage{}).
		Select("ivan_scanner_vuln_images.image_id", "ivan_scanner_vulns.severity_int", "count(ivan_scanner_vulns.id) as cnt").
		Joins("left  join ivan_scanner_vulns on ivan_scanner_vuln_images.unique_vuln=ivan_scanner_vulns.unique_vuln").
		Where("ivan_scanner_vuln_images.image_id IN ? ", images).
		Group("ivan_scanner_vuln_images.image_id,ivan_scanner_vulns.severity_int").
		Scan(&res).Error

	return res, err
}

func (v *VulnDao) DeleteVulnImage(ctx context.Context, imageIds []int64) error {
	if len(imageIds) == 0 {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().WithContext(ctx).Model(model.VulnImage{}).Where("image_id IN ?", imageIds)
	return db.Delete(&model.VulnImage{}).Error
}

var singeVulnDao *VulnDao

func NewVulnDao(rdb *databases.RDBInstance) *VulnDao {
	if singeVulnDao != nil {
		return singeVulnDao
	}
	singeVulnDao = &VulnDao{rdb: rdb}
	return singeVulnDao
}

func GetSingeVulnDao() *VulnDao {
	if singeVulnDao != nil {
		return singeVulnDao
	}
	singeVulnDao = &VulnDao{rdb: GetScannerWrapperDb()}
	return singeVulnDao
}

func (v *VulnDao) SearchVulnImage(ctx context.Context, param SearchVulnImageParam, filter *model.Filter) ([]*model.VulnImage, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().WithContext(ctx).Model(model.VulnImage{})

	if len(param.UniqueVulns) > 0 {
		db = db.Where("unique_vuln IN  ?", param.UniqueVulns)
	}
	if len(param.ImageIds) > 0 {
		db = db.Where("image_id IN  ?", param.ImageIds)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	res := make([]*model.VulnImage, 0)

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

func (v *VulnDao) SearchVuln(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*30)
	defer cancelFunc()
	db := v.rdb.Get().WithContext(ctx).Model(model.Vuln{})

	if len(param.UniqueVulns) > 0 {
		db = db.Where("unique_vuln IN  ?", param.UniqueVulns)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if len(param.OmitFields) > 0 {
		db = db.Omit(param.OmitFields...)
	}
	if param.Where != "" {
		db = db.Where(param.Where)
	}

	if param.NeedKernel == consts.FalseString {
		flag := util.SetBit1(0, model.VulnFlagKernel)
		db = db.Where("flag & ? = 0", flag, flag)
	}

	if param.OnlineImageVuln == consts.TrueString {
		defer func() {
			_ = db.Exec(consts.DropOnlineImageTempTableSql).Error
		}()

		if err := db.Exec(consts.CreateOnlineImageTempTableSql).Error; err != nil {
			return nil, 0, err
		}
		if err := db.Exec(consts.InsertOnlineImageTempTableSql).Error; err != nil {
			return nil, 0, err
		}

		sub := v.rdb.Get().WithContext(ctx).Table("ivan_scanner_vuln_images a").
			Joins("join ivan_scanner_online_image b  on a.image_id = b.image_id").Select("distinct a.unique_vuln")
		db = db.Where("unique_vuln IN (?)", sub)
	}

	if len(param.ImageIds) > 0 {
		sub := v.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Select("distinct unique_vuln").Where("image_id IN  ?", param.ImageIds)
		db = db.Where("unique_vuln IN (?)", sub)
	}
	if param.LayerSearch != nil {
		sub := v.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Select("distinct unique_vuln").
			Where("image_id =  ?", param.LayerSearch.ImageID).Where("layer_digest = ?", param.LayerSearch.LayerDigest)
		db = db.Where("unique_vuln IN (?)", sub)
	}

	if param.PkgName != "" {
		db = db.Where("pkg_name = ?", param.PkgName)
	}
	if param.PkgVersion != "" {
		db = db.Where("pkg_version = ?", param.PkgVersion)
	}
	if len(param.Sources) > 0 {
		db = db.Where("source IN ？", param.Sources)
	}
	if param.CanFixed == consts.TrueString || param.CanFixed == consts.YesString {
		db = db.Where("fixed_by != ''")
	}
	if param.CanFixed == consts.FalseString || param.CanFixed == consts.NoString {
		db = db.Where("fixed_by = '' OR fixed_by is null")
	}
	if param.PkgKeyword != "" {
		db = db.Where("pkg_name LIKE ? ", fmt.Sprintf("%%%s%%", param.PkgKeyword))
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
		db = db.Where("severity_int IN  ? ", param.SeverityInt)
	}
	if param.StartID > 0 {
		db = db.Where("id >  ? ", param.StartID)
	}
	if len(param.ClassType) > 0 {
		db = db.Where("`class` IN  ? ", param.ClassType)
	}

	res := make([]*model.Vuln, 0)
	var cnt int64
	if !param.NotReturnCount {
		db2 := db.Session(&gorm.Session{})
		// https://cloud.tencent.com/developer/article/1658068
		// 一般来说，mysql优化了count(*),count(*)也是性能更好的方式，但是我们环境中count(*)会耗时5s以上，用count(unique_vuln)到是很快，
		// 没有找到具体原因，后面需要持续关注

		if err := db2.Select("count(unique_vuln) as cnt").Find(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}

	if param.JustReturnCount {
		return nil, cnt, nil
	}

	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}

	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, nil
}

func (v *VulnDao) SearchVulnPkg(ctx context.Context, param SearchVulnParam, filter *model.Filter) ([]*model.Vuln, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := v.rdb.Get().WithContext(ctx).Model(model.Vuln{})
	if param.VulnKeyword != "" {
		db = db.Where("name LIKE ?", fmt.Sprintf("%%%s%%", param.VulnKeyword))
	}
	if len(param.UniqueVulns) > 0 {
		db = db.Where("unique_vuln IN ?", param.UniqueVulns)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if len(param.OmitFields) > 0 {
		db = db.Omit(param.OmitFields...)
	}
	if param.Where != "" {
		db = db.Where(param.Where)
	}
	if len(param.ImageIds) > 0 {
		sub := v.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Select("distinct unique_vuln").Where("image_id IN ? ", param.ImageIds)
		db = db.Where("unique_vuln IN (?)", sub)
	}
	if param.PkgName != "" {
		db = db.Where("pkg_name = ?", param.PkgName)
	}
	if param.PkgVersion != "" {
		db = db.Where("pkg_version = ?", param.PkgVersion)
	}
	if len(param.Sources) > 0 {
		db = db.Where("source IN ？", param.Sources)
	}
	if param.CanFixed == consts.TrueString {
		db = db.Where("fixed_by != ''")
	}
	if param.CanFixed == consts.FalseString {
		db = db.Where("fixed_by = ''")
	}

	res := make([]*model.Vuln, 0)

	db2 := db.Session(&gorm.Session{})
	var cnt int64
	if err := db2.Select("count(unique_vuln) as cnt").Find(&cnt).Error; err != nil {
		return nil, 0, err
	}

	if param.JustReturnCount {
		return nil, cnt, nil
	}
	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res, cnt, nil
}

func (v *VulnDao) CreateVuln(ctx context.Context, data []*model.Vuln) error {
	for i := range data {
		vuln := data[i]
		vuln.Serialize()
		vuln.CheckSum = vuln.GenCheckSum()
		vuln.UniqueVuln = vuln.GenUniqueVuln()
		data[i] = vuln
	}

	data = removeDuplicateVuln(data)
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000) // 批量写入,因为有大json格式的数据，时间会久些，时间久些
	defer cancelFunc()
	for i := range data {
		vuln := data[i]
		vulns, _, err := v.SearchVuln(ctx, SearchVulnParam{UniqueVulns: []uint64{vuln.UniqueVuln}, Fields: []string{"id", "unique_vuln", "check_sum"}}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("CreateVuln")
			return err
		}

		if len(vulns) > 0 {
			if vulns[0].CheckSum == vuln.CheckSum {
				logging.GetLogger().Debug().Uint64("UniqueVuln", vuln.UniqueVuln).Uint64("CheckSum", vuln.CheckSum).Msg("CreateVuln not change")
			} else {
				if err := v.UpdateVuln(ctx, fmt.Sprintf("id = %d", vulns[0].ID), nil, vuln); err != nil {
					logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Int64("ID", vulns[0].ID).Msg("CreateVuln")
					return err
				}
			}
			continue
		}

		if err := v.rdb.Get().WithContext(ctx).Model(new(model.Vuln)).Create(vuln).Error; err != nil {
			logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("CreateVuln")
			return err
		}
	}
	return nil
}

func (v *VulnDao) UpdateVuln(ctx context.Context, where string, updater map[string]interface{}, vuln *model.Vuln) error {
	if len(where) == 0 {
		return fmt.Errorf("no where condition")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	var err error
	db := v.rdb.Get().Model(new(model.Vuln)).WithContext(ctx).Where(where)

	if len(updater) > 0 {
		err = db.Updates(updater).Error
	} else if vuln != nil {
		err = db.Select("*").Omit("id", "created_at").Updates(vuln).Error
	}
	return err
}

func (v *VulnDao) CreateVulnImage(ctx context.Context, imageID int64, data []*model.VulnImage) error {

	for i := range data {
		data[i].ImageId = imageID
	}
	data = removeDuplicateVulnImage(data)

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()

	dbPre := make([]*model.VulnImage, 0)
	if err := v.rdb.Get().Model(new(model.VulnImage)).Where("image_id = ?", imageID).
		Find(&dbPre).Error; err != nil {
		return err
	}

	createData := make([]*model.VulnImage, 0)
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
		if err := v.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Where("id IN  ? ", deleteData).
			Delete(&model.VulnImage{}).Error; err != nil {
			return err
		}
	}
	for i := range createData {
		da := createData[i]
		if err := v.rdb.Get().WithContext(ctx).Model(new(model.VulnImage)).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			} else {
				return err
			}
		}
	}
	return nil
}

func removeDuplicateVuln(data []*model.Vuln) []*model.Vuln {
	exit := map[uint64]struct{}{}
	ans := make([]*model.Vuln, 0, len(data))

	for i := range data {
		if _, ok := exit[data[i].UniqueVuln]; !ok {
			ans = append(ans, data[i])
		}
		exit[data[i].UniqueVuln] = struct{}{}
	}
	return ans
}

func removeDuplicateVulnImage(data []*model.VulnImage) []*model.VulnImage {
	exit := map[string]struct{}{}
	ans := make([]*model.VulnImage, 0, len(data))

	for i := range data {
		key := fmt.Sprintf("%d-%d", data[i].UniqueVuln, data[i].ImageId)
		if _, ok := exit[key]; !ok {
			ans = append(ans, data[i])
		}
		exit[key] = struct{}{}
	}
	return ans
}
