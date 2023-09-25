package imagesec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DeployDal interface {
	SearchDeployRecord(ctx context.Context, param imagesecModel.ImageDalParam) ([]*imagesecModel.DeployRecord, int64, error)
	CreateDeployRecord(ctx context.Context, data *imagesecModel.DeployRecord) error

	SearchDeployWhiteImage(ctx context.Context, param imagesecModel.SearchDeployWhiteImageParam) ([]imagesecModel.DeployWhiteImage, int64, error)
	CreateDeployWhiteImage(ctx context.Context, data []*imagesecModel.DeployWhiteImage) error
	UpdateDeployWhiteImage(ctx context.Context, id int64, updater map[string]interface{}) error
	DeleteDeployWhiteImage(ctx context.Context, id int64) error
	GroupRecordFlag(ctx context.Context, param imagesecModel.GroupDeployFlagParam) ([]imagesecModel.DeployFlagGroup, error)
}

type DeployDao struct {
	db *databases.RDBInstance
}

func NewDeployDao(db *databases.RDBInstance) *DeployDao {
	return &DeployDao{db: db}
}

func (dal *DeployDao) SearchDeployRecord(ctx context.Context, param imagesecModel.ImageDalParam) ([]*imagesecModel.DeployRecord, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	m := &imagesecModel.DeployRecord{}
	tableName := m.TableName()
	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)

	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if len(param.UUIDs) > 0 {
		db = db.Where("image_uuid IN ? ", param.UUIDs)
	}

	if param.ImageKeyword != "" {
		db = db.Where("image_name LIKE ? ", fmt.Sprintf("%%%s%%", param.ImageKeyword))
	}

	if len(param.PolicyUniqueID) > 0 {
		sp := make([]string, 0)
		for i := range param.PolicyUniqueID {
			sp = append(sp, fmt.Sprintf("policy_unique_id LIKE '%%%s%%'", param.PolicyUniqueID[i]))
		}
		if param.PolicyIntersection == consts.OrString {
			db = db.Where(strings.Join(sp, " OR "))
		}
		if param.PolicyIntersection == consts.AndString {
			db = db.Where(strings.Join(sp, " AND "))
		}
	}

	if len(param.UniqueIds) > 0 {
		db = db.Where("image_unique_id IN ?", param.UniqueIds)
	}
	if param.UniqueId > 0 {
		db = db.Where("image_unique_id  = ?", param.UniqueId)
	}

	if param.DeployActionFlag > 0 {
		db = db.Where("flag &  ? > 0", param.DeployActionFlag)
	}

	// 漏洞统计
	if param.VulnStaticFlag > 0 {
		if param.VulnStaticIntersection == imagesecModel.OrString {
			db = db.Where("flag &  ? > 0", param.VulnStaticFlag)
		} else {
			db = db.Where("flag &  ? = ?", param.VulnStaticFlag, param.VulnStaticFlag)
		}
	}

	// 部署上线状态
	if param.DeployActionFlag > 0 {
		db = db.Where("flag &  ? > 0", param.DeployActionFlag)
	}

	// 安全问题
	if param.SecurityIssueFlag > 0 {
		if param.IssueIntersection == imagesecModel.OrString {
			db = db.Where("flag &  ? > 0", param.SecurityIssueFlag)
		} else {
			db = db.Where("flag &  ? = ?", param.SecurityIssueFlag, param.SecurityIssueFlag)
		}
	}
	if param.StartTime > 0 {
		db = db.Where("created_at >= ?", param.StartTime)
	}
	if param.EndTime > 0 {
		db = db.Where("created_at <= ?", param.EndTime)
	}

	// 先查总数
	var cnt int64
	if !param.NotNeedCount {
		if err := db.Count(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}

	if param.Filter != nil && param.Filter.Offset >= consts.DefaultMaxLimit {
		db2 := db.Session(&gorm.Session{})
		db2 = db2.Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}, Desc: true})
		db2 = db2.Offset(int(param.Filter.Offset)).Limit(1)
		db2 = db2.Select("id")

		db = db.Where("id < ( ? )", db2)
		param.Filter = param.Filter.SetOffset(0)
	}

	db = model.AddFilter(db, param.Filter)

	res := make([]*imagesecModel.DeployRecord, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (dal *DeployDao) CreateDeployRecord(ctx context.Context, data *imagesecModel.DeployRecord) error {
	data.Serialize()

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	err := dal.db.Get().WithContext(ctx).Model(&imagesecModel.DeployRecord{}).Create(&data).Error

	return err
}

func (dal *DeployDao) SearchDeployWhiteImage(ctx context.Context, param imagesecModel.SearchDeployWhiteImageParam) ([]imagesecModel.DeployWhiteImage, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	m := &imagesecModel.DeployWhiteImage{}
	tableName := m.TableName()
	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)

	if param.ImageKeyword != "" {
		db = db.Where("image_name LIKE ? ", fmt.Sprintf("%%%s%%", param.ImageKeyword))
	}
	if param.ExpirationStart > 0 {
		db = db.Where("expiration_at >= ? ", param.ExpirationStart)
	}
	if param.ExpirationEnd > 0 {
		db = db.Where("expiration_at <= ? ", param.ExpirationEnd)
	}

	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	if param.Filter != nil && param.Filter.Offset >= consts.DefaultMaxLimit {
		db2 := db.Session(&gorm.Session{})
		db2 = db2.Offset(int(param.Filter.Offset)).Limit(1)
		db2 = db2.Select("id")

		db = db.Where("id >= ( ? )", db2)
		param.Filter = param.Filter.SetOffset(0)
	}

	db = model.AddFilter(db, param.Filter)

	res := make([]imagesecModel.DeployWhiteImage, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}

	return res, cnt, nil
}

func (dal *DeployDao) CreateDeployWhiteImage(ctx context.Context, data2 []*imagesecModel.DeployWhiteImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*200)
	defer cancelFunc()
	data := make([]*imagesecModel.DeployWhiteImage, 0)
	for i := range data2 {
		if err := data2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "deployImage").Msg("CreateDeployWhiteImage")
			continue
		}
		data = append(data, data2[i])
	}
	mo := &imagesecModel.DeployWhiteImage{}
	for i := range data {
		da := data[i]
		pre := &imagesecModel.DeployWhiteImage{}
		if err := dal.db.Get().WithContext(ctx).Model(mo).Where("image_name = ?", da.ImageName).First(pre).Error; err == nil {
			up := da.ToUpdater()
			if err := dal.db.Get().WithContext(ctx).Model(mo).Where("id = ?", pre.ID).Updates(up).Error; err != nil {
				return err
			}
			continue
		}

		if err := dal.db.Get().WithContext(ctx).Model(mo).Create(da).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}

	return nil
}

func (dal *DeployDao) UpdateDeployWhiteImage(ctx context.Context, id int64, updater map[string]interface{}) error {
	if id <= 0 || len(updater) == 0 {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	err := dal.db.Get().WithContext(ctx).Model(&imagesecModel.DeployWhiteImage{}).
		Where("id = ?", id).Updates(updater).Error
	return err
}

func (dal *DeployDao) DeleteDeployWhiteImage(ctx context.Context, id int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	err := dal.db.Get().WithContext(ctx).Model(&imagesecModel.DeployWhiteImage{}).
		Where("id = ?", id).Delete(&imagesecModel.DeployWhiteImage{}).Error

	return err
}

func (dal *DeployDao) GroupRecordFlag(ctx context.Context, param imagesecModel.GroupDeployFlagParam) ([]imagesecModel.DeployFlagGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := make([]imagesecModel.DeployFlagGroup, 0)
	// 根据param的参数，来查询数据库
	param.Serialize()
	mo := &imagesecModel.DeployRecord{}
	db := dal.db.Get().WithContext(ctx).Table(mo.TableName())
	if param.Day == consts.TrueString {
		db = db.Where("day >= ?", param.StartDay)
		db = db.Select("count(*) as cnt", "day", "flag").Group("day,flag")
	}

	if param.Hour == consts.TrueString {
		db = db.Where("hour >= ?", param.StartHour)
		db = db.Select("count(*) as cnt", "hour", "flag").Group("hour,flag")
	}

	if param.Reason == consts.TrueString {
		db = db.Where("day >= ?", param.StartDay)
		db = db.Select("count(*) as cnt", "flag").Group("flag")
	}

	err := db.Find(&res).Error

	return res, err
}
