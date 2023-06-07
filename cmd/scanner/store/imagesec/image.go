package imagesec

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

// 镜像
type ImageMetaDal interface {
	CreateImage(ctx context.Context, data *imagesec.Image) error
	UpdateImage(ctx context.Context, param imagesec.UpdateImageParam) error
	SearchImage(ctx context.Context, param imagesec.NodeImageDalParam) ([]*imagesec.Image, int64, error)
	DeleteImage(ctx context.Context, imageFromType string, id int64) error
	SearchProject(ctx context.Context, param imagesec.SearchProjectParam) ([]imagesec.Project, error)
	GetOnlineImageUUID(ctx context.Context, start uint32, limit int64) ([]uint32, error)
}

type ImageMetaDao struct {
	db       *databases.RDBInstance
	redisCli *redis.Client
}

func NewImageMetaDao(db *databases.RDBInstance, redisCli *redis.Client) *ImageMetaDao {
	return &ImageMetaDao{db: db, redisCli: redisCli}
}

func (dal *ImageMetaDao) DeleteImage(ctx context.Context, imageFromType string, id int64) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesec.Image{ImageFromType: imageFromType}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("id = ?", id)
	return db.Delete(&m).Error
}

func (dal *ImageMetaDao) CreateImage(ctx context.Context, data *imagesec.Image) error {
	data.Serialize()

	if err := data.Check(); err != nil {
		return err
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	exit := make([]*imagesec.Image, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).
		Where("unique_id = ?", data.UniqueID).Find(&exit).Error; err != nil {
		return err
	}

	if len(exit) > 0 {
		updater := map[string]interface{}{"heartbeat": time.Now().UnixMilli()}
		if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).
			Where("unique_id = ?", data.UniqueID).Updates(updater).Error; err != nil {
			return err
		}
		return nil
	}

	if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error; err != nil {
		return err
	}
	return nil
}

func (dal *ImageMetaDao) UpdateImage(ctx context.Context, param imagesec.UpdateImageParam) error {
	if err := param.Check(); err != nil {
		return nil
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := &imagesec.Image{}
	tableName := m.TableName()

	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	if err := db.Updates(param.Updater).Error; err != nil {
		return err
	}
	return nil
}

func (dal *ImageMetaDao) SearchImage(ctx context.Context, param imagesec.NodeImageDalParam) (
	[]*imagesec.Image, int64, error) {

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	m := &imagesec.Image{}
	tableName := m.TableName()
	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)
	if param.ImageFromType != "" {
		db = db.Where("image_from_type = ?", param.ImageFromType)
	}

	if len(param.UUIDs) > 0 {
		db = db.Where("image_uuid IN ? ", param.UUIDs)
	}
	if len(param.Projects) > 0 {
		where := make([]string, 0)
		for i := range param.Projects {
			if param.Projects[i].ProjectName == "" {
				where = append(where, fmt.Sprintf("(reg_id = %d)", param.Projects[i].RegID))
			} else {
				where = append(where, fmt.Sprintf("(reg_id = %d  AND project = '%s')", param.Projects[i].RegID, param.Projects[i].ProjectName))
			}
		}
		db = db.Where(strings.Join(where, " OR "))
	}

	if len(param.InIds) > 0 {
		db = db.Where("id IN ? ", param.InIds)
	}
	if len(param.NotInIds) > 0 {
		db = db.Where("id NOT IN ? ", param.NotInIds)
	}

	if param.ImageKeyword != "" {
		db = db.Where("image_name LIKE ? ", fmt.Sprintf("%%%s%%", param.ImageKeyword))
	}

	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	if param.UniqueId > 0 {
		db = db.Where("unique_id  = ?", param.UniqueId)
	}
	if param.ImageID > 0 {
		db = db.Where("id =  ?", param.ImageID)
	}
	if param.AndFlag > 0 {
		db = db.Where("flag &  ? = ?", param.AndFlag, param.AndFlag)
	}
	if param.OrFlag > 0 {
		db = db.Where("flag &  ? > 0 ", param.OrFlag)
	}

	// 节点名搜索
	if param.ImageFromType == imagesec.ImageFromNode && (param.NodeKeyword != "" || len(param.ClusterKey) > 0) {
		sub := dal.db.Get().WithContext(ctx).Model(new(imagesec.NodeInfo)).Select("unique_id")
		if param.NodeKeyword != "" {
			sub = sub.Where("hostname  LIKE ?", fmt.Sprintf("%%%s%%", param.NodeKeyword))
		}
		if len(param.ClusterKey) > 0 {
			sub = sub.Where("cluster_key IN ?", param.ClusterKey)
		}
		db = db.Where("node_id IN ( ? )", sub)
	}

	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}
	if len(param.OmitFields) > 0 {
		db = db.Omit(param.OmitFields...)
	}

	if len(param.Digests) > 0 {
		db = db.Where("digest IN   ?  ", param.Digests)
	}

	if param.WebshellMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesec.Webshell).TableName()).Select("unique_id").Where("md5 = ?", param.WebshellMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesec.WebshellToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		db = db.Where("unique_id IN ( ? )", sub2)
	}

	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}
	if param.LessHeartbeat > 0 {
		db = db.Where("heartbeat < ?", param.LessHeartbeat)
	}

	db = model.AddFilter(db, param.Filter)

	res := make([]*imagesec.Image, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (dal *ImageMetaDao) SearchProject(ctx context.Context, param imagesec.SearchProjectParam) ([]imagesec.Project, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*15)
	defer cancelFunc()
	type Repo struct {
		NodeID  uint64 `gorm:"column:node_id"`
		RegID   int64  `gorm:"column:reg_id"`
		Project string `gorm:"column:project"`
	}
	mode := &imagesec.Image{ImageFromType: param.ImageFromType}
	db := dal.db.Get().WithContext(ctx).Model(mode.TableName())
	if param.RegID > 0 {
		db = db.Where("reg_id = ?", param.RegID)
	}
	if param.NodeID > 0 {
		db = db.Where("node_id = ?", param.NodeID)
	}
	if param.Keyword != "" {
		db = db.Where("project LIKE ?", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ImageFromType == imagesec.ImageFromRegistry {
		db = db.Select("distinct reg_id,project")
	} else if param.ImageFromType == imagesec.ImageFromNode {
		db = db.Select("distinct node_id,project")
	}

	res := make([]Repo, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	ans := make([]imagesec.Project, 0)
	for i := range res {
		ans = append(ans, imagesec.Project{
			RegistryID:   res[i].RegID,
			Project:      res[i].Project,
			NodeUniqueID: res[i].NodeID,
		})
	}

	return ans, nil
}

func (dal *ImageMetaDao) GetOnlineImageUUID(ctx context.Context, start uint32, limit int64) ([]uint32, error) {
	if dal.redisCli == nil {
		return nil, fmt.Errorf("not get ridis client")
	}
	uuids := make([]uint32, 0)
	opt := &redis.ZRangeBy{
		Min:   strconv.Itoa(int(start)),
		Max:   consts.RedisPositiveInfinity,
		Count: limit,
	}
	if opt.Count <= 0 {
		opt.Count = consts.DefaultLimit
	}
	scores := dal.redisCli.ZRangeByScoreWithScores(ctx, consts.OnlineImageRedisKey, opt)
	result, err := scores.Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	ans := make([]int, 0)
	for i := range result {
		ans = append(ans, int(result[i].Score))
	}
	sort.Ints(ans)
	for i := range ans {
		uuids = append(uuids, uint32(ans[i]))
	}

	return uuids, nil
}

func GetOnlineImageUUIDSub(ctx context.Context, db *gorm.DB) *gorm.DB {
	sub := db.WithContext(ctx).Model(new(model.ImageList)).Select("distinct ivan_scanner_image_list.image_uuid").
		Joins("join ivan_assets_containers on ivan_assets_containers.image_uuid = ivan_scanner_image_list.image_uuid").
		Where("ivan_assets_containers.status = 0")
	return sub
}
