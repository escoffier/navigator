package imagesec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像
type ImageMetaDal interface {
	CreateNodeImage(ctx context.Context, data []*imagesecModel.Image) error
	CreateRegImage(ctx context.Context, images2 []*imagesecModel.Image) error
	UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error
	SearchImage(ctx context.Context, param imagesecModel.ImageDalParam) ([]*imagesecModel.Image, int64, error)
	DeleteImage(ctx context.Context, id int64) error
	SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) ([]imagesecModel.Project, error)
	GetOnlineImageUUID(ctx context.Context) ([]uint32, error)
	GroupImageFlags(ctx context.Context, param imagesecModel.ImageGroupParam) ([]imagesecModel.ImageFlagGroup, error)
}

type ImageCacheDal interface {
	CreateCacheInfo(ctx context.Context, data *imagesecModel.CacheInfo) error
	SearchCacheInfo(ctx context.Context, dataType string) (*imagesecModel.CacheInfo, error)
}

type PreImageDal interface {
	DeletePreImage(ctx context.Context, image *model.ImageList) error
	CreatePreImage(ctx context.Context, image *model.ImageList) error
}

type ImageMetaDao struct {
	db *databases.RDBInstance
}

func NewImageMetaDao(db *databases.RDBInstance) *ImageMetaDao {
	return &ImageMetaDao{db: db}
}

type ImageCacheDao struct {
	db *databases.RDBInstance
}

func NewImageCacheDao(db *databases.RDBInstance) *ImageCacheDao {
	return &ImageCacheDao{db: db}
}

func (dal *ImageMetaDao) DeleteImage(ctx context.Context, id int64) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.Image{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("id = ?", id)
	return db.Delete(&m).Error
}

func (dal *ImageMetaDao) CreateNodeImage(ctx context.Context, images2 []*imagesecModel.Image) error {
	images := make([]*imagesecModel.Image, 0)
	for i := range images2 {
		images2[i].Serialize()
	}
	uniqueIds := make([]uint64, 0)
	for i := range images2 {
		if err := images2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Interface("image", images2[i]).Msg("CreateNodeImage")
			continue
		}
		images = append(images, images2[i])
		uniqueIds = append(uniqueIds, images2[i].UniqueID)
	}

	if len(images) == 0 {
		return nil
	}

	tableName := images[0].TableName()

	dbPre, _, err := dal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	needUpdate := make([]uint64, 0)
	createData := make([]*imagesecModel.Image, 0)
	for i := range dbPre {
		needUpdate = append(needUpdate, dbPre[i].UniqueID)
	}

	// find need create
	for i := range images {
		needCreate := true
		for j := range dbPre {
			if images[i].Same(dbPre[j]) {
				needCreate = false
				break
			}
		}
		if needCreate {
			createData = append(createData, images[i])
		}
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	if len(needUpdate) > 0 {
		updater := map[string]interface{}{"heartbeat": time.Now().UnixMilli()}
		_ = dal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
			UniqueIds: needUpdate,
			Updater:   updater,
		})
	}

	for i := range createData {
		if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Create(createData[i]).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}
	return nil
}

func (dal *ImageMetaDao) CreateRegImage(ctx context.Context, images2 []*imagesecModel.Image) error {
	images := make([]*imagesecModel.Image, 0)
	for i := range images2 {
		images2[i].Serialize()
	}

	uniqueIds := make([]uint64, 0)
	for i := range images2 {
		if err := images2[i].Check(); err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Interface("image", images2[i]).Msg("CreateRegImage")
			continue
		}
		images = append(images, images2[i])
		uniqueIds = append(uniqueIds, images2[i].UniqueID)
	}

	if len(images) == 0 {
		return nil
	}

	tableName := images[0].TableName()

	dbPre, _, err := dal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		return err
	}

	needUpdate := make([]uint64, 0)
	createData := make([]*imagesecModel.Image, 0)
	deleteData := make([]int64, 0)

	for i := range dbPre {
		needUpdate = append(needUpdate, dbPre[i].UniqueID)
	}
	dbMap := make(map[uint64]*imagesecModel.Image)
	for i := range dbPre {
		dbMap[dbPre[i].UniqueID] = dbPre[i]
	}

	// find need create
	for i := range images {
		im, ok := dbMap[images[i].UniqueID]
		if !ok {
			createData = append(createData, images[i])
			continue
		}
		if !im.Same(images[i]) {
			deleteData = append(deleteData, im.ID)
			continue
		}
		needUpdate = append(needUpdate, im.UniqueID)
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	if len(deleteData) > 0 {
		if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Where("id IN ?", deleteData).
			Delete(&imagesecModel.Image{}).Error; err != nil {
			return err
		}
	}

	if len(needUpdate) > 0 {
		updater := map[string]interface{}{"heartbeat": time.Now().UnixMilli()}
		_ = dal.UpdateImage(ctx, imagesecModel.UpdateImageParam{
			UniqueIds: needUpdate,
			Updater:   updater,
		})
	}

	for i := range createData {
		im := createData[i]
		if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Create(im).Error; err != nil {
			if strings.Contains(err.Error(), consts.DuplicateKey) {
				continue
			}
			return err
		}
	}
	return nil
}

func (dal *ImageMetaDao) UpdateImage(ctx context.Context, param imagesecModel.UpdateImageParam) error {
	if err := param.Check(); err != nil {
		return nil
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := &imagesecModel.Image{}
	tableName := m.TableName()

	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	if err := db.Updates(param.Updater).Error; err != nil {
		return err
	}
	return nil
}

func (dal *ImageMetaDao) SearchImage(ctx context.Context, param imagesecModel.ImageDalParam) (
	[]*imagesecModel.Image, int64, error) {

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	m := &imagesecModel.Image{}
	tableName := m.TableName()
	db := dal.db.Get().WithContext(cancelCtx).Table(tableName)
	if param.ImageFromType != "" {
		db = db.Where("image_from_type = ?", param.ImageFromType)
	}
	if param.CheckRegDeleted == consts.TrueString {
		sub := dal.db.Get().WithContext(ctx).Model(new(imagesecModel.Registry)).Select("id")
		db = db.Where("reg_id IN ( ? )", sub)
	}

	if len(param.UUIDs) > 0 {
		db = db.Where("image_uuid IN ? ", param.UUIDs)
	}
	if len(param.RegIds) > 0 {
		db = db.Where("reg_id IN ? ", param.RegIds)
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

	if len(param.ImageIds) > 0 {
		db = db.Where("id IN ? ", param.ImageIds)
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
		} else {
			db = db.Where(strings.Join(sp, " AND "))
		}
	}

	if len(param.UniqueIds) > 0 {
		db = db.Where("unique_id IN ?", param.UniqueIds)
	}
	if param.UniqueId > 0 {
		db = db.Where("unique_id  = ?", param.UniqueId)
	}

	if param.ID > 0 {
		db = db.Where("id =  ?", param.ID)
	}
	if param.SafeAttrFlag > 0 { // 只有取并集这一项目
		db = db.Where("flag &  ? > 0", param.SafeAttrFlag)
	}
	if param.OnlineFlag > 0 { // 只有取并集这一项目
		db = db.Where("flag &  ? > 0", param.OnlineFlag)
	}

	// 属性
	if param.ImageAttrFlag > 0 {
		if param.AttrIntersection == imagesecModel.AndString {
			db = db.Where("flag &  ? = ?", param.ImageAttrFlag, param.ImageAttrFlag)
		} else {
			db = db.Where("flag &  ? > 0", param.ImageAttrFlag)
		}
	}

	// 漏洞统计
	if param.VulnStaticFlag > 0 {
		if param.VulnStaticIntersection == imagesecModel.AndString {
			db = db.Where("flag &  ? = ?", param.VulnStaticFlag, param.VulnStaticFlag)
		} else {
			db = db.Where("flag &  ? > 0", param.VulnStaticFlag)
		}
	}

	// 安全问题
	if param.SecurityIssueFlag > 0 {
		if param.IssueIntersection == imagesecModel.AndString {
			db = db.Where("flag &  ? = ?", param.SecurityIssueFlag, param.SecurityIssueFlag)
		} else {
			db = db.Where("flag &  ? > 0", param.SecurityIssueFlag)
		}
	}

	// 节点名搜索
	if param.ImageFromType == imagesecModel.ImageFromNode && (param.NodeKeyword != "" || len(param.ClusterKey) > 0) {
		sub := dal.db.Get().WithContext(ctx).Model(new(imagesecModel.NodeInfo)).Select("unique_id")
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
		db = db.Where("digest IN ?  ", param.Digests)
	}

	if param.WebshellMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.Webshell).TableName()).Select("unique_id").Where("md5 = ?", param.WebshellMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.WebshellToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		db = db.Where("unique_id IN ( ? )", sub2)
	}
	if param.VulnUniqueID > 0 {
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.VulnToImage).TableName()).Select("image_unique_id").
			Where("unique_target  =  ? ", param.VulnUniqueID)
		db = db.Where("unique_id IN ( ? )", sub2)
	}

	if param.PkgUniqueID > 0 {
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.PkgToImage).TableName()).Select("image_unique_id").
			Where("unique_target  =  ? ", param.PkgUniqueID)
		db = db.Where("unique_id IN ( ? )", sub2)
	}

	if param.MalwareMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.Malware).TableName()).Select("unique_id").Where("hash = ?", param.MalwareMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.MalwareToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		db = db.Where("unique_id IN ( ? )", sub2)
	}

	if param.SensitiveMD5 != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.SensitiveFile).TableName()).Select("unique_id").Where("md5 = ?", param.SensitiveMD5)
		sub2 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.SensitiveToImage).TableName()).Select("image_unique_id").Where("unique_target IN ( ? )", sub1)
		db = db.Where("unique_id IN ( ? )", sub2)
	}

	if param.StartID > 0 {
		db = db.Where("id > ?", param.StartID)
	}

	if param.LessHeartbeat > 0 {
		db = db.Where("heartbeat < ?", param.LessHeartbeat)
	}
	if param.LayerStrPrefix != "" {
		db = db.Where("layer_str LIKE ?", fmt.Sprintf("%s%%", param.LayerStrPrefix))
	}
	if param.RegKeyword != "" {
		sub1 := dal.db.Get().WithContext(ctx).Table(new(imagesecModel.Registry).TableName()).Select("id").
			Where("name LIKE ? OR url LIKE ? ", fmt.Sprintf("%%%s%%", param.RegKeyword), fmt.Sprintf("%%%s%%", param.RegKeyword))
		db = db.Where("reg_id IN ( ? )", sub1)
	}

	// 先查总数
	var cnt int64
	if !param.NotNeedCount {
		if err := db.Count(&cnt).Error; err != nil {
			return nil, 0, err
		}
	}

	// fixme 加了排序，就不能这么优化了
	// if param.Filter != nil && param.Filter.Offset > consts.DefaultMaxLimit {
	// 	filter := param.Filter.DeepCopy().SetLimit(1)
	// 	db2 := db.Session(&gorm.Session{})
	// 	db2 = model.AddFilter(db2, filter)
	// 	db2 = db2.Select("id")
	//
	// 	db = db.Where("id >= ( ? )", db2)
	// 	param.Filter = param.Filter.SetOffset(0)
	// }

	db = model.AddFilter(db, param.Filter)
	res := make([]*imagesecModel.Image, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	for i := range res {
		res[i].Deserialize()
	}

	return res, cnt, nil
}

func (dal *ImageMetaDao) SearchProject(ctx context.Context, param imagesecModel.SearchProjectParam) ([]imagesecModel.Project, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*15)
	defer cancelFunc()
	type Repo struct {
		NodeID  uint64 `gorm:"column:node_id"`
		RegID   int64  `gorm:"column:reg_id"`
		Project string `gorm:"column:project"`
	}
	mode := &imagesecModel.Image{ImageFromType: param.ImageFromType}
	db := dal.db.Get().WithContext(ctx).Table(mode.TableName())
	if param.RegID > 0 {
		db = db.Where("reg_id = ?", param.RegID)
	}
	if param.NodeID > 0 {
		db = db.Where("node_id = ?", param.NodeID)
	}
	if param.Keyword != "" {
		db = db.Where("project LIKE ?", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ImageFromType == imagesecModel.ImageFromRegistry {
		db = db.Select("distinct reg_id,project")
	} else if param.ImageFromType == imagesecModel.ImageFromNode {
		db = db.Select("distinct node_id,project")
	}

	res := make([]Repo, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	ans := make([]imagesecModel.Project, 0)
	for i := range res {
		an := imagesecModel.Project{
			RegID:        res[i].RegID,
			Project:      res[i].Project,
			NodeUniqueID: res[i].NodeID,
		}
		if param.ImageFromType == imagesecModel.ImageFromRegistry && an.RegID <= 0 {
			continue
		}
		if param.ImageFromType == imagesecModel.ImageFromNode && an.NodeUniqueID <= 0 {
			continue
		}

		ans = append(ans, an)
	}

	return ans, nil
}

func (dal *ImageMetaDao) GetOnlineImageUUID(ctx context.Context) ([]uint32, error) {

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	ans := make([]uint32, 0)
	db := dal.db.Get().WithContext(ctx).Table(new(model.TensorRawContainer).TableName())
	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortFiled("image_uuid").SetSortAsc()

	var startID uint32

	for {
		res := make([]*model.TensorRawContainer, 0)

		db = db.Where("image_uuid > ?", startID).Where("status = 0")
		db = db.Select("image_uuid")

		db = model.AddFilter(db, filter)
		if err := db.Find(&res).Error; err != nil {
			return ans, err
		}
		if len(res) == 0 {
			break
		}
		startID = res[len(res)-1].ImageUUID

		th := make([]uint32, 0)
		for i := range res {
			th = append(th, res[i].ImageUUID)
		}
		th = util.DuplicateUint32Slice(th)
		ans = append(ans, th...)
	}

	ans = util.DuplicateUint32Slice(ans)
	return ans, nil
	// if param.ImageUUID > 0 {
	// 	db = db.Where("image_uuid = ?", param.ImageUUID)
	// }

	// 不能使用 redis 了，
	// if dal.redisCli == nil {
	// 	return nil, fmt.Errorf("not get redis client")
	// }
	// uuids := make([]uint32, 0)
	// start := 0
	// tmx, cancelFunc := context.WithTimeout(context.Background(), time.Second*100)
	// defer cancelFunc()
	// cnt := 0
	// for {
	// 	opt := &redis.ZRangeBy{
	// 		Min:   strconv.Itoa(int(start)),
	// 		Max:   consts.RedisPositiveInfinity,
	// 		Count: consts.DefaultMaxLimit,
	// 	}
	// 	scores := dal.redisCli.ZRangeByScoreWithScores(tmx, consts.OnlineImageRedisKey, opt)
	// 	result, err := scores.Result()
	// 	if err != nil {
	// 		logging.Get().Err(err).Str("module", "imageMeta").Int("uuid", len(uuids)).Msg("updateOnlineImage")
	// 		return nil, err
	// 	}
	// 	ans := make([]int, 0)
	// 	for i := range result {
	// 		if int(result[i].Score) <= 0 {
	// 			continue
	// 		}
	// 		ans = append(ans, int(result[i].Score))
	// 	}
	// 	if len(ans) == 0 {
	// 		break
	// 	}
	// 	ans = util.DuplicateIntSlice(ans)
	// 	sort.Ints(ans)
	// 	start = ans[len(ans)-1] + 1
	// 	for i := range ans {
	// 		uuids = append(uuids, uint32(ans[i]))
	// 	}
	// 	uuids = util.DuplicateUint32Slice(uuids)
	//
	// 	if len(uuids) == cnt {
	// 		break
	// 	}
	// 	cnt = len(uuids)
	// }
	// return uuids, nil
}

func (dal *ImageMetaDao) GroupImageFlags(ctx context.Context, param imagesecModel.ImageGroupParam) ([]imagesecModel.ImageFlagGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(&imagesecModel.Image{})
	res := make([]imagesecModel.ImageFlagGroup, 0)

	if param.ImageFromType != "" {
		db = db.Where("image_from_type = ?", param.ImageFromType)
	}

	db = db.Select("count(*) as cnt", "flag").Group("flag")

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}

	return res, nil
}

func (dal *ImageMetaDao) DeletePreImage(ctx context.Context, image *model.ImageList) error {
	if image == nil {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	tableName := image.TableName()
	if image.ID > 0 {
		_ = dal.db.Get().WithContext(ctx).Table(tableName).Where("id = ?", image.ID).Delete(&model.ImageList{}).Error
	}
	if image.UniqueImage > 0 {
		_ = dal.db.Get().WithContext(ctx).Table(tableName).Where("unique_image = ?", image.UniqueImage).Delete(&model.ImageList{}).Error
	}
	// if image.Digest != "" {
	// 	_ = dal.db.Get().WithContext(ctx).Table(tableName).Where("digest = ?", image.Digest).Delete(&model.ImageList{}).Error
	// }
	if image.FullRepoName != "" && image.Tags != "" && image.RegistryID > 0 {
		_ = dal.db.Get().WithContext(ctx).Table(tableName).Where("full_repo_name = ?", image.FullRepoName).
			Where("tags = ?", image.Tags).Where("registry_id = ?", image.RegistryID).Delete(&model.ImageList{}).Error
	}

	return nil
}

func (dal *ImageMetaDao) CreatePreImage(ctx context.Context, image *model.ImageList) error {
	if image == nil {
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	tableName := image.TableName()
	err := dal.db.Get().WithContext(ctx).Table(tableName).Create(image).Error
	return err
}

func (dal *ImageCacheDao) CreateCacheInfo(ctx context.Context, data *imagesecModel.CacheInfo) error {
	if err := data.Check(); err != nil {
		return err
	}

	data.Serialize()
	tableName := data.TableName()
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()

	info, err := dal.SearchCacheInfo(ctx, data.DataType)
	if err == nil && info != nil {
		up := data.ToUpdater()
		if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Where("id =  ?", info.ID).Updates(up).Error; err != nil {
			return err
		}
		return nil
	}
	if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Create(data).Error; err != nil {
		return err
	}

	return nil
}

func (dal *ImageCacheDao) SearchCacheInfo(ctx context.Context, dataType string) (*imagesecModel.CacheInfo, error) {

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*100)
	defer cancelFunc()
	mod := &imagesecModel.CacheInfo{}
	tableName := mod.TableName()
	res := make([]*imagesecModel.CacheInfo, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(tableName).Where("data_type =  ?", dataType).Find(&res).Error; err != nil {
		return nil, err
	}
	for i := range res {
		res[i].Deserializer()
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("not find:%s", dataType)
	}

	return res[0], nil
}

// 所有镜像的统计，不统计镜像本身属性
func ToSecurityOverView(groups []imagesecModel.ImageFlagGroup) imagesecModel.SecurityStatistic {
	overView := imagesecModel.SecurityStatistic{}

	for i := range groups {
		overView.ImageCount += groups[i].Count

		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionVuln) {
			overView.Total.Vuln += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionSensitive) {
			overView.Total.Sensitive += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionMalware) {
			overView.Total.Malware += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionWebshell) {
			overView.Total.Webshell += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionEnv) {
			overView.Total.Env += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionPKG) {
			overView.Total.Pkg += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionPkgLicense) {
			overView.Total.PkgLicense += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionLicense) {
			overView.Total.License += groups[i].Count
		}
		// if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasFixedVuln) {
		// 	overView.Total.HasFixedVuln += groups[i].Count
		// }
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagDetectExceptionBoot) {
			overView.Total.ExceptionBoot += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDetectUnTrusted) {
			overView.Total.Untrusted += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDetectNotExitINReg) {
			overView.Total.NotInRegistry += groups[i].Count
		}
	}

	for i := range groups {
		if !util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageOnline) {
			continue
		}
		overView.OnlineCount += groups[i].Count
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionVuln) {
			overView.Online.Vuln += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionSensitive) {
			overView.Online.Sensitive += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionMalware) {
			overView.Online.Malware += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionWebshell) {
			overView.Online.Webshell += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionEnv) {
			overView.Online.Env += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionPKG) {
			overView.Online.Pkg += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionPkgLicense) {
			overView.Online.PkgLicense += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagHasExceptionLicense) {
			overView.Online.License += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagDetectExceptionBoot) {
			overView.Online.ExceptionBoot += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDetectUnTrusted) {
			overView.Online.Untrusted += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDetectNotExitINReg) {
			overView.Online.NotInRegistry += groups[i].Count
		}
	}
	return overView
}
