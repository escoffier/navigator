package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanCiInterface interface {
	CreatePolicy(context.Context, scanner_ci.CiPolicy) (int64, error)
	UpdatePolicy(context.Context, scanner_ci.CiPolicy) error
	GetPolicyDetail(context.Context, int64) (scanner_ci.CiPolicy, error)
	CreateWhitelist(context.Context, []scanner_ci.CiWhitelist) error
	GetPolicyByName(context.Context, string) (scanner_ci.CiPolicy, error)
	UpdateWhitelist(context.Context, []scanner_ci.CiWhitelist) error
	DeleteWhitelist(context.Context, int64) error
	GetWhitelist(context.Context, scanner_ci.WhitelistParams) ([]scanner_ci.CiWhitelist, int64, error)
	GetImageList(context.Context, scanner_ci.ImageFilter) ([]scanner_ci.CiScan, int64, error)
	GetImageDetail(context.Context, int64) (scanner_ci.CiScan, error)
	GetImageOverview(context.Context, int64) ([]scanner_ci.CiScan, error)
	CreateCiVuln(context.Context, []*scanner_ci.CiVulns) error
	CreateVulnImage(context.Context, int64, []*scanner_ci.CiVulnImage) error
	CreatePkgImage(context.Context, int64, []*scanner_ci.CiPkgImage) error
	CreateRecord(context.Context, scanner_ci.CiScan) (int64, error)
	GetPolicyList(context.Context, int64, int64, string) ([]scanner_ci.CiPolicy, int64, error)
	DeletePolicy(context.Context, int64) error
	GetRecordTop5(context.Context) ([]scanner_ci.ImageRecordTop5, error)
	SearchVuln(context.Context, scanner_ci.SearchVulnParm, *model.Filter) ([]*scanner_ci.CiVulns, model.SeverityHistogramInfo, int64, error)
	SearchPkgImage(context.Context, int64, int64, string, int64, bool) ([]scanner_ci.CiPkgImage, int64, error)
	CreateWebhook(context.Context, scanner_ci.Webhook) error
	UpdateWebhook(context.Context, scanner_ci.Webhook, int64) error
	GetWebhook(context.Context) (scanner_ci.Webhook, error)
	GetWebhookRecords(context.Context, int, int) ([]scanner_ci.WebhookRecord, int64, error)
	CreateWebhookRecord(context.Context, scanner_ci.WebhookRecord)
	CreatePkgs(context.Context, []scanner_ci.CiPkgs) error
	GetPkgs(context.Context, int, int, int64, string) ([]scanner_ci.CiPkgs, int64, error)
	CreateSensitiveImages(context.Context, []scanner_ci.CiSensitiveImages) error
	GetSensitiveImages(context.Context, int, int, int64, string, bool) ([]scanner_ci.CiSensitiveImages, int64, error)
	TickerCleanRecord(context.Context, int)
}

type CiDao struct {
	db *databases.RDBInstance
}

func NewCiDao(db *databases.RDBInstance) *CiDao {
	return &CiDao{db: db}
}

func (c *CiDao) CreateSensitiveImages(ctx context.Context, sensitives []scanner_ci.CiSensitiveImages) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiSensitiveImages{}).WithContext(ctxd).CreateInBatches(sensitives, 100).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("create sensitive file error")
		return err
	}
	return nil
}

func (c *CiDao) GetSensitiveImages(ctx context.Context, limit int, offset int, imageID int64, search string, matchPolicy bool) ([]scanner_ci.CiSensitiveImages, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.CiSensitiveImages{}).WithContext(ctxd)

	if imageID != 0 {
		db = db.Where("image_id = ?", imageID)
	}

	if matchPolicy {
		db = db.Where("match_policy = ?", matchPolicy)
	}

	if search != "" {
		db = db.Where("file like ?", fmt.Sprintf("%%%s%%", search))
	}

	var cnt int64
	db.Count(&cnt)

	if limit != 0 {
		db = db.Limit(limit)
	}

	if offset != 0 {
		db = db.Offset(offset)
	}
	var res []scanner_ci.CiSensitiveImages
	err := db.Find(&res).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get sensitive images error")
		return res, 0, err
	}
	return res, cnt, nil
}

func (c *CiDao) CreatePkgs(ctx context.Context, pkgs []scanner_ci.CiPkgs) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiPkgs{}).WithContext(ctxd).CreateInBatches(pkgs, 100).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("create pkgs error")
		return err
	}
	return nil
}

func (c *CiDao) GetPkgs(ctx context.Context, limit int, offset int, imageID int64, search string) ([]scanner_ci.CiPkgs, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Minute*10)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.CiPkgs{}).WithContext(ctxd)

	if imageID != 0 {
		db = db.Where("image_id = ?", imageID)
	}

	if search != "" {
		db = db.Where("unique_pkg like ?", fmt.Sprintf("%%%s%%", search))
	}

	var cnt int64
	db.Count(&cnt)

	if limit != 0 {
		db = db.Limit(limit)
	}

	if offset != 0 {
		db = db.Offset(offset)
	}

	res := []scanner_ci.CiPkgs{}
	err := db.Find(&res).Error

	if err != nil {
		logging.GetLogger().Err(err).Msgf("GetPkgs error")
		return res, 0, err
	}

	return res, cnt, nil
}

func (c *CiDao) TickerCleanRecord(ctx context.Context, limit int) {
	ctxd, cancel := context.WithTimeout(ctx, time.Minute*2)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.CiScan{})
	var cnt int64
	db.Count(&cnt)
	type tmp struct {
		ID int64 `json:"id"`
	}
	maxId := tmp{}
	if cnt > int64(limit) {
		err := db.Select("min(id) as id").Limit(limit).Find(&maxId).WithContext(ctxd).Order("id desc").Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get ciscan max id error")
			return
		}
		err = c.db.Get().Model(&scanner_ci.CiScan{}).Delete(&scanner_ci.CiScan{}).WithContext(ctxd).Where("id < ?", maxId.ID).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete error")
			return
		}
	}
}

func (c *CiDao) GetImageOverview(ctx context.Context, startAt int64) ([]scanner_ci.CiScan, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	res := []scanner_ci.CiScan{}
	db := c.db.Get().Model(&scanner_ci.CiScan{}).WithContext(ctxd)
	err := db.Select("started_at,mode").Where("started_at > ?", startAt).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *CiDao) GetImageDetail(ctx context.Context, id int64) (scanner_ci.CiScan, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	res := scanner_ci.CiScan{}
	err := c.db.Get().Model(&scanner_ci.CiScan{}).WithContext(ctxd).Where("id = ?", id).Find(&res).Error
	if err != nil {
		return res, err
	}
	return res, nil
}

func (c *CiDao) GetImageList(ctx context.Context, params scanner_ci.ImageFilter) ([]scanner_ci.CiScan, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	res := []scanner_ci.CiScan{}
	db := c.db.Get().Model(&scanner_ci.CiScan{}).WithContext(ctxd)
	if params.Image != "" {
		db = db.Where("image_name like ?", fmt.Sprintf("%%%s%%", params.Image))
	}
	if len(params.Kind) != 0 {
		var flag uint64
		for i := range params.Kind {
			flag = util.SetBit1(flag, uint64(params.Kind[i]))
		}

		if params.KindAttribute == consts.AndString {
			db = db.Where("flag & ? = ?", flag, flag)
		}
		if params.KindAttribute == consts.OrString {
			db = db.Where("flag & ? > 0", flag)
		}
	}

	if params.TaskName != "" {
		db = db.Where("pipeline_name like ?", fmt.Sprintf("%%%s%%", params.TaskName))
	}

	if len(params.Status) != 0 {
		db = db.Where("mode IN ?", params.Status)
	}
	if params.StartTime != 0 {
		db = db.Where("started_at >= ?", params.StartTime)

	}
	if params.EndTime != 0 {
		db = db.Where("started_at <= ?", params.EndTime)
	}
	var cnt int64
	db.Count(&cnt)
	if params.Offset != 0 {
		db = db.Offset(params.Offset)
	}
	if params.Limit != 0 {
		db = db.Limit(params.Limit)
	}
	err := db.Order("started_at DESC").Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	return res, cnt, err
}

func (c *CiDao) GetPolicyDetail(ctx context.Context, id int64) (scanner_ci.CiPolicy, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	policy := scanner_ci.CiPolicy{}
	err := c.db.Get().Model(&scanner_ci.CiPolicy{}).WithContext(ctxd).Where("id = ?", id).Find(&policy).Error
	if err != nil {
		return policy, err
	}
	return policy, nil
}

func (c *CiDao) GetPolicyByName(ctx context.Context, name string) (scanner_ci.CiPolicy, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	policy := scanner_ci.CiPolicy{}
	err := c.db.Get().WithContext(timeoutCtx).Model(&scanner_ci.CiPolicy{}).Where("name = ?", name).Find(&policy).Error
	if err != nil {
		return policy, err
	}
	return policy, nil
}

func (c *CiDao) DeletePolicy(ctx context.Context, id int64) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiPolicy{}).WithContext(ctxd).Where("id = ?", id).Delete(&scanner_ci.CiPolicy{}).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *CiDao) UpdatePolicy(ctx context.Context, policy scanner_ci.CiPolicy) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiPolicy{}).WithContext(ctxd).Omit("created_at", "operator").Select("*").Where("id = ?", policy.ID).Updates(&policy).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *CiDao) GetPolicyList(ctx context.Context, limit int64, offset int64, name string) ([]scanner_ci.CiPolicy, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.CiPolicy{}).Order("updated_at DESC").WithContext(ctxd)
	if limit != 0 {
		db = db.Limit(int(limit))
	}
	if offset != 0 {
		db = db.Offset(int(offset))
	}
	if name != "" {
		db = db.Where("name like ?", fmt.Sprintf("%%%s%%", name))
	}
	var cnt int64
	db.Count(&cnt)
	var res []scanner_ci.CiPolicy
	err := db.Find(&res).Error
	if err != nil {
		return res, 0, err
	}
	return res, cnt, nil
}

func (c *CiDao) CreatePolicy(ctx context.Context, policy scanner_ci.CiPolicy) (int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiPolicy{}).WithContext(ctxd).Create(&policy).Error
	if err != nil {
		return -1, err
	}
	return policy.ID, err
}

func (c *CiDao) DeleteWhitelist(ctx context.Context, id int64) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiWhitelist{}).WithContext(ctxd).Where("id = ?", id).Delete(&scanner_ci.CiWhitelist{}).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *CiDao) UpdateWhitelist(ctx context.Context, whitelist []scanner_ci.CiWhitelist) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*100)
	defer cancel()
	var rerr error
	for k := range whitelist {
		err := c.db.Get().Model(&scanner_ci.CiWhitelist{}).WithContext(ctxd).Where("id = ?", whitelist[k].ID).Omit("created_at", "id").Select("*").Updates(whitelist[k]).Error
		if err != nil {
			logging.GetLogger().Err(err).Msgf("update whitelist name:%s error", whitelist[k].Name)
			rerr = err
		}
	}
	return rerr
}

func (c *CiDao) CreateWhitelist(ctx context.Context, whitelist []scanner_ci.CiWhitelist) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiWhitelist{}).WithContext(ctxd).CreateInBatches(&whitelist, 100).Error
	if err != nil {
		return err
	}
	return err
}

func (c *CiDao) GetWhitelist(ctx context.Context, params scanner_ci.WhitelistParams) ([]scanner_ci.CiWhitelist, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	var res []scanner_ci.CiWhitelist
	db := c.db.Get().Model(&scanner_ci.CiWhitelist{}).WithContext(ctxd).Order("updated_at DESC")
	if params.Image != "" {
		db = db.Where("name like ?", fmt.Sprintf("%%%s%%", params.Image))
	}

	if params.StartTime != 0 {
		db = db.Where("expire_time >= ?", params.StartTime)
	}
	if params.EndTime != 0 {
		db = db.Where("expire_time <= ?", params.EndTime)
	}
	if params.NowTime != 0 {
		db = db.Where("expire_time >= ?", params.NowTime)
	}
	var cnt int64
	db.Count(&cnt)
	if params.Offset != 0 {
		db = db.Offset(params.Offset)
	}
	if params.Limit != 0 {
		db = db.Limit(params.Limit)
	}

	err := db.Find(&res).Error
	if err != nil {
		return []scanner_ci.CiWhitelist{}, 0, err
	}
	return res, cnt, nil
}

func (c *CiDao) GetRecordTop5(ctx context.Context) ([]scanner_ci.ImageRecordTop5, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	res := []scanner_ci.ImageRecordTop5{}
	err := c.db.Get().Model(&scanner_ci.CiScan{}).WithContext(ctxd).Select("count(*) as count,image_name").Group("image_name").Order("count desc").Limit(5).Find(&res).Error
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *CiDao) CreateRecord(ctx context.Context, record scanner_ci.CiScan) (int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.CiScan{}).WithContext(ctxd).WithContext(ctx).Create(&record).Error
	if err != nil {
		return -1, err
	}
	return record.ID, nil
}

func (c *CiDao) removeDuplicateVuln(data []*scanner_ci.CiVulns) []*scanner_ci.CiVulns {
	exit := map[uint64]struct{}{}
	ans := make([]*scanner_ci.CiVulns, 0, len(data))

	for i := range data {
		if _, ok := exit[data[i].UniqueVuln]; !ok {
			ans = append(ans, data[i])
		}
		exit[data[i].UniqueVuln] = struct{}{}
	}
	return ans
}

func (c *CiDao) addHistogram(Severity string, cnt int64, his *model.SeverityHistogramInfo) {
	switch Severity {
	case "CRITICAL":
		his.NumCritical += cnt
	case "HIGH":
		his.NumHigh += cnt
	case "MEDIUM":
		his.NumMedium += cnt
	case "LOW":
		his.NumLow += cnt
	case "UNKNOWN":
		his.NumUnknown += cnt
	}
}

func (c *CiDao) SearchVuln(ctx context.Context, param scanner_ci.SearchVulnParm, filter *model.Filter) ([]*scanner_ci.CiVulns, model.SeverityHistogramInfo, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := c.db.Get().WithContext(ctx).Model(scanner_ci.CiVulns{})
	ciVulnImages := []scanner_ci.CiVulnImage{}
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
	if param.ImageID > 0 {
		sub := c.db.Get().WithContext(ctx).Model(new(scanner_ci.CiVulnImage)).Select("unique_vuln", "match_policy", "white").Where("image_id = ?", param.ImageID)
		if param.MatchPolicy {
			sub = sub.Where("match_policy > 0")
		}
		err := sub.Find(&ciVulnImages).Error
		if err != nil {
			return nil, model.SeverityHistogramInfo{}, 0, err
		}
		var list []uint64
		if len(ciVulnImages) == 0 {
			return make([]*scanner_ci.CiVulns, 0), model.SeverityHistogramInfo{}, 0, err
		}
		for k := range ciVulnImages {
			list = append(list, ciVulnImages[k].UniqueVuln)
		}
		db = db.Where("unique_vuln IN (?)", list)
	}
	if param.PkgName != "" {
		db = db.Where("pkg_name = ?", param.PkgName)
	}
	if param.PkgVersion != "" {
		db = db.Where("pkg_version = ?", param.PkgVersion)
	}
	if param.CanFixed == consts.TrueString {
		db = db.Where("fixed_by != ''")
	}
	if param.CanFixed == consts.FalseString {
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
		db = db.Where("name LIKE ?", fmt.Sprintf("%%%s%%", param.VulnKeyword))
	}
	if len(param.SeverityInt) > 0 {
		db = db.Where("severity_int IN  ? ", param.SeverityInt)
	}
	if len(param.Class) > 0 {
		db = db.Where("`class` IN  ? ", param.Class)
	}
	res := make([]*scanner_ci.CiVulns, 0)

	db2 := db.Session(&gorm.Session{})
	var cnt int64

	if err := db2.Select("count(unique_vuln) as cnt").Find(&cnt).Error; err != nil {
		return nil, model.SeverityHistogramInfo{}, 0, err
	}
	if param.JustReturnCount {
		return nil, model.SeverityHistogramInfo{}, cnt, nil
	}
	var cntLevel []scanner_ci.CountServerity
	err := db.Session(&gorm.Session{}).Select("count(severity) as cnt", "severity").Group("severity").Find(&cntLevel).Error
	if err != nil {
		return nil, model.SeverityHistogramInfo{}, 0, nil
	}

	var resLevels model.SeverityHistogramInfo
	for _, v := range cntLevel {
		c.addHistogram(v.Severity, int64(v.Cnt), &resLevels)
	}

	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, model.SeverityHistogramInfo{}, 0, err
	}
	for i := range res {
		res[i].Deserialize()
		res[i].Serialize()
	}
	if param.ImageID > 0 {
		mp := make(map[uint64]scanner_ci.CiVulnImage)
		for k, v := range ciVulnImages {
			mp[v.UniqueVuln] = ciVulnImages[k]
		}
		for k, v := range res {
			if vv, ok := mp[v.UniqueVuln]; ok {
				res[k].Match = vv.MatchPolicy
				res[k].White = vv.White
			}
		}
	}

	return res, resLevels, cnt, nil
}

func (c *CiDao) UpdateVuln(ctx context.Context, where string, updater map[string]interface{}, vuln *scanner_ci.CiVulns) error {
	if len(where) == 0 {
		return fmt.Errorf("no where condition")
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	var err error
	db := c.db.Get().Model(new(scanner_ci.CiVulns)).WithContext(ctx).Where(where)

	if len(updater) > 0 {
		err = db.Updates(updater).Error
	} else if vuln != nil {
		err = db.Select("*").Omit("id", "created_at").Updates(vuln).Error
	}
	return err
}

func (c *CiDao) CreateCiVuln(ctx context.Context, data []*scanner_ci.CiVulns) error {
	for i := range data {
		vuln := data[i]
		vuln.Serialize()
		vuln.CheckSum = vuln.GenCheckSum()
		vuln.UniqueVuln = vuln.GenUniqueVuln()
		data[i] = vuln
	}

	data = c.removeDuplicateVuln(data)
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1000) // 批量写入,因为有大json格式的数据，时间会久些，时间久些
	defer cancelFunc()
	for i := range data {
		vuln := data[i]
		vulns, _, _, err := c.SearchVuln(ctx, scanner_ci.SearchVulnParm{UniqueVulns: []uint64{vuln.UniqueVuln}, Fields: []string{"id", "unique_vuln", "check_sum", "class"}}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("CreateVuln")
			return err
		}
		if len(vulns) > 0 {
			if vulns[0].CheckSum == vuln.CheckSum && vulns[0].Class == vuln.Class { // 经过测试，class变动时checkSum有可能不变动
				logging.GetLogger().Info().Uint64("UniqueVuln", vuln.UniqueVuln).Uint64("CheckSum", vuln.CheckSum).Msg("CreateVuln not change")
			} else {
				if err := c.UpdateVuln(ctx, fmt.Sprintf("id = %d", vulns[0].ID), nil, vuln); err != nil {
					logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Int64("ID", vulns[0].ID).Msg("CreateVuln")
					return err
				}
			}
			continue
		}

		if err := c.db.Get().WithContext(ctx).Model(new(scanner_ci.CiVulns)).Create(vuln).Error; err != nil {
			logging.GetLogger().Err(err).Uint64("UniqueVuln", vuln.UniqueVuln).Msg("CreateVuln")
			return err
		}
	}
	return nil
}

func (c *CiDao) removeDuplicateVulnImage(data []*scanner_ci.CiVulnImage) []*scanner_ci.CiVulnImage {
	exit := map[string]struct{}{}
	ans := make([]*scanner_ci.CiVulnImage, 0, len(data))

	for i := range data {
		key := fmt.Sprintf("%d-%d", data[i].UniqueVuln, data[i].ImageID)
		if _, ok := exit[key]; !ok {
			ans = append(ans, data[i])
		}
		exit[key] = struct{}{}
	}
	return ans
}

func (c *CiDao) CreateVulnImage(ctx context.Context, imageID int64, data []*scanner_ci.CiVulnImage) error {
	for i := range data {
		data[i].ImageID = imageID
	}
	data = c.removeDuplicateVulnImage(data)
	newExit := make(map[string]*scanner_ci.CiVulnImage)
	for i := range data {
		key := fmt.Sprintf("%d_%d", data[i].ImageID, data[i].UniqueVuln)
		newExit[key] = data[i]
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()
	// 不能简单的先删除再新建，因为主建可能被用完，也不能使用ON DUPLICATE KEY UPDATE方法，因为本质上mysql还是做的先删除再新建
	// 不用事务，因为插入部分出错没有影响
	vulnImages := make([]scanner_ci.CiVulnImage, 0)
	if err := c.db.Get().Model(new(scanner_ci.CiVulnImage)).Select("id", "unique_vuln", "image_id").Where("image_id = ?", imageID).Find(&vulnImages).Error; err != nil {
		return err
	}
	dbExit := make(map[string]int64)
	createData := make([]*scanner_ci.CiVulnImage, 0)
	deleteData := make([]int64, 0)

	for i := range vulnImages {
		key := fmt.Sprintf("%d_%d", vulnImages[i].ImageID, vulnImages[i].UniqueVuln)
		dbExit[key] = vulnImages[i].ID
	}
	for key := range newExit {
		if _, ok := dbExit[key]; !ok {
			createData = append(createData, newExit[key])
		}
	}

	for key := range dbExit {
		if _, ok := newExit[key]; !ok {
			deleteData = append(deleteData, dbExit[key])
		}
	}

	if len(createData) > 0 {
		if err := c.db.Get().Model(new(scanner_ci.CiVulnImage)).CreateInBatches(createData, 100).Error; err != nil {
			return err
		}
	}
	if len(deleteData) > 0 {
		if err := c.db.Get().Model(new(scanner_ci.CiVulnImage)).Where("id IN  ? ", deleteData).Delete(&scanner_ci.CiVulnImage{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (c *CiDao) removeDuplicatePkgImage(data []*scanner_ci.CiPkgImage) []*scanner_ci.CiPkgImage {
	exit := map[string]struct{}{}
	ans := make([]*scanner_ci.CiPkgImage, 0, len(data))

	for i := range data {
		key := fmt.Sprintf("%s-%d-%d", data[i].UniquePkg, data[i].UniqueVuln, data[i].ImageID)
		if _, ok := exit[key]; !ok {
			ans = append(ans, data[i])
		}
		exit[key] = struct{}{}
	}
	return ans
}

func (c *CiDao) SearchPkgImage(ctx context.Context, limit int64, offset int64, search string, ImageID int64, dis bool) ([]scanner_ci.CiPkgImage, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.CiPkgImage{}).WithContext(ctxd)
	if search != "" {
		db = db.Where("unique_pkg like ?", fmt.Sprintf("%%%s%%", search))
	}

	db = db.Where("image_id = ?", ImageID)
	var cnt int64
	db.Count(&cnt)
	if dis {
		db = db.Distinct("unique_pkg")
	}
	if limit != 0 {
		db = db.Limit(int(limit))
	}

	if offset != 0 {
		db = db.Offset(int(offset))
	}

	res := []scanner_ci.CiPkgImage{}
	err := db.Find(&res).Error
	if err != nil {
		return res, 0, err
	}
	return res, cnt, nil
}

func (c *CiDao) CreatePkgImage(ctx context.Context, imageID int64, data []*scanner_ci.CiPkgImage) error {
	for i := range data {
		data[i].ImageID = imageID
	}
	data = c.removeDuplicatePkgImage(data)
	newExit := make(map[string]*scanner_ci.CiPkgImage)
	for i := range data {
		key := fmt.Sprintf("%s_%d_%d", data[i].UniquePkg, data[i].UniqueVuln, data[i].ImageID)
		newExit[key] = data[i]
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*100) // 大批量写入，时间会久些
	defer cancelFunc()
	// 不能简单的先删除再新建，因为主建可能被用完，也不能使用ON DUPLICATE KEY UPDATE方法，因为本质上mysql还是做的先删除再新建
	// 不用事务，因为插入部分出错没有影响
	pkgImages := make([]scanner_ci.CiPkgImage, 0)
	if err := c.db.Get().Model(new(scanner_ci.CiPkgImage)).Select("id", "unique_pkg", "unique_vuln", "image_id").Where("image_id = ?", imageID).Find(&pkgImages).Error; err != nil {
		return err
	}
	dbExit := make(map[string]int64)
	createData := make([]*scanner_ci.CiPkgImage, 0)
	deleteData := make([]int64, 0)

	for i := range pkgImages {
		key := fmt.Sprintf("%s_%d_%d", pkgImages[i].UniquePkg, pkgImages[i].UniqueVuln, pkgImages[i].ImageID)
		dbExit[key] = pkgImages[i].ID
	}
	for key := range newExit {
		if _, ok := dbExit[key]; !ok {
			createData = append(createData, newExit[key])
		}
	}

	for key := range dbExit {
		if _, ok := newExit[key]; !ok {
			deleteData = append(deleteData, dbExit[key])
		}
	}

	if len(createData) > 0 {
		if err := c.db.Get().Model(new(scanner_ci.CiPkgImage)).CreateInBatches(createData, 100).Error; err != nil {
			return err
		}
	}
	if len(deleteData) > 0 {
		if err := c.db.Get().Model(new(scanner_ci.CiPkgImage)).Where("id IN  ? ", deleteData).Delete(&scanner_ci.CiPkgImage{}).Error; err != nil {
			return err
		}
	}
	return nil
}
func (c *CiDao) CreateWebhook(ctx context.Context, web scanner_ci.Webhook) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.Webhook{}).WithContext(ctxd).Create(&web).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *CiDao) UpdateWebhook(ctx context.Context, web scanner_ci.Webhook, id int64) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.Webhook{}).Omit("created_at").WithContext(ctxd).Select("*").Where("id = ?", id).Updates(&web).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *CiDao) GetWebhook(ctx context.Context) (scanner_ci.Webhook, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	res := scanner_ci.Webhook{}
	err := c.db.Get().Model(&scanner_ci.Webhook{}).WithContext(ctxd).Find(&res).Error
	if err != nil {
		return res, err
	}
	return res, nil
}

func (c *CiDao) CreateWebhookRecord(ctx context.Context, record scanner_ci.WebhookRecord) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err := c.db.Get().Model(&scanner_ci.WebhookRecord{}).WithContext(ctxd).Create(&record).Error
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CreateWebhookRecord error")
	}
}

func (c *CiDao) GetWebhookRecords(ctx context.Context, limit int, offset int) ([]scanner_ci.WebhookRecord, int64, error) {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	db := c.db.Get().Model(&scanner_ci.WebhookRecord{}).WithContext(ctxd).Order("updated_at DESC")
	var cnt int64
	db.Count(&cnt)
	if limit != 0 {
		db = db.Limit(limit)
	}
	if offset != 0 {
		db = db.Offset(offset)
	}
	res := []scanner_ci.WebhookRecord{}
	err := db.Find(&res).Error
	if err != nil {
		return nil, 0, err
	}
	return res, cnt, nil
}
