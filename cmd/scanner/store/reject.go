package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

// CreateRejectRecord 创建记录，
func (s *ScannerOrm) CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	// if data.Library == "" {
	// 	return nil, errors.New("no library")
	// }
	if data.FullRepoName == "" {
		return nil, errors.New("no full repo name")
	}
	// if data.Tag == "" {
	// 	return nil, errors.New("no tag")
	// }
	if len(data.RejectReason) <= 0 && len(data.RejectReasonJson) <= 0 {
		return nil, errors.New("no reject reason")
	}
	if data.RejectDetail == "" {
		return nil, errors.New("no reject detail")
	}
	if len(data.RejectReasonJson) == 0 && len(data.RejectReason) > 0 {
		reasonMap := make(map[int64]int64)
		reasons := make([]int64, 0)

		for i := range data.RejectReason {
			if reasonMap[data.RejectReason[i]] < 1 {
				reasons = append(reasons, data.RejectReason[i])
				reasonMap[data.RejectReason[i]]++
			}
		}
		reasonsDuplication := make(map[string]string)
		for _, r := range reasons {
			reasonsDuplication[strconv.Itoa(int(r))] = strconv.Itoa(int(r))
		}
		if bys, err := json.Marshal(reasonsDuplication); err == nil {
			data.RejectReasonJson = bys
		}
	}

	err := s.psql.Get().WithContext(ctx).Create(&data).Debug().Error
	return &data, err
}

func (s *ScannerOrm) OverviewForInterval(ctx context.Context, interval int, intervalType string) ([]IntervalDateGroup, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	if interval < 1 {
		return nil, errors.New("interval must more than 1")
	}

	var (
		startAt   time.Time
		sql       string
		timeParse string
	)
	now := time.Now().UTC()
	switch intervalType {
	case consts.IntervalHour:
		startAt = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-time.Duration(interval-1) * time.Hour).UTC()
		sql = fmt.Sprintf("select to_char(reject_at, 'YYYY-MM-DD HH24') as interval_date,count(id)  as  cnt from  %s  where reject_at <= ?  AND reject_at >= ?  group by interval_date  order by interval_date ;", new(model.RejectRecord).TableName())
		timeParse = consts.TimeFormatWithHour

	case consts.IntervalDay:
		startAt = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(interval - 1)).UTC()
		sql = fmt.Sprintf("select to_char(reject_at, 'YYYY-MM-DD') as interval_date,count(id)  as  cnt from  %s  where reject_at <= ?  AND reject_at >= ?  group by interval_date  order by interval_date ;", new(model.RejectRecord).TableName())
		timeParse = consts.TimeFormatWithDay
	}

	logging.GetLogger().WithContext(ctx).Infof("OverviewForInterval sql:%s", sql)
	res := make([]IntervalDateGroup, 0)
	err := s.psql.Get().Debug().Raw(sql, now, startAt).Scan(&res).Error
	if err != nil {
		return res, err
	}
	for i := range res {
		if tm, err := time.Parse(timeParse, res[i].IntervalDate); err == nil {
			res[i].IntervalDateTime = tm
		}
	}
	sort.Sort(IntervalDateGroups(res))
	return res, err
}

func (s *ScannerOrm) OverviewReasonTopN(ctx context.Context, param OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	res := make([]model.RejectReasonStatistic, 0)
	// 取全表数据
	records, _, err := s.SearchRejectRecord(ctx, SearchRejectRecordParam{
		Fields: []string{"reject_reason_json"},
	}, &model.Filter{PageSize: math.MaxInt64})
	if err != nil {
		return res, err
	}
	// 统计
	statistics := make(map[int64]int64)
	for _, rec := range records {
		for _, re := range rec.RejectReason {
			statistics[re]++
		}
	}
	// 生成结果
	for ke, va := range statistics {
		res = append(res, model.RejectReasonStatistic{
			RejectReason: ke,
			Count:        va,
		})
	}
	// 排序
	sort.Sort(model.RejectReasonStatistics(res))
	// 生成中文
	reasonCNMap := map[int64]string{
		model.RejectReasonScore:             model.RejectReasonScoreZH,
		model.RejectReasonHasSensitiveFile:  model.RejectReasonHasSensitiveFileZH,
		model.RejectReasonHasMalicious:      model.RejectReasonHasMaliciousZH,
		model.RejectReasonHasCustomizeVuln:  model.RejectReasonHasCustomizeVulnZH,
		model.RejectReasonHasNegligibleVuln: model.RejectReasonHasNegligibleVulnZH,
		model.RejectReasonHasUnknownVuln:    model.RejectReasonHasUnknownVulnZH,
		model.RejectReasonHasLowVuln:        model.RejectReasonHasLowVulnZH,
		model.RejectReasonHasMediumVuln:     model.RejectReasonHasMediumVulnZH,
		model.RejectReasonHasHighVuln:       model.RejectReasonHasHighVulnZH,
		model.RejectReasonHasCriticalVuln:   model.RejectReasonHasCriticalVulnZH,
		model.RejectNoLibrary:               model.RejectNoLibraryZH,
		model.RejectScanFailure:             model.RejectScanFailureZH,
		model.RejectScanNotScanned:          model.RejectScanScanNotScannedZH,
	}
	reasonENMap := map[int64]string{
		model.RejectReasonScore:             model.RejectReasonScoreEN,
		model.RejectReasonHasSensitiveFile:  model.RejectReasonHasSensitiveFileEN,
		model.RejectReasonHasMalicious:      model.RejectReasonHasMaliciousEN,
		model.RejectReasonHasCustomizeVuln:  model.RejectReasonHasCustomizeVulnEN,
		model.RejectReasonHasNegligibleVuln: model.RejectReasonHasNegligibleVulnEN,
		model.RejectReasonHasUnknownVuln:    model.RejectReasonHasUnknownVulnEN,
		model.RejectReasonHasLowVuln:        model.RejectReasonHasLowVulnEN,
		model.RejectReasonHasMediumVuln:     model.RejectReasonHasMediumVulnEN,
		model.RejectReasonHasHighVuln:       model.RejectReasonHasHighVulnEN,
		model.RejectReasonHasCriticalVuln:   model.RejectReasonHasCriticalVulnEN,
		model.RejectNoLibrary:               model.RejectNoLibraryEN,
		model.RejectScanFailure:             model.RejectScanFailureEN,
		model.RejectScanNotScanned:          model.RejectScanScanNotScannedEN,
	}
	for i := range res {
		res[i].RejectReasonStringCN = reasonCNMap[res[i].RejectReason]
		res[i].RejectReasonStringEN = reasonENMap[res[i].RejectReason]
	}
	// 取结果
	if len(res) > param.TopN {
		return res[:param.TopN], nil
	}
	return res, err
}

func (s *ScannerOrm) SearchRejectRecord(ctx context.Context, param SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.RejectRecord)).WithContext(ctx).Debug()
	if !param.StartAt.IsZero() {
		db = db.Where("reject_at >= ?", param.StartAt) // fixme
	}
	if !param.EndAt.IsZero() {
		db = db.Where("reject_at <= ?", param.EndAt) // fixme
	}
	if param.Search != "" {
		db = db.Where("full_repo_name LIKE ? OR tag LIKE ?  ", fmt.Sprintf("%%%s%%", param.Search), fmt.Sprintf("%%%s%%", param.Search))
	}
	if len(param.RejectReasons) > 0 {
		sqls := make([]string, 0)
		for _, rej := range param.RejectReasons {
			sqls = append(sqls, fmt.Sprintf("reject_reason_json ->>'%s' ::text = '%s'", strconv.Itoa(int(rej)), strconv.Itoa(int(rej))))
		}
		db = db.Where(strings.Join(sqls, " OR "))
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}

	if len(param.Libraries) > 0 {
		if len(param.Libraries) == 1 {
			db = db.Where("library = ? ", param.Libraries[0])
		} else {
			db = db.Where("library IN ? ", param.Libraries)
		}
	}
	if param.Library != "" {
		db = db.Where("library = ? ", param.Library)
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ? ", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tag = ? ", param.Tag)
	}

	// 计算count
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.RejectRecord, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	// 序列化数据
	// 因为要对这个字段做查询，所以数据库只能存{"1":"1"}的方式
	for i := range res {
		re := make([]int64, 0)
		reasonMap := make(map[string]string)
		if len(res[i].RejectReasonJson) > 0 {
			if err := json.Unmarshal(res[i].RejectReasonJson, &reasonMap); err != nil {
				logging.GetLogger().WithContext(ctx).Errorf(err, "SearchRejectRecord json Unmarshal error")
			}
		}
		for k := range reasonMap {
			if i, err := strconv.ParseInt(k, 10, 64); err == nil {
				re = append(re, i)
			}
		}
		res[i].RejectReason = re
	}
	return res, cnt, nil
}

func (s *ScannerOrm) CreateImageWhitelist(ctx context.Context, data model.ImageWhitelist) (*model.ImageWhitelist, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	if data.FullRepoName == "" {
		return nil, errors.New("no full repo name")
	}
	if data.Tag == "" {
		return nil, errors.New("no tag")
	}
	if data.Library == "" {
		return nil, errors.New("no library")
	}
	err := s.psql.Get().WithContext(ctx).Create(&data).Error
	return &data, err
}

func (s *ScannerOrm) SearchImageWhitelist(ctx context.Context, param SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	db := s.psql.Get().WithContext(ctx).Model(new(model.ImageWhitelist))
	if param.SearchWord != "" {
		db = db.Where("full_repo_name LIKE ? OR tag LIKE ?  ", fmt.Sprintf("%%%s%%", param.SearchWord), fmt.Sprintf("%%%s%%", param.SearchWord))
	}
	if param.FullRepoName != "" {
		db = db.Where("full_repo_name = ?", param.FullRepoName)
	}
	if param.Tag != "" {
		db = db.Where("tag = ?", param.Tag)
	}
	if param.Library != "" {
		db = db.Where("library = ?", param.Library)
	}
	if param.Digest != "" {
		db = db.Where("digest = ?", param.Digest)
	}

	// 计算count
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)
	res := make([]model.ImageWhitelist, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, cnt, err
	}
	return res, cnt, nil
}

func (s *ScannerOrm) DeleteImageWhitelist(ctx context.Context, param DeleteImageWhitelistParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	err := s.psql.Get().WithContext(ctx).Where("id = ?", param.WhiteId).Delete(&model.ImageWhitelist{}).Error
	return err
}
