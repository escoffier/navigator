package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var ModeToString = map[int]string{
	scanner_ci.CiPolicyResultCodeUnknown:   "unknown",
	scanner_ci.CiPolicyResultCodePass:      scanner_ci.CiActionPass,
	scanner_ci.CiPolicyResultCodeBlock:     scanner_ci.CiActionBlock,
	scanner_ci.CiPolicyResultCodeAlert:     scanner_ci.CiActionAlert,
	scanner_ci.CiPolicyResultCodeException: "abnormal",
}

var StatusToInt = map[string]int{
	"unknown":                scanner_ci.CiPolicyResultCodeUnknown,
	scanner_ci.CiActionPass:  scanner_ci.CiPolicyResultCodePass,
	scanner_ci.CiActionBlock: scanner_ci.CiPolicyResultCodeBlock,
	scanner_ci.CiActionAlert: scanner_ci.CiPolicyResultCodeAlert,
	"abnormal":               scanner_ci.CiPolicyResultCodeException,
}

type ImageManager struct {
	dal store.ScanCiInterface
}

func NewImageManager(dal store.ScanCiInterface) ImageManager {
	return ImageManager{dal: dal}
}

func ParseKind(status string) []int {
	if status == "" {
		return nil
	}
	var res []int
	statusStr := strings.Split(status, ",")
	for _, v := range statusStr {
		tmp, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("parse status error %v", v)
			continue
		}
		res = append(res, int(tmp))
	}
	return res
}

func ParseStatus(status string) []int {
	if status == "" {
		return nil
	}
	var res []int
	statusStr := strings.Split(status, ",")
	for _, v := range statusStr {
		if vv, ok := StatusToInt[v]; ok {
			res = append(res, vv)
		}
	}
	return res
}

func (im *ImageManager) GetHoursOverview(record []scanner_ci.CiScan, intervalType string, interval int) []scanner_ci.ImageOverviewNode {
	var timeParse string
	mp := make(map[string]scanner_ci.ImageOverviewNode, 0)
	switch intervalType {
	case consts.IntervalHour:
		timeParse = consts.TimeFormatWithHour
	case consts.IntervalDay:
		timeParse = consts.TimeFormatWithDay
	}
	fixedZone := time.FixedZone("CST", 8*3600)
	for k := range record {
		t := time.Unix(record[k].StartedAt/1000, 0).In(fixedZone)
		key := t.Format(timeParse)
		if v, ok := mp[key]; ok {
			v.Sum++
			if record[k].Mode == scanner_ci.CiPolicyResultCodeAlert {
				v.Alert++
			} else if record[k].Mode == scanner_ci.CiPolicyResultCodeBlock {
				v.Reject++
			}
			mp[key] = v
		} else {
			tmp := scanner_ci.ImageOverviewNode{}
			tmp.Sum = 1
			tmp.Time = key
			if record[k].Mode == scanner_ci.CiPolicyResultCodeAlert {
				tmp.Alert++
			} else if record[k].Mode == scanner_ci.CiPolicyResultCodeBlock {
				tmp.Reject++
			}
			mp[key] = tmp
		}
	}
	timeGraph := im.GenerationInterval(interval, intervalType)
	for k := range timeGraph {
		key := timeGraph[k].Format(timeParse)
		if _, ok := mp[key]; !ok {
			mp[key] = scanner_ci.ImageOverviewNode{Time: key}
		}
	}

	res := []scanner_ci.ImageOverviewNode{}
	for k := range mp {
		res = append(res, mp[k])
	}
	sort.Sort(scanner_ci.ImageOverviewNodes(res))
	return res
}

func (im *ImageManager) GetImageTop5(ctx context.Context) ([]scanner_ci.ImageRecordTop5, error) {
	return im.dal.GetRecordTop5(ctx)
}

func (im *ImageManager) GenerationInterval(interval int, intervalType string) []time.Time {
	res := make([]time.Time, 0)
	if interval < 1 {
		return res
	}
	fixedZone := time.FixedZone("CST", 8*3600)
	now := time.Now().In(fixedZone)
	switch intervalType {
	case consts.IntervalHour:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, fixedZone).Add(-time.Duration(i) * time.Hour)
			res = append(res, endAt)
		}
	case consts.IntervalDay:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, fixedZone).AddDate(0, 0, -i)
			res = append(res, endAt)
		}
	}
	return res
}

func (im *ImageManager) GetImageOverView(ctx context.Context, interval int) ([]scanner_ci.ImageOverviewNode, error) {
	var startAt time.Time
	nodes := []scanner_ci.ImageOverviewNode{}
	if interval == 24 {
		startAt = time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), time.Now().Hour(), 0, 0, 0, time.UTC).Add(-23 * time.Hour)
	} else {
		startAt = time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1*(interval-1))
	}

	res, err := im.dal.GetImageOverview(ctx, startAt.UnixMilli())
	if err != nil {
		return nodes, err
	}
	if interval == 24 {
		nodes = im.GetHoursOverview(res, consts.IntervalHour, interval)
	} else {
		nodes = im.GetHoursOverview(res, consts.IntervalDay, interval)
	}
	return nodes, nil
}

func (im *ImageManager) transImageRecord(scan scanner_ci.CiScan, InWhitelist bool) scanner_ci.ImageRecord {
	res := scanner_ci.ImageRecord{
		ImageName:      scan.ImageName,
		TaskName:       scan.PipelineName,
		ScanTime:       scan.StartedAt,
		ID:             scan.ID,
		InWhitelist:    InWhitelist,
		MatchWhitelist: scan.MatchWhitelist,
	}
	status, ok := ModeToString[scan.Mode]
	if ok {
		res.Status = status
	}
	if len(scan.SeverityHistogramJSON) != 0 {
		err := json.Unmarshal(scan.SeverityHistogramJSON, &res.SeverityHistogram)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("unmarsh SeverityHistogramJSON error")
		}
	}
	quesions := []string{}
	for _, v := range scanner_ci.GenQuestionFlag() {
		if scan.Flag&(1<<(v-1)) > 0 {
			quesions = append(quesions, fmt.Sprintf("%v", v))
		}
	}
	res.Questions = strings.Join(quesions, ",")
	return res
}

func (im *ImageManager) GetImageList(ctx context.Context, params scanner_ci.ImageParams) ([]scanner_ci.ImageRecord, int64, error) {
	filter := scanner_ci.ImageFilter{
		Image:         params.Image,
		Kind:          ParseKind(params.Kind),
		TaskName:      params.TaskName,
		Status:        ParseStatus(params.Status),
		StartTime:     params.StartTime,
		EndTime:       params.EndTime,
		Limit:         params.Limit,
		Offset:        params.Offset,
		KindAttribute: params.KindAttribute,
	}
	scans, cnt, err := im.dal.GetImageList(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	whitelist, _, err := im.dal.GetWhitelist(ctx, scanner_ci.WhitelistParams{Limit: 10000, Offset: 0, NowTime: time.Now().UnixMilli()})
	regs := []*regexp.Regexp{}
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.GetLogger().Warn().Msgf("compile failed %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}

	res := []scanner_ci.ImageRecord{}
	for k := range scans {
		flag := false
		for _, v := range regs {
			match := v.Match([]byte(scans[k].ImageName))
			if match {
				flag = true
			}
		}
		res = append(res, im.transImageRecord(scans[k], flag))
	}
	return res, cnt, nil
}

func (im *ImageManager) transSensitive(sensitive []scanner_ci.CiSensitiveImages) []scanner_ci.Sensitive {
	res := []scanner_ci.Sensitive{}
	for _, v := range sensitive {
		tmp := scanner_ci.Sensitive{}
		index := strings.LastIndex(v.File, "/")
		if index == -1 {
			tmp.Name = v.File
			tmp.Path = "/"
		} else {
			tmp.Name = v.File[index+1:]
			tmp.Path = v.File[0:index]
		}
		tmp.Match = v.MatchPolicy
		res = append(res, tmp)
	}
	return res
}

func (im *ImageManager) GetSensitives(ctx context.Context, limit int, offset int, imageID int64, search string, match bool) ([]scanner_ci.Sensitive, int64, error) {
	sensitives, cnt, err := im.dal.GetSensitiveImages(ctx, limit, offset, imageID, search, match)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get sensitive error")
		return nil, 0, err
	}
	res := im.transSensitive(sensitives)
	return res, cnt, nil
}

func (im *ImageManager) GetImageDetail(ctx context.Context, id int64) (scanner_ci.ImageRecordDetail, error) {
	record, err := im.dal.GetImageDetail(ctx, id)
	if err != nil {
		return scanner_ci.ImageRecordDetail{}, err
	}

	quesions := []string{}
	for _, v := range scanner_ci.GenQuestionFlag() {
		if record.Flag&(1<<(v-1)) > 0 {
			quesions = append(quesions, fmt.Sprintf("%v", v))
		}
	}
	res := scanner_ci.ImageRecordDetail{
		OSString:       record.OS,
		PipelineName:   record.PipelineName,
		Status:         ModeToString[record.Mode],
		Questions:      strings.Join(quesions, ","),
		ScanTime:       record.StartedAt,
		ID:             record.ID,
		ImageName:      record.ImageName,
		MatchWhitelist: record.MatchWhitelist,
	}

	_, _, cnt, err := im.dal.SearchVuln(ctx, scanner_ci.SearchVulnParm{ImageID: id, MatchPolicy: true}, &model.Filter{Limit: 1}) // 可以单独搜索优化
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get match policy error")
	}

	if cnt != 0 {
		res.VulnFlag = true
	}

	_, cnt, err = im.dal.GetSensitiveImages(ctx, 1, 0, id, "", true)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get match sensitive error")
	}

	if cnt != 0 {
		res.SensitiveFlag = true
	}

	err = json.Unmarshal(record.Remediation, &res.AllRemediation)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("unmarshal Remediation error")
	}

	if len(record.PolicySnapshot) > 0 {
		err = json.Unmarshal(record.PolicySnapshot, &res.PolicySnap)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("unmarshal policy error")
		}
	}
	if len(record.Layers) > 0 {
		err = json.Unmarshal(record.Layers, &res.Layers)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("unmarshal Layers error")
		}
	}
	return res, err
}

func (im *ImageManager) GetRecordPkgs(ctx context.Context, limit int64, offset int64, search string, imageID int64) ([]scanner_ci.PkgList, int64, error) {
	res := make([]scanner_ci.PkgList, 0)

	// 全部 Pkg
	all, cnt, err := im.dal.GetPkgs(ctx, 0, 0, imageID, search)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("SearchPkgImage error")
		return nil, 0, err
	}
	if cnt == 0 {
		return res, 0, nil
	}
	hasVulnPkg, _, err := im.dal.SearchPkgImage(ctx, 0, 0, "", imageID, false)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get pkgs error")
		return nil, 0, err
	}
	for i := range all {
		al := all[i]
		split := strings.Split(al.UniquePkg, "|")
		if len(split) != 2 || split[0] == "" || split[1] == "" {
			continue
		}
		pk := scanner_ci.PkgList{
			Pkg:        al.UniquePkg,
			PkgName:    split[0],
			PkgVersion: split[1],
			UniqueVuln: make([]uint64, 0),
			Histogram:  model.SeverityHistogramInfo{},
		}

		res = append(res, pk)
	}

	vulnU := make([]uint64, 0)
	for i := range hasVulnPkg {
		vulnU = append(vulnU, hasVulnPkg[i].UniqueVuln)
		for j := range res {
			if res[j].Pkg == hasVulnPkg[i].UniquePkg {
				res[j].UniqueVuln = append(res[j].UniqueVuln, hasVulnPkg[i].UniqueVuln)
				break
			}
		}
	}

	vulnSerMap := make(map[uint64]*scanner_ci.CiVulns)
	if len(vulnU) > 0 {
		vulns, _, _, err := im.dal.SearchVuln(ctx, scanner_ci.SearchVulnParm{UniqueVulns: vulnU}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("SearchPkgImage error")
			return nil, 0, err
		}
		for i := range vulns {
			vulnSerMap[vulns[i].UniqueVuln] = vulns[i]
		}
	}
	for i := range res {
		for j := range res[i].UniqueVuln {
			un := res[i].UniqueVuln[j]
			vul := vulnSerMap[un]
			key := fmt.Sprintf(consts.UniqueVulnFamat, vul.Name, res[i].PkgName, res[i].PkgVersion)
			uid := util.GenerateUUID64(key)
			if uid != un {
				continue
			}

			switch strings.ToUpper(vul.Severity) {
			case "CRITICAL":
				res[i].Histogram.NumCritical++
			case "HIGH":
				res[i].Histogram.NumHigh++
			case "MEDIUM":
				res[i].Histogram.NumMedium++
			case "LOW":
				res[i].Histogram.NumLow++
			case "UNKNOWN":
				res[i].Histogram.NumUnknown++
			}
		}
	}

	count := int64(len(res))
	// 程序中分页
	start := int(offset)
	end := int(offset + limit)

	if len(res) <= start {
		res = make([]scanner_ci.PkgList, 0)
	} else {
		res = res[start:util.MinInt(end, len(res))]
	}
	return res, count, nil
}

func (im *ImageManager) SearchVulns(ctx context.Context, param scanner_ci.SearchVulnParam, filter *model.Filter) ([]*scanner_ci.CiVulns, model.SeverityHistogramInfo, int64, error) {
	daoParam := scanner_ci.SearchVulnParm{
		VulnKeyword:     param.VulnKeyword,
		PkgKeyword:      param.PkgKeyword,
		TargetKeyword:   param.TargetKeyword,
		LanguageKeyword: param.LanguageKeyword,
		FrameKeyword:    param.FrameKeyword,
		UniqueVulns:     param.UniqueVulns,
		Fields:          param.Fields,
		ImageID:         param.ImageID,
		PkgName:         param.PkgName,
		PkgVersion:      param.PkgVersion,
		Sources:         nil,
		CanFixed:        param.CanFixed,
		SeverityInt:     param.SeverityInt,
		JustReturnCount: false,
		MatchPolicy:     param.MatchPolicy,
		Class:           param.Class,
	}

	vulns, levels, cnt, err := im.dal.SearchVuln(ctx, daoParam, filter)
	return vulns, levels, cnt, err
}

func (im *ImageManager) TransCvss3ToPercent(cvss string) map[string]string {
	VulnAttr := make(map[string]map[string]string, 0)
	res := make(map[string]string, 0)
	// 攻击位置难易
	VulnAttr["AV"] = map[string]string{
		"N": "100%",
		"A": "75%",
		"L": "50%",
		"P": "25%",
	}
	// 是否自动化触发
	VulnAttr["UI"] = map[string]string{
		"N": "100%",
		"R": "0%",
	}
	// 攻击复杂度
	VulnAttr["AC"] = map[string]string{
		"L": "100%",
		"H": "50%",
	}
	// 信息泄露风险
	VulnAttr["C"] = map[string]string{
		"N": "0%",
		"L": "50%",
		"H": "100%",
	}
	// 信息/系统篡改风险
	VulnAttr["A"] = map[string]string{
		"N": "0%",
		"L": "50%",
		"H": "100%",
	}
	//  权限范围扩大
	VulnAttr["Stream"] = map[string]string{
		"C": "100%",
		"U": "0%",
	}
	// 所需权限级别
	VulnAttr["PR"] = map[string]string{
		"N": "100%",
		"L": "67%",
		"H": "33%",
	}
	// 触发dos风险
	VulnAttr["I"] = map[string]string{
		"N": "0%",
		"L": "50%",
		"H": "100%",
	}

	vector := strings.Split(cvss, "/")
	for _, v := range vector {
		cvss3 := strings.Split(v, ":")
		if vv, ok := VulnAttr[cvss3[0]]; ok {
			res[cvss3[0]] = vv[cvss3[1]]
		}
	}
	return res
}
