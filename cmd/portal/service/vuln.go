package service

import (
	"context"
	"fmt"
	"regexp"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/portalI18"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannerCi "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// ModeToString CI扫描模式到字符串的映射
var ModeToString = map[int]string{
	scannerCi.CiPolicyResultCodeUnknown:   "unknown",
	scannerCi.CiPolicyResultCodePass:      scannerCi.CiActionPass,
	scannerCi.CiPolicyResultCodeBlock:     scannerCi.CiActionBlock,
	scannerCi.CiPolicyResultCodeAlert:     scannerCi.CiActionAlert,
	scannerCi.CiPolicyResultCodeException: "abnormal",
}

type VulnService interface {
	SearchCodesecVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.CodeSecVuln, int64, error)
	CodesecSummary(ctx context.Context, projectUuid string) (*model.CodesecSummary, error)
	CreateVuln(ctx context.Context, projectUuid string, vulns []*model.CodeSecVuln) error
	SearchSourceCheckVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckVuln, int64, error)
	SearchSourceCheckLicense(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckLicense, int64, error)
	SearchSourceCheckComponent(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckComponent, int64, error)
	SourceCheckSummary(ctx context.Context, projectUuid string) (*model.SourceCheckSummary, error)
	SearchCIVuln(ctx context.Context, param model.SearchVulnParam) ([]*scannerCi.CiVulns, int64, error)
	SearchCIImage(ctx context.Context, param model.SearchVulnParam) ([]*model.ImageRecord, int64, error)
}

type VulnSer struct {
	codesecDal     store.CodesecScanDal
	sourceCheckDal store.SourceCheckScanDal
	ciScanDal      store.CiScanDal
	projectDal     store.ProjectDal
	Log            *scannerUtils.LogEvent
}

func NewVulnService(codesecDal store.CodesecScanDal, sourceCheckDal store.SourceCheckScanDal, ciScanDal store.CiScanDal, projectDal store.ProjectDal) *VulnSer {
	return &VulnSer{
		codesecDal:     codesecDal,
		sourceCheckDal: sourceCheckDal,
		ciScanDal:      ciScanDal,
		projectDal:     projectDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("Vuln"),
			scannerUtils.WithSubModule("vuln")),
	}
}

func (s *VulnSer) SearchCodesecVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.CodeSecVuln, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	vulns, total, err := s.codesecDal.SearchVuln(ctx, param)
	if err != nil {
		s.Log.Err(err).
			Str("projectUuid", param.ProjectUuid).
			Interface("param", param).
			Msg("Failed to get CodeSecVuln list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}

	return vulns, total, nil
}

func (s *VulnSer) CodesecSummary(ctx context.Context, projectUuid string) (*model.CodesecSummary, error) {
	if projectUuid == "" {
		s.Log.Error().Msg("project_uuid is required")
		return nil, portalI18.ProjectUuidRequired(fmt.Errorf("project_uuid is required"))
	}

	s.Log.Info().Str("projectUuid", projectUuid).Msg("Getting CodesecSummary")
	pros, _, err := s.projectDal.SearchProject(ctx, model.SearchProjectParam{ProjectUuid: projectUuid})
	if err != nil {
		s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get project")
		return nil, portalI18.SearchProjectFail(err)
	}
	if len(pros) == 0 {
		return nil, portalI18.ProjectNotExist(fmt.Errorf("project not found"))
	}
	// Query scan results, get the latest record by project_uuid
	param := model.SearchScanResultParam{ProjectUuid: projectUuid}
	result, err := s.codesecDal.GetSummary(ctx, param)
	if err != nil {
		s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get CodesecSummary")
		// 最新要求，没有结果时返回空值，不报错
		result = &model.CodesecSummary{}
	}

	result.ScanStatus = pros[0].CodesecScanStatus
	result.ScanMsg = pros[0].CodesecScanMsg

	return result, nil
}

// SearchSourceCheckVuln searches SourceCheck vulnerability list
func (s *VulnSer) SearchSourceCheckVuln(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckVuln, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	vulns, total, err := s.sourceCheckDal.SearchVuln(ctx, param)
	if err != nil {
		s.Log.Err(err).Str("projectUuid", param.ProjectUuid).Interface("param", param).
			Msg("Failed to get SourceCheckVuln list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}

	return vulns, total, nil
}

// SearchSourceCheckLicense searches SourceCheck license list
func (s *VulnSer) SearchSourceCheckLicense(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckLicense, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	licenses, total, err := s.sourceCheckDal.SearchLicense(ctx, param)
	if err != nil {
		s.Log.Err(err).
			Str("projectUuid", param.ProjectUuid).
			Interface("param", param).
			Msg("Failed to get SourceCheckLicense list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}
	s.Log.Info().Str("projectUuid", param.ProjectUuid).Int64("total", total).Msg("Successfully retrieved SourceCheckLicense list")
	return licenses, total, nil
}

// SearchSourceCheckComponent searches SourceCheck component list
func (s *VulnSer) SearchSourceCheckComponent(ctx context.Context, param model.SearchVulnParam) ([]*model.SourceCheckComponent, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	components, total, err := s.sourceCheckDal.SearchComponent(ctx, param)
	if err != nil {
		s.Log.Err(err).
			Str("projectUuid", param.ProjectUuid).
			Interface("param", param).
			Msg("Failed to get SourceCheckComponent list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}
	s.Log.Info().Str("projectUuid", param.ProjectUuid).Int64("total", total).Msg("Successfully retrieved SourceCheckComponent list")
	return components, total, nil
}

func (s *VulnSer) SourceCheckSummary(ctx context.Context, projectUuid string) (*model.SourceCheckSummary, error) {
	if projectUuid == "" {
		return nil, portalI18.ProjectUuidRequired(fmt.Errorf("project_uuid is required"))
	}

	pros, _, err := s.projectDal.SearchProject(ctx, model.SearchProjectParam{ProjectUuid: projectUuid})
	if err != nil {
		s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get project")
		return nil, portalI18.SearchProjectFail(err)
	}
	if len(pros) == 0 {
		return nil, portalI18.ProjectNotExist(fmt.Errorf("project not found"))
	}

	param := model.SearchScanResultParam{ProjectUuid: projectUuid}
	result, err := s.sourceCheckDal.GetSummary(ctx, param)
	if err != nil {
		s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get SourceCheck summary")
		// 最新要求，返回空，不报错
		result = &model.SourceCheckSummary{}
	}

	result.ScanStatus = pros[0].SourceCheckScanStatus
	result.ScanMsg = pros[0].SourceCheckScanMsg

	return result, nil
}

func (s *VulnSer) CreateVuln(ctx context.Context, projectUuid string, vulns []*model.CodeSecVuln) error {
	if projectUuid == "" {
		s.Log.Error().Msg("project_uuid is required")
		return portalI18.ProjectUuidRequired(fmt.Errorf("project_uuid is required"))
	}

	s.Log.Info().
		Str("projectUuid", projectUuid).
		Int("vulnCount", len(vulns)).
		Msg("Creating CodeSecVuln records")

	err := s.codesecDal.CreateVuln(ctx, projectUuid, vulns)
	if err != nil {
		s.Log.Err(err).
			Str("projectUuid", projectUuid).
			Int("vulnCount", len(vulns)).
			Msg("Failed to create CodeSecVuln records")
		return portalI18.CreateVulnFail(err)
	}

	s.Log.Info().
		Str("projectUuid", projectUuid).
		Int("vulnCount", len(vulns)).
		Msg("Successfully created CodeSecVuln records")

	return nil
}

// SearchCIVuln 查询CI漏洞列表
func (s *VulnSer) SearchCIVuln(ctx context.Context, param model.SearchVulnParam) ([]*scannerCi.CiVulns, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	// 转换参数
	ciParam := store.SearchCiVulnParam{
		ProjectUuid: param.ProjectUuid,
		Filter:      param.Filter,
	}

	vulns, total, err := s.ciScanDal.SearchCiVuln(ctx, ciParam)
	if err != nil {
		s.Log.Err(err).Str("project", param.ProjectUuid).Msg("Failed to get CiVuln list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}

	s.Log.Info().Str("projectUuid", param.ProjectUuid).Int64("total", total).Msg("Successfully retrieved CiVuln list")

	return vulns, total, nil
}

// SearchCIImage 查询CI镜像列表
func (s *VulnSer) SearchCIImage(ctx context.Context, param model.SearchVulnParam) ([]*model.ImageRecord, int64, error) {
	if err := param.Check(); err != nil {
		return nil, 0, err
	}

	// 转换参数
	ciParam := store.SearchCiScanParam{
		ProjectUuid: param.ProjectUuid,
		Filter:      param.Filter,
	}

	ciScans, total, err := s.ciScanDal.SearchCiScan(ctx, ciParam)
	if err != nil {
		s.Log.Err(err).Str("projectUuid", param.ProjectUuid).Interface("param", param).Msg("Failed to get CiImage list")
		return nil, 0, portalI18.GetVulnListFail(err)
	}

	// 获取白名单
	whitelist, err := s.ciScanDal.GetWhitelist(ctx)
	if err != nil {
		s.Log.Err(err).Msg("Failed to get whitelist")
		whitelist = make([]scannerCi.CiWhitelist, 0) // 如果获取失败，使用空白名单
	}

	// 编译白名单正则表达式
	regs := make([]*regexp.Regexp, 0, len(whitelist))
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.GetLogger().Warn().Msgf("compile whitelist pattern failed: %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}

	// 转换为 model.ImageRecord 格式并检查白名单
	res := make([]*model.ImageRecord, len(ciScans))
	for i := range ciScans {
		inWhitelist := false
		for _, reg := range regs {
			if reg.Match([]byte(ciScans[i].ImageName)) {
				inWhitelist = true
				break
			}
		}
		record := transImageRecord(ciScans[i], inWhitelist)
		res[i] = &record
	}

	s.Log.Info().Str("projectUuid", param.ProjectUuid).Int64("total", total).Msg("Successfully retrieved CiImage list")

	return res, total, nil
}

func transImageRecord(scan *scannerCi.CiScan, InWhitelist bool) model.ImageRecord {
	res := model.ImageRecord{
		ImageName:      scan.ImageName,
		TaskName:       scan.PipelineName,
		ScanTime:       scan.StartedAt,
		ID:             scan.ID,
		InWhitelist:    InWhitelist,
		MatchWhitelist: scan.MatchWhitelist,
		ProjectUuid:    scan.ProjectUuid,
	}

	// 设置状态
	status, ok := ModeToString[scan.Mode]
	if ok {
		res.Status = status
	}

	// 处理漏洞统计信息 - 直接使用 CiScan 的 SeverityHistogram 字段
	res.VulnStatic = imagesec.VulnSeverityStatic{
		Critical: scan.SeverityHistogram.NumCritical,
		High:     scan.SeverityHistogram.NumHigh,
		Medium:   scan.SeverityHistogram.NumMedium,
		Low:      scan.SeverityHistogram.NumLow,
		Unknown:  scan.SeverityHistogram.NumUnknown,
	}

	// 处理安全问题标志
	var questions []string
	if util.ExistBit1(scan.Flag, scannerCi.VulnQuestion-1) {
		questions = append(questions, "vuln")
	}
	if util.ExistBit1(scan.Flag, scannerCi.SenSitiveQuestion-1) {
		questions = append(questions, "sensitive")
	}
	res.Questions = questions

	return res
}
