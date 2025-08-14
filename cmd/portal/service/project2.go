package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/codesec"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/sourceCheck"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
)

func (s *projectService) scanProjectByType(ctx context.Context, project *model.Project, scanType string) {
	s.Log.Info().Str("project", project.LogStr()).
		Str("scanType", scanType).
		Msg("Starting scan project by type")
	switch scanType {
	case consts.ModelCodesec:
		_ = s.startCodesecScan(ctx, project)
	case consts.ModelSourceCheck:
		_ = s.startSourceCheckScan(ctx, project)

	default:
		s.Log.Error().
			Str("projectUuid", project.Uuid).
			Str("scanType", scanType).
			Msg("Unsupported scan type")
		return
	}
}

func (s *projectService) startCodesecScan(ctx context.Context, project *model.Project) error {
	// 检查扫描状态，如果正在扫描中就直接跳过
	if project.CodesecScanStatus == consts.ScanStatusScanning {
		s.Log.Info().Str("projectUuid", project.Uuid).Msg("CodeSec scan is in progress, skipping")
		return nil
	}

	// 检查必要的配置
	if project.CodesecUUID == "" || project.CodesecAppID == "" {
		return fmt.Errorf("项目缺少CodeSec配置信息")
	}
	if project.CodesecAk == "" || project.CodesecSk == "" {
		return fmt.Errorf("项目缺少CodeSec认证信息")
	}

	// 创建扫描服务
	srv := codesec.NewScanAPISer(s.codesecURL, project.CodesecAk, project.CodesecSk, s.codesecScanDal, s.projectDal)

	// 调用CodeSec的扫描接口
	s.Log.Info().Str("projectUuid", project.CodesecUUID).Str("appId", project.CodesecAppID).Msg("Starting to call CodeSec scan interface")
	_, err := srv.ScanSubProject(project.CodesecUUID, project.CodesecAppID)
	if err != nil {

		// 更新扫描状态为失败
		updater := scanFailedUpdater(consts.ModelCodesec, err)
		_ = s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
			ID:      project.ID,
			Updater: updater,
		})
		return fmt.Errorf("调用CodeSec扫描接口失败: %v", err)
	}

	// 更新扫描状态为扫描中
	updater := scanStarUpdater(consts.ModelCodesec)
	if err := s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
		ID:      project.ID,
		Updater: updater,
	}); err != nil {
		s.Log.Err(err).Int64("projectID", project.ID).Interface("updater", updater).Msg("Failed to update CodeSec scan status")
		return fmt.Errorf("更新CodeSec扫描状态失败: %v", err)
	}

	s.Log.Info().Str("project", project.LogStr()).Msg("CodeSec start scan success")

	go func() {
		s.MonitorChan <- MonitorData{
			ProjectID:   project.ID,
			ScanType:    consts.ModelCodesec,
			ExecutionAt: time.Now().Add(time.Second * 30).Unix(),
		}
	}()

	return nil
}

func (s *projectService) startSourceCheckScan(ctx context.Context, project *model.Project) error {
	// 检查扫描状态，如果正在扫描中就直接跳过
	if project.SourceCheckScanStatus == consts.ScanStatusScanning {
		s.Log.Info().Str("projectUuid", project.Uuid).Msg("SourceCheck scan is in progress, skipping")
		return nil
	}

	// 检查必要的配置
	if project.SourceCheckUUID == "" {
		return fmt.Errorf("项目缺少SourceCheck配置信息")
	}
	if project.SourceCheckToken == "" {
		return fmt.Errorf("项目缺少SourceCheck认证信息")
	}

	// 创建SourceCheck API客户端
	api := sourceCheck.NewApi(
		sourceCheck.WithBaseURL(s.sourceCheckRUL),
		sourceCheck.WithAuthorization(project.SourceCheckToken),
	)

	// 调用SourceCheck的扫描接口
	s.Log.Info().Str("sourceCheckUuid", project.SourceCheckUUID).Msg("Starting to call SourceCheck scan interface")
	scanResp, err := api.StartScan(ctx, sourceCheck.StartScanRequest{
		AppUuid:     project.SourceCheckUUID,
		CallBackUrl: "http://127.0.0.1:10800",
	})
	if err != nil {
		// 更新扫描状态为失败
		updater := scanFailedUpdater(consts.ModelSourceCheck, err)
		_ = s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
			ID:      project.ID,
			Updater: updater,
		})
		return fmt.Errorf("调用SourceCheck扫描接口失败: %v", err)
	}

	// 更新扫描状态为扫描中，并保存检测编号
	updater := scanStarUpdater(consts.ModelSourceCheck)
	updater["source_check_check_no"] = scanResp.Data.CheckNo
	if err := s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
		ID:      project.ID,
		Updater: updater,
	}); err != nil {
		s.Log.Err(err).Int64("projectID", project.ID).Interface("updater", updater).Msg("Failed to update SourceCheck scan status")
		return fmt.Errorf("更新SourceCheck扫描状态失败: %v", err)
	}

	s.Log.Info().Str("project", project.LogStr()).Msg("SourceCheck scan started successfully")
	go func() {
		s.MonitorChan <- MonitorData{
			ProjectID:   project.ID,
			ScanType:    consts.ModelSourceCheck,
			ExecutionAt: time.Now().Add(time.Second * 30).Unix(),
		}
	}()
	return nil
}

func codeSecGitType(t string) int {
	switch t {
	case model.GitTypeGitlabV3, model.GitTypeGitlabV4:
		return 1
	case model.GitTypeGitHub:
		return 2
	case model.GitTypeGitee:
		return 3
	}
	return 1
}

func GetGitlabVersion(s string) string {
	switch s {
	case model.GitTypeGitlabV3:
		return consts.GitlabApiVersionV3
	}
	return consts.GitlabApiVersionV4
}

func GetGitType(s string) string {
	switch s {
	case model.GitTypeGitlabV3, model.GitTypeGitlabV4:
		return model.GitTypeGitlab
	case model.GitTypeGitHub:
		return model.GitTypeGitHub
	case model.GitTypeGitee:
		return model.GitTypeGitee
	}
	return model.GitTypeGitlab
}

func GetProtocol(s string) string {
	if strings.Contains(s, "https") {
		return "HTTPS"
	}
	return "SSH"
}

func (s *projectService) updateProjectCodesec(ctx context.Context, proID int64) error {
	pros, _, err := s.projectDal.SearchProject(ctx, model.SearchProjectParam{ID: proID})
	if err != nil {
		s.Log.Err(err).Int64("projectID", proID).Msg("Search project failed")
		return err
	}

	if len(pros) == 0 {
		s.Log.Info().Int64("projectID", proID).Msg("Project not found")
		return fmt.Errorf("project not found")
	}

	pro := pros[0]

	srv := codesec.NewScanAPISer(s.codesecURL, pro.CodesecAk, pro.CodesecSk, s.codesecScanDal, s.projectDal)
	res1, err := srv.GetScanProgress(pro.CodesecUUID, pro.CodesecAppID)
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get scan progress failed")
		// 有超时兜底，所以只记录，不返回error
		return nil
	}

	if strings.Contains(res1.Msg, consts.ScanFailedMsg) || strings.Contains(res1.Msg, consts.ScanTerMsg) {
		updater := scanFailedUpdater(consts.ModelCodesec, fmt.Errorf(res1.Msg))
		err = s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
			ID:      pro.ID,
			Updater: updater,
		})
		return err
	}
	if strings.Contains(res1.Msg, consts.ScanSuccessMsg) || strings.Contains(res1.Msg, consts.ScanFinishMsg) {
		if err := s.getCodesecAllVulnAndSave(ctx, pro); err != nil {
			s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get all vulnerabilities and save to database failed")
			return err
		}
		return nil
	}
	// 其他就认为是扫描中
	go func() {
		s.MonitorChan <- MonitorData{ProjectID: pro.ID, ScanType: consts.ModelCodesec, ExecutionAt: time.Now().Add(time.Minute * 2).Unix()}
	}()
	return nil
}

func (s *projectService) updateProjectSourceCheck(ctx context.Context, proID int64) error {
	pros, _, err := s.projectDal.SearchProject(ctx, model.SearchProjectParam{ID: proID})
	if err != nil {
		s.Log.Err(err).Int64("projectID", proID).Msg("Search project failed")
		return err
	}

	if len(pros) == 0 {
		s.Log.Info().Int64("projectID", proID).Msg("Project not found")
		return nil
	}

	pro := pros[0]

	api := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(pro.SourceCheckToken))

	resp, err := api.GetScanProgress(ctx, pro.SourceCheckCheckNo)
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get scan progress failed")
		// 有超时兜底，所以只记录，不返回error
		return nil
	}
	if resp.ScanStatus() == consts.ScanStatusFailed {
		updater := scanFailedUpdater(consts.ModelSourceCheck, fmt.Errorf(consts.ScanFailedCantGetResult))
		_ = s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{
			ID:      pro.ID,
			Updater: updater,
		})
		return nil
	}
	if resp.ScanStatus() == consts.ScanStatusScanning {
		go func() {
			s.MonitorChan <- MonitorData{
				ProjectID:   pro.ID,
				ScanType:    consts.ModelSourceCheck,
				ExecutionAt: time.Now().Add(time.Second * 30).Unix(),
			}
		}()
		return nil
	}

	errs := make([]error, 0)
	// 获取所有的漏洞
	vulns, err := api.GetAllVuln(ctx, sourceCheck.VulnerabilityListRequest{AppUuid: pro.SourceCheckUUID})
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get all vuln failed")
		errs = append(errs, err)
	}
	// 获取所有的组件
	components, err := api.GetAllComponent(ctx, sourceCheck.ComponentListRequest{AppUuid: pro.SourceCheckUUID})
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get all components failed")
		errs = append(errs, err)
	}
	// 获取所有的许可证
	licenses, err := api.GetAllLicense(ctx, sourceCheck.LicenseListRequest{AppUuid: pro.SourceCheckUUID})
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get all licenses failed")
		errs = append(errs, err)
	}
	// 保存漏洞
	if err := s.sourceCheckDal.CreateVuln(ctx, pro.Uuid, vulns); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Create vuln failed")
		errs = append(errs, err)
	}
	// 保存组件
	if err := s.sourceCheckDal.CreateComponent(ctx, pro.Uuid, components); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Create component failed")
		errs = append(errs, err)
	}
	// 保存许可证
	if err := s.sourceCheckDal.CreateLicense(ctx, pro.Uuid, licenses); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Create license failed")
		errs = append(errs, err)
	}
	// 更新项目的最高风险并统计各风险等级的漏洞数量
	risk, sev := int64(0), ""
	for i := range vulns {
		vulns[i].Serialize()
	}
	var highRiskCount, mediumRiskCount, lowRiskCount, criticalRiskCount int64

	for _, vu := range vulns {
		vu.Serialize()
		// 更新最高风险
		if vu.SeverityInt > risk {
			risk = vu.SeverityInt
			sev = vu.Severity
		}
		// 统计各风险等级数量
		switch vu.Severity {
		case model.SeverityCritical:
			criticalRiskCount++
		case model.SeverityHigh:
			highRiskCount++
		case model.SeverityMedium:
			mediumRiskCount++
		case model.SeverityLow:
			lowRiskCount++
		}
	}

	// 创建并保存SourceCheckSummary
	summary := &model.SourceCheckSummary{
		ProjectUuid:       pro.Uuid,
		SourceCheckUuid:   pro.SourceCheckUUID,
		CheckNo:           pro.SourceCheckCheckNo,
		VulnCount:         int64(len(vulns)),
		ComponentCount:    int64(len(components)),
		LicenseCount:      int64(len(licenses)),
		HighRiskCount:     highRiskCount,
		MediumRiskCount:   mediumRiskCount,
		LowRiskCount:      lowRiskCount,
		CriticalRiskCount: criticalRiskCount,
		ScanStatus:        consts.ScanStatusSuccess,
		ScanStartTime:     pro.SourceCheckScanStartAt,
		ScanEndTime:       time.Now().UnixMilli(),
	}

	// 计算扫描持续时间（毫秒）
	if summary.ScanEndTime > summary.ScanStartTime {
		summary.ScanDuration = summary.ScanEndTime - summary.ScanStartTime
	}

	// 保存摘要数据（CreateSummary方法内部会调用Serialize来生成UniqueID）
	if err := s.sourceCheckDal.CreateSummary(ctx, summary); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Int64("projectID", pro.ID).Interface("summary", summary).Msg("Create source check summary failed")
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to update project: %v", errs)
	}
	updater := scanSuccessUpdater(consts.ModelSourceCheck, sev, risk)

	// 计算并更新项目整体风险级别
	// 需要获取当前的 Codesec 风险级别来计算整体风险
	currentCodesecSeverity := pro.CodesecHighSeverity
	projectRiskLevel := calculateProjectRiskLevel(currentCodesecSeverity, risk)
	updater["risk_level"] = projectRiskLevel

	if err := s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{ID: pro.ID, Updater: updater}); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Interface("updater", updater).Msg("Update project failed")
		return err
	}

	s.Log.Info().Str("project", pro.LogStr()).Interface("summary", summary).Str("riskLevel", projectRiskLevel).Msg("Create source check summary success")

	return nil
}

// getCodesecAllVulnAndSave 获取所有漏洞并保存到数据库（先删除再插入）
func (s *projectService) getCodesecAllVulnAndSave(ctx context.Context, pro *model.Project) error {
	// 1. 获取所有漏洞数据
	srv := codesec.NewScanAPISer(s.codesecURL, pro.CodesecAk, pro.CodesecSk, s.codesecScanDal, s.projectDal)
	vuln, scr, err := srv.GetAllVuln(pro.CodesecUUID, pro.CodesecAppID)
	if err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Get all vulnerabilities failed")
		return fmt.Errorf("failed to get all vulnerabilities: %v", err)
	}

	for i := range vuln {
		vuln[i].Serialize()
	}

	if err := s.codesecScanDal.CreateVuln(ctx, pro.Uuid, vuln); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Create vulnerabilities failed")
		return fmt.Errorf("failed to save vulnerabilities to database: %v", err)
	}

	scr.ProjectUuid = pro.Uuid
	if err := s.codesecScanDal.CreateSummary(ctx, scr); err != nil {
		s.Log.Err(err).Str("project", pro.LogStr()).Msg("Create summary failed")
		return err
	}
	// 更新项目的最高风险
	risk, sev := int64(0), ""
	for _, vu := range vuln {
		if vu.SeverityInt > risk {
			risk = vu.SeverityInt
			sev = vu.Severity
		}
	}

	updater := scanSuccessUpdater(consts.ModelCodesec, sev, risk)

	// 计算并更新项目整体风险级别
	// 需要获取当前的 SourceCheck 风险级别来计算整体风险
	currentSourceCheckSeverity := pro.SourceCheckHighSeverity
	projectRiskLevel := calculateProjectRiskLevel(risk, currentSourceCheckSeverity)
	updater["risk_level"] = projectRiskLevel

	if err := s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{ID: pro.ID, Updater: updater}); err != nil {
		s.Log.Err(err).Int64("projectID", pro.ID).Interface("updater", updater).Msg("Update project failed")
		return err
	}
	s.Log.Info().Str("project", pro.LogStr()).Str("riskLevel", projectRiskLevel).Msg("Update codesec project success")
	return nil
}

type MonitorData struct {
	ProjectID   int64
	ScanType    string
	Err         error
	ExecutionAt int64 // 执行时间
}

func (s *projectService) updateProjectScanError(ctx context.Context, data MonitorData) error {
	updater := scanFailedUpdater(data.ScanType, data.Err)
	err := s.projectDal.UpdateProject(ctx, model.UpdateProjectParam{ID: data.ProjectID, Updater: updater})
	if err != nil {
		s.Log.Err(err).Int64("projectID", data.ProjectID).Interface("updater", updater).Msg("Update project failed")
		return err
	}
	return nil
}

func scanFailedUpdater(scanType string, err error) map[string]interface{} {
	now := time.Now().UnixMilli()
	updater := map[string]interface{}{}

	if scanType == consts.ModelCodesec {
		updater["codesec_scan_status"] = consts.ScanStatusFailed
		updater["codesec_scan_end_at"] = now
		updater["codesec_scan_msg"] = fmt.Sprintf("扫描失败: %s", err.Error())
		// 注意：扫描失败时不重置风险级别相关字段，保持之前的扫描结果
	}
	if scanType == consts.ModelSourceCheck {
		updater["source_check_scan_status"] = consts.ScanStatusFailed
		updater["source_check_scan_end_at"] = now
		updater["source_check_scan_msg"] = fmt.Sprintf("扫描失败: %s", err.Error())
		// 注意：扫描失败时不重置风险级别相关字段，保持之前的扫描结果
	}
	return updater
}

func scanSuccessUpdater(scanType string, highRisk string, highSeverity int64) map[string]interface{} {
	now := time.Now().UnixMilli()
	updater := map[string]interface{}{}

	if scanType == consts.ModelCodesec {
		updater["codesec_scan_status"] = consts.ScanStatusSuccess
		updater["codesec_scan_end_at"] = now
		updater["codesec_scan_msg"] = ""
		updater["codesec_high_risk"] = highRisk
		updater["codesec_high_severity"] = highSeverity
	}
	if scanType == consts.ModelSourceCheck {
		updater["source_check_scan_status"] = consts.ScanStatusSuccess
		updater["source_check_scan_end_at"] = now
		updater["source_check_scan_msg"] = ""
		updater["source_check_high_risk"] = highRisk
		updater["source_check_high_severity"] = highSeverity
	}
	return updater
}

// calculateProjectRiskLevel 计算项目整体风险级别
func calculateProjectRiskLevel(codesecSeverity, sourceCheckSeverity int64) string {
	// 考虑超危级别（CRITICAL）
	if codesecSeverity >= model.SeverityCriticalInt || sourceCheckSeverity >= model.SeverityCriticalInt {
		return model.SeverityCritical
	} else if codesecSeverity >= model.SeverityHighInt || sourceCheckSeverity >= model.SeverityHighInt {
		return model.SeverityHigh
	} else if codesecSeverity >= model.SeverityMediumInt || sourceCheckSeverity >= model.SeverityMediumInt {
		return model.SeverityMedium
	} else if codesecSeverity >= model.SeverityLowInt || sourceCheckSeverity >= model.SeverityLowInt {
		return model.SeverityLow
	} else {
		return model.SeverityUnknown
	}
}

func scanStarUpdater(scanType string) map[string]interface{} {
	now := time.Now().UnixMilli()
	updater := map[string]interface{}{}

	if scanType == consts.ModelCodesec {
		updater["codesec_scan_status"] = consts.ScanStatusScanning
		updater["codesec_scan_start_at"] = now
		updater["codesec_scan_end_at"] = 0 // 清零结束时间
		updater["codesec_scan_msg"] = ""   // 清空错误消息
		updater["last_scan_at"] = now
		// 注意：开始扫描时不重置风险级别相关字段，保持之前的扫描结果
	}
	if scanType == consts.ModelSourceCheck {
		updater["source_check_scan_status"] = consts.ScanStatusScanning
		updater["source_check_scan_start_at"] = now
		updater["source_check_scan_end_at"] = 0 // 清零结束时间
		updater["source_check_scan_msg"] = ""   // 清空错误消息
		updater["last_scan_at"] = now
		// 注意：不要重置 source_check_check_no，这个值在 startSourceCheckScan 中设置
		// 注意：开始扫描时不重置风险级别相关字段，保持之前的扫描结果
	}
	return updater
}
