package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannerCi "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
)

// PortalExport Portal项目数据导出
type PortalExport struct {
	ExportTaskDal      imagesecStore.ExportTaskDal
	FileDir            string // 文件存储的绝对路径
	UpdateTask         types.UpdateExportTask
	CodesecScanDal     store.CodesecScanDal
	SourceCheckScanDal store.SourceCheckScanDal
	CiScanDal          store.CiScanDal
	ProjectDal         store.ProjectDal // 用于获取项目相关信息
	Log                *scannerUtils.LogEvent
}

// NewPortalExport 创建Portal导出实例
func NewPortalExport(
	exportTaskDal imagesecStore.ExportTaskDal,
	fileDir string,
	updateTask types.UpdateExportTask,
	codesecScanDal store.CodesecScanDal,
	sourceCheckScanDal store.SourceCheckScanDal,
	projectDal store.ProjectDal, // 用于获取项目相关信息
	ciScanDal store.CiScanDal,
) *PortalExport {
	return &PortalExport{
		ExportTaskDal:      exportTaskDal,
		FileDir:            fileDir,
		UpdateTask:         updateTask,
		CodesecScanDal:     codesecScanDal,
		SourceCheckScanDal: sourceCheckScanDal,
		CiScanDal:          ciScanDal,
		ProjectDal:         projectDal,
		Log:                scannerUtils.NewLogEvent(scannerUtils.WithModule("PortalExport")),
	}
}

// GetTensorTask 获取导出任务
func (s *PortalExport) GetTensorTask(ctx context.Context, executeType string) ([]imagesecModel.ExportTensorTask, error) {
	tasks, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesecModel.SearchExportTaskParam{
		ExecuteType: []string{executeType},
		TaskType:    imagesecModel.ExportExcel,
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
		Filter:      &imagesecModel.Filter{Limit: 1},
	})
	if err != nil {
		s.Log.Err(err).Str("ExecuteType", executeType).Msg("Failed to search export tasks")
		return nil, err
	}
	return tasks, nil
}

// Run 运行导出任务
func (s *PortalExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportPortalProject)
	if err != nil {
		s.Log.Err(err).Msg("Failed to get export tasks")
		return
	}

	if len(tasks) == 0 {
		return
	}

	s.Log.Info().Int("taskCount", len(tasks)).Msg("Processing export tasks")

	for i := range tasks {
		if err := s.UpdateTask.Start(ctx, tasks[i].ID); err != nil {
			s.Log.Err(err).Str("exportTask", tasks[i].LogStr()).Msg("Failed to start export task")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			s.Log.Err(err).Str("exportTask", tasks[i].LogStr()).Msg("Failed to process export task")
			if err := s.UpdateTask.Failure(ctx, tasks[i].ID, err.Error()); err != nil {
				s.Log.Err(err).Str("exportTask", tasks[i].LogStr()).Msg("Failed to update task failure status")
			}
		}
	}
}

// worker 执行单个导出任务
func (s *PortalExport) worker(ctx context.Context, task imagesecModel.ExportTensorTask) error {
	param := imagesecModel.PortalProjectExportParam{}
	if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
		s.Log.Err(err).Str("exportTask", task.LogStr()).Msg("Failed to unmarshal param parameter")
		return fmt.Errorf("failed to unmarshal param parameter: %w", err)
	}

	// 获取项目详细信息
	project, _, err := s.ProjectDal.SearchProject(ctx, model.SearchProjectParam{Ids: param.ProjectID})
	if err != nil {
		s.Log.Err(err).Str("exportTask", task.LogStr()).Msg("Failed to search project")
		if updateErr := s.UpdateTask.Failure(ctx, task.ID, err.Error()); updateErr != nil {
			s.Log.Err(updateErr).Str("exportTask", task.LogStr()).Msg("Failed to update task failure status")
		}
		return err
	}
	if len(project) == 0 {
		s.Log.Error().Str("exportTask", task.LogStr()).Msg("没有可导出的数据")
		if updateErr := s.UpdateTask.Failure(ctx, task.ID, "没有可导出的数据"); updateErr != nil {
			s.Log.Err(updateErr).Str("exportTask", task.LogStr()).Msg("Failed to update task failure status")
		}
		return nil
	}

	fileName := strings.ReplaceAll(task.FilePath, ".zip", "")

	excelChan := s.Export(ctx, fileName, project, task)

	if err := s.ZipAndSave(ctx, fileName, excelChan); err != nil {
		s.Log.Err(err).Str("exportTask", task.LogStr()).Msg("Failed to zip and save file")
		return err
	}

	// 成功之后更新任务
	filePath := fmt.Sprintf("%s/%s.zip", s.FileDir, fileName)
	if err := s.UpdateTask.Success(ctx, task.ID, filePath); err != nil {
		s.Log.Err(err).Str("exportTask", task.LogStr()).Msg("Failed to update task success status")
		return err
	}
	s.Log.Info().Str("exportTask", task.LogStr()).Msg("task finished and success")

	return nil
}

// Export 导出Portal项目数据到Excel
func (s *PortalExport) Export(ctx context.Context, filename string, projects []*model.Project, task imagesecModel.ExportTensorTask) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {

		defer close(out)
		s.Log.Info().Str("filename", filename).Int64("taskID", task.ID).Msg("Portal export started")

		// 准备Excel数据结构
		finalExcelData := make(map[types.SheetName][]chan []string)
		sheets := s.getPortalSheetInfo()

		// 为每个项目获取数据并合并
		for _, project := range projects {
			// 获取单个项目的所有数据
			excelData := s.getAllData(ctx, *project)
			// 转换数据格式以适配WriteToExcel
			s.addDataToExcel(finalExcelData, excelData)
		}

		// 生成Excel文件
		excelFile, err := common.WriteToExcel(filename, sheets, finalExcelData)
		if err != nil {
			s.Log.Err(err).Str("exportTask", task.LogStr()).Msg("Failed to write Excel file")
			return
		}

		out <- excelFile
	}()

	return out
}

// addDataToExcel 转换数据格式以适配WriteToExcel函数
func (s *PortalExport) addDataToExcel(finalExcelData map[types.SheetName][]chan []string,
	sourceData map[types.SheetName]chan []string) {

	defer func() {
		if r := recover(); r != nil {
			s.Log.Error().Str("stack", string(debug.Stack())).Msg("addDataToExcel panic")
		}
	}()

	// 将单个channel转换为channel数组格式
	for sheetName, dataChan := range sourceData {
		if finalExcelData[sheetName] == nil {
			finalExcelData[sheetName] = make([]chan []string, 0)
		}
		finalExcelData[sheetName] = append(finalExcelData[sheetName], dataChan)
	}
}

// ZipAndSave 压缩并保存文件
func (s *PortalExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {
	file, err := common.ZipExcelFile(files)
	if err != nil {
		s.Log.Err(err).Str("filename", filename).Msg("Failed to zip Excel file")
		return err
	}

	filePath := s.FileDir + "/" + filename
	if err := common.SaveFile(file, filePath); err != nil {
		s.Log.Err(err).Str("filename", filename).Str("filePath", filePath).Msg("Failed to save file")
		return err
	}
	return nil
}

// getAllData 获取项目的所有数据，返回数据通道以支持并发处理
func (s *PortalExport) getAllData(ctx context.Context, pro model.Project) map[types.SheetName]chan []string {
	result := make(map[types.SheetName]chan []string)

	// 使用函数式编程风格，参考excel-export.go的实现
	dataFetchers := []func(){
		// CodeSec漏洞数据获取
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("getAllData CodeSec panic")
				}
			}()

			codesecVulns := s.getAllCodeSecVulns(ctx, pro.Uuid)
			if len(codesecVulns) > 0 {
				sheetName := types.SheetName(s.getCodeSecVulnMeta().SheetName)
				result[sheetName] = s.genCodeSecVulnChan(pro, codesecVulns)
			}
		},

		// SourceCheck漏洞数据获取
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("getAllData SourceCheck vulns panic")
				}
			}()

			sourceCheckVulns := s.getAllSourceCheckVulns(ctx, pro.Uuid)
			if len(sourceCheckVulns) > 0 {
				sheetName := types.SheetName(s.getSourceCheckVulnMeta().SheetName)
				result[sheetName] = s.genSourceCheckVulnChan(pro, sourceCheckVulns)
			}
		},

		// SourceCheck组件数据获取
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("getAllData SourceCheck components panic")
				}
			}()

			sourceCheckComponents := s.getAllSourceCheckComponents(ctx, pro.Uuid)
			if len(sourceCheckComponents) > 0 {
				sheetName := types.SheetName(s.getSourceCheckComponentMeta().SheetName)
				result[sheetName] = s.genSourceCheckComponentChan(pro, sourceCheckComponents)
			}
		},

		// SourceCheck许可数据获取
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("getAllData SourceCheck licenses panic")
				}
			}()

			sourceCheckLicenses := s.getAllSourceCheckLicenses(ctx, pro.Uuid)
			if len(sourceCheckLicenses) > 0 {
				sheetName := types.SheetName(s.getSourceCheckLicenseMeta().SheetName)
				result[sheetName] = s.genSourceCheckLicenseChan(pro, sourceCheckLicenses)
			}
		},

		// CI扫描数据获取
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("getAllData CI scans panic")
				}
			}()

			ciScans := s.getAllCiScans(ctx, pro.Uuid)
			if len(ciScans) > 0 {
				sheetName := types.SheetName(s.getCiScanMeta().SheetName)
				result[sheetName] = s.genCiScanChan(pro, ciScans)
			}
		},
	}

	// 顺序执行所有数据获取函数，确保数据完整性
	for _, fetcher := range dataFetchers {
		fetcher()
	}

	return result
}

// getPortalSheetInfo 获取Portal项目导出的Sheet信息
func (s *PortalExport) getPortalSheetInfo() []types.ExcelMeta {
	return []types.ExcelMeta{
		s.getCodeSecVulnMeta(),
		s.getSourceCheckVulnMeta(),
		s.getSourceCheckComponentMeta(),
		s.getSourceCheckLicenseMeta(),
		s.getCiScanMeta(),
	}
}

// getCodeSecVulnMeta 获取CodeSec漏洞Sheet元数据
func (s *PortalExport) getCodeSecVulnMeta() types.ExcelMeta {
	return types.ExcelMeta{
		SheetName: "代码扫描_漏洞",
		Header: []string{
			"ID",     // ID
			"项目UUID", // 项目UUID
			"项目名称",   // 项目名称
			"项目URL",  // 项目URL
			"缺陷名称",   // 缺陷名称
			"严重级别",   // 风险等级
			"文件名",    // 文件名
			"文件行数",   // 文件行数
			"缺陷跟踪",   // 缺陷跟踪
		},
	}
}

// getSourceCheckVulnMeta 获取SourceCheck漏洞Sheet元数据
func (s *PortalExport) getSourceCheckVulnMeta() types.ExcelMeta {
	return types.ExcelMeta{
		SheetName: "开源软件扫描_漏洞",
		Header: []string{
			"ID",     // ID
			"项目UUID", // 项目UUID
			"项目名称",   // 项目名称
			"项目URL",  // 项目URL
			"漏洞编号",   // CVE编号
			"严重等级",   // 风险等级
			"弱点类型名称", // 弱点类型名称
			"影响组件数",  // 影响组件数
			"漏洞描述",   // 漏洞描述
		},
	}
}

// getSourceCheckComponentMeta 获取SourceCheck组件Sheet元数据
func (s *PortalExport) getSourceCheckComponentMeta() types.ExcelMeta {
	return types.ExcelMeta{
		SheetName: "开源软件扫描_组件",
		Header: []string{
			"ID",     // ID
			"项目UUID", // 项目UUID
			"项目名称",   // 项目名称
			"项目URL",  // 项目URL
			"组件名称",   // 组件名称
			"严重级别",   // 风险等级
			"语言",     //   语言
			"许可名称列表", // 许可名称列表(JSON)
			"当前版本",   // 版本
			"推荐版本",   // 推荐版本
			"最新版本",   // 最新版本
			"国家",     // 所属国家
		},
	}
}

// getSourceCheckLicenseMeta 获取SourceCheck许可Sheet元数据
func (s *PortalExport) getSourceCheckLicenseMeta() types.ExcelMeta {
	return types.ExcelMeta{
		SheetName: "开源软件扫描_许可",
		Header: []string{
			"ID",     // ID
			"项目UUID", // 项目UUID
			"项目名称",   // 项目名称
			"项目URL",  // 项目URL
			"许可简称",   // 许可简称
			"风险等级",   // 风险等级
			"许可全称",   // 许可全称
		},
	}
}

// getCiScanMeta 获取CI镜像扫描Sheet元数据
func (s *PortalExport) getCiScanMeta() types.ExcelMeta {
	return types.ExcelMeta{
		SheetName: "CI镜像扫描",
		Header: []string{
			"ID",     // ID
			"项目UUID", // 项目UUID
			"项目名称",   // 项目名称
			"项目URL",  // 项目URL
			"镜像名称",   // 镜像名称
			"操作系统",   // 操作系统
			"流水线名称",  // 流水线名称
			"阻断模式",   // action
			"匹配白名单",  // 匹配白名单
			"错误信息",   // 错误信息
			"严重漏洞数",
			"高危漏洞数",
			"中危漏洞数",
			"低危漏洞数",
			"扫描开始时间", // 扫描开始时间
			"扫描结束时间", // 扫描结束时间
		},
	}
}

// 数据生成方法
func (s *PortalExport) genCodeSecVulnChan(pro model.Project, vulns []*model.CodeSecVuln) chan []string {
	out := make(chan []string, len(vulns))

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("stack", string(debug.Stack())).Str("project", pro.LogStr()).Msg("genCodeSecVulnChan panic")
			}
		}()
		defer close(out)

		for _, vuln := range vulns {
			vuln.Serialize()
			row := []string{
				fmt.Sprintf("%d", vuln.ID), // ID
				pro.Uuid,                   // 项目UUID
				pro.Name,                   // 项目名称
				pro.Url,                    // 项目URL
				vuln.VulName,               // 缺陷名称
				vuln.Severity,              // 严重级别
				vuln.Filename,              // 文件名
				vuln.RowNum,                // 文件行数
				vuln.VulFlag,               // 缺陷跟踪
			}
			out <- row
		}
	}()

	return out
}

func (s *PortalExport) genSourceCheckVulnChan(pro model.Project, vulns []*model.SourceCheckVuln) chan []string {
	out := make(chan []string, len(vulns))

	go func() {
		defer close(out)

		for _, vuln := range vulns {
			vuln.Serialize()
			row := []string{
				fmt.Sprintf("%d", vuln.ID), // ID
				pro.Uuid,                   // 项目UUID
				pro.Name,                   // 项目名称
				pro.Url,                    // 项目URL
				vuln.CustomCveNo,           // 漏洞编号 (CVE编号)
				vuln.Severity,              // 严重等级
				vuln.CweName,               // 弱点类型名称
				fmt.Sprintf("%d", vuln.AffectComponentCount), // 影响组件数
				vuln.Description, // 漏洞描述
			}
			out <- row
		}
	}()

	return out
}

func (s *PortalExport) genSourceCheckComponentChan(pro model.Project, components []*model.SourceCheckComponent) chan []string {
	out := make(chan []string, len(components))

	go func() {
		defer close(out)

		for _, apiComp := range components {
			apiComp.Serialize()
			row := []string{
				fmt.Sprintf("%d", apiComp.ID),         // ID
				pro.Uuid,                              // 项目UUID
				pro.Name,                              // 项目名称
				pro.Url,                               // 项目URL
				apiComp.ArtifactId,                    // 组件名称
				apiComp.Severity,                      // 严重级别
				apiComp.JarInfoAddFrom,                // 语言
				strings.Join(apiComp.LicenseIds, ","), // 许可名称列表
				apiComp.Version,                       // 当前版本
				apiComp.RecommendVersion,              // 推荐版本
				apiComp.LatestVersion,                 // 最新版本
				apiComp.Country,                       // 国家
			}
			out <- row
		}
	}()

	return out
}

func (s *PortalExport) genSourceCheckLicenseChan(pro model.Project, licenses []*model.SourceCheckLicense) chan []string {
	out := make(chan []string, len(licenses))

	go func() {
		defer close(out)

		for _, license := range licenses {
			license.Serialize()
			row := []string{
				fmt.Sprintf("%d", license.ID), // ID
				pro.Uuid,                      // 项目UUID
				pro.Name,                      // 项目名称
				pro.Url,                       // 项目URL
				license.LicenseId,             // 许可简称
				license.Grade,                 // 风险等级
				license.LicenseName,           // 许可全称
			}
			out <- row
		}
	}()

	return out
}

// genCiScanChan 生成CI镜像扫描数据
func (s *PortalExport) genCiScanChan(pro model.Project, ciScans []*scannerCi.CiScan) chan []string {
	out := make(chan []string, len(ciScans))

	go func() {
		defer close(out)

		for _, ciScan := range ciScans {
			row := []string{
				fmt.Sprintf("%d", ciScan.ID), // ID
				pro.Uuid,                     // 项目UUID
				pro.Name,                     // 项目名称
				pro.Url,                      // 项目URL
				ciScan.ImageName,             // 镜像名称
				ciScan.OS,                    // 操作系统
				ciScan.PipelineName,          // 流水线名称
				getCiMode(ciScan.Mode),
				fmt.Sprintf("%t", ciScan.MatchWhitelist), // 匹配白名单
				ciScan.Message,                           // 错误信息
				fmt.Sprintf("%d", ciScan.SeverityHistogram.NumCritical),                       // 严重漏洞数
				fmt.Sprintf("%d", ciScan.SeverityHistogram.NumHigh),                           // 高危漏洞数
				fmt.Sprintf("%d", ciScan.SeverityHistogram.NumMedium),                         // 中危漏洞数
				fmt.Sprintf("%d", ciScan.SeverityHistogram.NumLow),                            // 低危漏洞数
				time.UnixMilli(ciScan.StartedAt).In(time.Local).Format("2006-01-02 15:04:05"), // 扫描开始时间
				ciScan.FinishAt.Format("2006-01-02 15:04:05"),                                 // 扫描结束时间
			}
			out <- row
		}
	}()

	return out
}

func getCiMode(mod int) string {
	switch mod {
	case scannerCi.CiPolicyResultCodeAlert:
		return "告警"
	case scannerCi.CiPolicyResultCodeBlock:
		return "阻断"
	default:
		return "通过"
	}
}

// 分页获取数据的方法
const (
	defaultPageSize = 1000 // 每页获取1000条数据
)

// getAllCodeSecVulns 分页获取所有CodeSec漏洞数据
func (s *PortalExport) getAllCodeSecVulns(ctx context.Context, projectUuid string) []*model.CodeSecVuln {
	var allVulns []*model.CodeSecVuln
	startID := int64(0)
	filter := imagesecModel.EmptyFilter().SetLimit(defaultPageSize).SetSortFiledByID().SetSortAsc()
	for {
		vulns, _, err := s.CodesecScanDal.SearchVuln(ctx, model.SearchVulnParam{
			ProjectUuid: projectUuid,
			StartID:     startID,
			Filter:      filter,
		})
		if err != nil {
			s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get codesec vulns")
			break
		}

		if len(vulns) == 0 {
			break
		}
		startID = vulns[len(vulns)-1].ID

		allVulns = append(allVulns, vulns...)

		// 如果返回的数据少于页大小，说明已经是最后一页
		if len(vulns) < defaultPageSize {
			break
		}
	}

	s.Log.Info().Str("projectUuid", projectUuid).Int("totalCount", len(allVulns)).Msg("Finished retrieving all CodeSec vulns")
	return allVulns
}

// getAllSourceCheckVulns 分页获取所有SourceCheck漏洞数据
func (s *PortalExport) getAllSourceCheckVulns(ctx context.Context, projectUuid string) []*model.SourceCheckVuln {
	var allVulns []*model.SourceCheckVuln
	filter := imagesecModel.EmptyFilter().SetLimit(defaultPageSize).SetSortFiledByID().SetSortAsc()
	startID := int64(0)
	for {
		vulns, _, err := s.SourceCheckScanDal.SearchVuln(ctx, model.SearchVulnParam{
			ProjectUuid: projectUuid,
			StartID:     startID,
			Filter:      filter,
		})
		if err != nil {
			s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get sourcecheck vulns")
			break
		}

		if len(vulns) == 0 {
			break
		}
		startID = vulns[len(vulns)-1].ID
		allVulns = append(allVulns, vulns...)

		// 如果返回的数据少于页大小，说明已经是最后一页
		if len(vulns) < defaultPageSize {
			break
		}
	}

	s.Log.Info().Str("projectUuid", projectUuid).Int("totalCount", len(allVulns)).Msg("Finished retrieving all SourceCheck vulns")
	return allVulns
}

// getAllSourceCheckComponents 分页获取所有SourceCheck组件数据
func (s *PortalExport) getAllSourceCheckComponents(ctx context.Context, projectUuid string) []*model.SourceCheckComponent {
	var allComponents []*model.SourceCheckComponent
	filter := imagesecModel.EmptyFilter().SetLimit(defaultPageSize).SetSortFiledByID().SetSortAsc()
	startID := int64(0)
	for {
		components, _, err := s.SourceCheckScanDal.SearchComponent(ctx, model.SearchVulnParam{
			ProjectUuid: projectUuid,
			StartID:     startID,
			Filter:      filter,
		})
		if err != nil {
			s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get sourcecheck components")
			break
		}

		if len(components) == 0 {
			break
		}
		startID = components[len(components)-1].ID
		allComponents = append(allComponents, components...)

		// 如果返回的数据少于页大小，说明已经是最后一页
		if len(components) < defaultPageSize {
			break
		}
	}

	s.Log.Info().Str("projectUuid", projectUuid).Int("totalCount", len(allComponents)).Msg("Finished retrieving all SourceCheck components")
	return allComponents
}

// getAllSourceCheckLicenses 分页获取所有SourceCheck许可数据
func (s *PortalExport) getAllSourceCheckLicenses(ctx context.Context, projectUuid string) []*model.SourceCheckLicense {
	var allLicenses []*model.SourceCheckLicense
	startID := int64(0)
	filter := imagesecModel.EmptyFilter().SetLimit(defaultPageSize).SetSortFiledByID().SetSortAsc()

	for {
		licenses, _, err := s.SourceCheckScanDal.SearchLicense(ctx, model.SearchVulnParam{
			ProjectUuid: projectUuid,
			StartID:     startID,
			Filter:      filter,
		})
		if err != nil {
			s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get sourcecheck licenses")
			break
		}

		if len(licenses) == 0 {
			break
		}
		startID = licenses[len(licenses)-1].ID

		allLicenses = append(allLicenses, licenses...)

		// 如果返回的数据少于页大小，说明已经是最后一页
		if len(licenses) < defaultPageSize {
			break
		}
	}

	s.Log.Info().Str("projectUuid", projectUuid).Int("totalCount", len(allLicenses)).Msg("Finished retrieving all SourceCheck licenses")
	return allLicenses
}

// getAllCiScans 分页获取所有CI扫描数据
func (s *PortalExport) getAllCiScans(ctx context.Context, projectUuid string) []*scannerCi.CiScan {
	var allCiScans []*scannerCi.CiScan
	filter := imagesecModel.EmptyFilter().SetLimit(defaultPageSize).SetSortFiledByID().SetSortAsc()
	startID := int64(0)

	for {
		ciScans, _, err := s.CiScanDal.SearchCiScan(ctx, store.SearchCiScanParam{
			ProjectUuid: projectUuid,
			StartID:     startID,
			Filter:      filter,
		})
		if err != nil {
			s.Log.Err(err).Str("projectUuid", projectUuid).Msg("Failed to get ci scans")
			break
		}

		if len(ciScans) == 0 {
			break
		}
		startID = ciScans[len(ciScans)-1].ID

		allCiScans = append(allCiScans, ciScans...)

		// 如果返回的数据少于页大小，说明已经是最后一页
		if len(ciScans) < defaultPageSize {
			break
		}
	}

	s.Log.Info().Str("projectUuid", projectUuid).Int("totalCount", len(allCiScans)).Msg("Finished retrieving all CI scans")
	return allCiScans
}
