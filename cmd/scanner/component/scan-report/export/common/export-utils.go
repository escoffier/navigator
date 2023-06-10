package common

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func GenBaseInfoChan(image imagesecModel.ImageWithCorrelateData2) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenBaseInfoChan")
			}
		}()
		defer close(out)

		info := GenImageBaseInfo(image)
		out <- info
	}()
	return out
}

func GenVulnInfoChan(baseImage imagesecModel.ImageBaseResponse, vuln []*imagesecModel.VulnView) chan []string {
	out := make(chan []string, 1)
	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenVulnInfoChan")
			}
		}()

		defer close(out)

		for i := range vuln {
			vu := vuln[i]
			info := GenVulnInfo(baseImage, *vu)
			out <- info
		}

	}()
	return out
}

func GenSensitiveFileChan(baseImage imagesecModel.ImageBaseResponse, files []*imagesecModel.SensitiveFile) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenSensitiveFileChan")
			}
		}()
		defer close(out)

		for i := range files {
			file := files[i]
			info := GenSensitiveFileInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenWebShellChan(baseImage imagesecModel.ImageBaseResponse, files []*imagesecModel.WebshellView) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenWebShellChan")
			}
		}()
		defer close(out)
		for i := range files {
			file := files[i]
			info := GenWebShellInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenMalwareChan(baseImage imagesecModel.ImageBaseResponse, files []*imagesecModel.Malware) chan []string {
	out := make(chan []string, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenMalwareChan")
			}
		}()
		defer close(out)
		for i := range files {
			file := files[i]
			info := GenMalwareInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenEnvChan(baseImage imagesecModel.ImageBaseResponse, files []*imagesecModel.ImageEnv) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenEnvChan")
			}
		}()
		defer close(out)

		for i := range files {
			file := files[i]
			info := GenEnvInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenImageResourceChan(baseImage imagesecModel.ImageBaseResponse, files []*imagesecModel.ImageContainerResources) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenImageResourceChan")
			}
		}()

		defer close(out)

		for i := range files {
			file := files[i]
			info := GenResponseInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenAppOrBaseImageChan(images []*imagesecModel.ImageBaseResponse) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("LibImageScanTaskExport")
			}
		}()

		defer close(out)

		for i := range images {
			file := images[i]
			info := GenBaseOrAppImageInfo(*file)
			out <- info
		}
	}()
	return out
}

func GenVulnInfo(image imagesecModel.ImageBaseResponse, vuln imagesecModel.VulnView) []string {

	info := []string{
		getImageName(image),
		image.RegistryUrl,
		vuln.Name,
		imagesecModel.GetSeverityView(vuln.SeverityInt),
		vuln.PkgName,
		vuln.PkgVersion,
		getVulnIsFixed(vuln.FixedVersion),
		vuln.CnnvdName,
		getVulnCvssScore(vuln),
		vuln.Description,
		vuln.Target, // 攻击路径
		getVulnDifficultyAttackingLocation(vuln.Attr),
		getVulnWhetherAutoTrigger(vuln.Attr),
		getVulnRequiredPermissionLevel(vuln.Attr),
		getVulnAttackComplexity(vuln.Attr),
		getVulnLeakageRisk(vuln.Attr),
		getVulnTamperingRisk(vuln.Attr),
		getVulnDosRisk(vuln.Attr),
		getVulnExpandedScope(vuln.Attr),
		vuln.CnnvdFixSuggestion,
		vuln.FixedVersion,
		getVulnReference(vuln),
		vuln.ClassView,
		getVulnIsKernel(vuln),
	}

	return info
}

func GenSensitiveFileInfo(image imagesecModel.ImageBaseResponse, file imagesecModel.SensitiveFile) []string {

	info := make([]string, 5)
	if file.Name == "" {
		return info
	}

	info[0] = getImageName(image)
	info[1] = image.RegistryUrl
	info[3] = file.Name

	// 暂时没有文件类型
	split := strings.Split(file.Name, "/")
	if len(split) >= 2 {
		// 文件名
		info[2] = split[len(split)-1]
	}

	return info
}

func getImageName(image imagesecModel.ImageBaseResponse) string {
	return fmt.Sprintf("%s:%s", image.FullRepoName, image.Tag)
}

func GenResponseInfo(image imagesecModel.ImageBaseResponse, file imagesecModel.ImageContainerResources) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Name, file.ResourceName, file.Namespace, file.ClusterName}
	return info
}

func GenMalwareInfo(image imagesecModel.ImageBaseResponse, file imagesecModel.Malware) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Name, file.Filename, file.Filepath}
	return info
}

func GenWebShellInfo(image imagesecModel.ImageBaseResponse, file imagesecModel.WebshellView) []string {
	level := "确定"
	if file.RiskLevel == imagesecModel.WebshellRiskLevelMaybe {
		level = "疑似"
	}
	info := []string{getImageName(image), image.RegistryUrl, file.Filename, file.Filepath, level, file.CodeContent()}
	return info
}

func GenEnvInfo(image imagesecModel.ImageBaseResponse, file imagesecModel.ImageEnv) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Key, file.Value}
	if file.PolicyDetect.Exception {
		info = append(info, "异常")
	} else {
		info = append(info, "正常")
	}
	return info
}

func GenBaseOrAppImageInfo(image imagesecModel.ImageBaseResponse) []string {
	info := []string{getImageName(image), image.RegistryUrl}
	return info
}

// 攻击路径
func getVulnDifficultyAttackingLocation(attr map[string]string) string {
	return imagesecModel.GetVulnAVView("")[attr["AV"]]
}

// 是否自动化触发
func getVulnWhetherAutoTrigger(attr map[string]string) string {
	return imagesecModel.GetVulnUIView(model.LangZh)[attr["UI"]]
}

// 所需权限级别
func getVulnRequiredPermissionLevel(attr map[string]string) string {
	return imagesecModel.GetVulnPrView(model.LangZh)[attr["PR"]]
}

// 攻击复杂度
func getVulnAttackComplexity(attr map[string]string) string {
	return imagesecModel.GetVulnAcView(model.LangZh)[attr["AC"]]
}

// 信息泄露风险
func getVulnLeakageRisk(attr map[string]string) string {
	return imagesecModel.GetVulnCView(model.LangZh)[attr["C"]]
}

// 信息/系统篡改风险
func getVulnTamperingRisk(attr map[string]string) string {
	return imagesecModel.GetVulnAView(model.LangZh)[attr["A"]]
}

// 造成 DoS 风险
func getVulnDosRisk(attr map[string]string) string {
	return imagesecModel.GetVulnIView(model.LangZh)[attr["I"]]
}

// 权限范围扩大
func getVulnExpandedScope(attr map[string]string) string {
	return imagesecModel.GetVulnSView(model.LangZh)[attr["S"]]
}

// 修复建议
func getVulnFixSuggestion(vuln imagesecModel.VulnView) string {
	return ""
}

// 参考链接
func getVulnReference(vuln imagesecModel.VulnView) string {
	if len(vuln.References) > 0 {
		return strings.Join(vuln.References, "\n")
	}
	return ""
}

// 是否内核漏洞
func getVulnIsKernel(vu imagesecModel.VulnView) string {
	// 提供开关临时关闭内核漏洞的判断
	kernelVuln := os.Getenv("IDENTITY_KERNEL_VULN")
	if kernelVuln != consts.FalseString {
		if util.ExistBit1(vu.Flag, model.VulnFlagKernel) {
			return "是"
		}
	}

	return "否"
}

func getVulnCvssScore(vuln imagesecModel.VulnView) string {
	if vuln.CVSSV3Score > 0 {
		return fmt.Sprintf("%.1f", vuln.CVSSV3Score)
	}
	return ""
}

func getVulnCnnvdNumber(vuln model.Vuln) string {
	if vuln.Metadata != nil {
		return vuln.Metadata.CNNVDs.Number
	}
	return ""
}

func getVulnIsFixed(fixedBy string) string {
	if fixedBy == "" {
		return "否"
	}
	return "是"
}

func GenImageBaseInfo(data imagesecModel.ImageWithCorrelateData2) []string {

	im := data.ToImageBaseResponse()

	info := []string{
		fmt.Sprintf("%s:%s", im.FullRepoName, im.Tag),
		im.RegistryUrl,
		util.ToString(im.RiskScore),
		getImageAttr(im.Flag, im.ImageAttr.Trusted), // 属性
		getImageOnline(im.Online),
		getImageSecurityQuestion(im.Flag),
		FormatTime(im.LastScanAt, consts.ExportTimeFormat),
		im.Digest,
		im.Tag,
		im.Size,
		im.GetOSView(),
		FormatTime(im.LastSyncAt, consts.ExportTimeFormat),
		IsBaseImage(im.Flag),
	}
	if util.ExistBit1(im.Flag, model.FlagImageNotMaintained) {
		info[10] = fmt.Sprintf("%s(%s)", im.Os, "此操作系统已经不再维护，可能导致漏洞扫描结果不准确，建议尽快升级")
	}

	suggest := append([]string{}, data.GenVulnSuggest(true)...)
	suggest = append([]string{}, data.GenSensitiveFileSuggest(true)...)
	info = append(info, strings.Join(suggest, "\n"))

	return info
}

func FormatTime(ti int64, format string) string {
	if ti <= 0 {
		return ""
	}
	if format == "" {
		format = consts.ExportTimeFormat
	}
	cstZone := time.FixedZone("GMT", 8*3600)
	return time.UnixMilli(ti).In(cstZone).Format(format)
}

func IsBaseImage(flag uint64) string {
	if model.ExistFlag(flag, model.FlagBaseImage) {
		return "是"
	}
	return "否"

}

func getImageSecurityQuestion(flag uint64) string {
	qus := make([]string, 0)
	if model.ExistFlag(flag, model.FlagHasVuln) {
		qus = append(qus, "漏洞")
	}
	if model.ExistFlag(flag, model.FlagHasMalicious) {
		qus = append(qus, "恶意文件")
	}
	if model.ExistFlag(flag, model.FlagHasSensitive) {
		qus = append(qus, "敏感文件")
	}
	if model.ExistFlag(flag, model.FlagHasWebshell) {
		qus = append(qus, "WebShell")
	}
	if model.ExistFlag(flag, model.FlagHasExceptPKG) {
		qus = append(qus, "不合规软件")
	}
	if model.ExistFlag(flag, model.FlagHasExceptEnv) {
		qus = append(qus, "异常环境变量")
	}
	if model.ExistFlag(flag, model.FlagPrivilegedBoot) {
		qus = append(qus, "root用户启动")
	}
	if model.ExistFlag(flag, model.FlagHasExceptLicense) {
		qus = append(qus, "不允许开源许可")
	}
	return strings.Join(qus, ",")
}

func getImageOnline(online bool) string {
	if online {
		return "在线"
	}
	return "离线"
}

func getImageAttr(flag uint64, trusted bool) string {
	qus := make([]string, 0)
	if model.ExistFlag(flag, model.FlagBaseImage) {
		qus = append(qus, "基础镜像")
	}
	if model.ExistFlag(flag, model.FlagHasFixedVuln) {
		qus = append(qus, "存在可修复漏洞")
	}
	if trusted {
		qus = append(qus, "可信镜像")
	} else {
		qus = append(qus, "非可信镜像")
	}

	return strings.Join(qus, ",")
}

func GenImageBaseInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "基础信息",

		Header: []string{
			"镜像名称",
			"来源仓库",
			"镜像评分",
			"属性",
			"运行状态",
			"安全问题",
			"最后一次扫描时间",
			"Image ID",
			"版本",
			"大小",
			"OS 版本",
			"入库时间",
			"是否为基础镜像",
			"修复建议",
		},
	}

	return data
}

func GetImageSheetInfo(executeType string) []types.ExcelMeta {

	sheets := make([]types.ExcelMeta, 8)
	sheets[0] = GenImageBaseInfoMeta()
	sheets[1] = GenImageVulnInfoMeta()
	sheets[2] = GenImageSensitiveFileInfoMeta()
	sheets[3] = GenImageVirusInfoMeta()
	sheets[4] = GenImageWebshellInfoMeta()
	sheets[5] = GenImageEnvInfoMeta()
	sheets[6] = GenImageResourcesInfoMeta()
	sheets[7] = GenImageTypeInfoMeta()

	if executeType == consts.ExportSingleImage {
		for i := range sheets {
			if sheets[i].SheetName != GenImageTypeInfoMeta().SheetName && sheets[i].SheetName != GenImageBaseInfoMeta().SheetName {
				sheets[i].Header = sheets[i].Header[2:]
			}
		}
	}
	return sheets
}

func GetVulnSheetInfo() []types.ExcelMeta {
	sheets := make([]types.ExcelMeta, 2)
	vulnHeader := GenImageVulnInfoMeta().Header[2:]
	vulnMete := GenImageVulnInfoMeta()
	vulnMete.Header = vulnHeader

	sheets[0] = vulnMete
	resourcesHeader := GenImageResourcesInfoMeta().Header

	resourcesHeader = append(resourcesHeader[:1], resourcesHeader[2:]...)
	resourcesMeta := GenImageResourcesInfoMeta()
	resourcesMeta.Header = resourcesHeader
	sheets[1] = resourcesMeta
	return sheets
}

func GenImageVulnInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "漏洞信息",

		Header: []string{
			"镜像名称",
			"来源仓库",
			"漏洞编号",
			"严重程度",
			"来源",
			"版本",
			"是否可修复",
			"CNNVD 编号",
			"CVSS3.0评分",
			"漏洞介绍",
			"路径",
			"攻击位置难易",
			"是否自动化触发",
			"所需权限级别",
			"攻击复杂度",
			"信息泄露风险",
			"信息/系统篡改风险",
			"造成DoS风险",
			"权限范围扩大",
			"修复建议",
			"修复版本",
			"参考链接",
			"漏洞类型",
			"是否是内核漏洞",
		},
	}
	return data
}

func GenImageSensitiveFileInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "敏感文件",

		Header: []string{
			"镜像名称", "来源仓库", "敏感文件名", "文件路径", "文件类型",
		},
	}
	return data
}

func GenImageVirusInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "恶意文件信息",

		Header: []string{
			"镜像名称", "来源仓库", "恶意文件名", "文件名", "文件路径",
		},
	}
	return data
}

func GenImageWebshellInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "Webshell信息",

		Header: []string{
			"镜像名称", "来源仓库", "文件名", "路径", "风险程度", "代码段",
		},
	}
	return data
}

func GenImageEnvInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "环境变量",

		Header: []string{
			"镜像名称", "来源仓库", "变量名", "变量值", "属性",
		},
	}
	return data
}

func GenImageResourcesInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "关联容器",

		Header: []string{
			"镜像名称", "来源仓库", "容器名称", "关联资源", "命名空间", "集群",
		},
	}
	return data
}

func GenImageTypeInfoMeta() types.ExcelMeta {
	data := types.ExcelMeta{
		SheetName: "基础镜像/应用镜像信息",

		Header: []string{
			"镜像名称", "来源仓库",
		},
	}
	return data
}

func Min(values ...int64) int64 {
	var res int64 = math.MaxInt64
	for i := range values {
		if values[i] < res {
			res = values[i]
		}
	}
	return res
}

func WriteToExcel(filenamePrefix string, sheets []types.ExcelMeta, data types.ExcelExportImageData) (*excelize.File, error) {
	if data == nil {
		return nil, fmt.Errorf("WriteToExcel  data is nil")
	}
	if filenamePrefix == "" {
		return nil, fmt.Errorf("filename is nil")
	}
	start := time.Now().UnixMilli()
	file := excelize.NewFile()
	file.Path = filenamePrefix + ".xlsx"
	logging.Get().Info().Str("excelPath", file.Path).Msg("WriteToExcel start")

	styleID, err := file.NewStyle(&excelize.Style{Font: &excelize.Font{Color: "#777777"}})
	if err != nil {
		styleID = 0
	}

	for i := range sheets {
		// 写入数据，用流式方式
		idx := file.NewSheet(sheets[i].SheetName)
		file.SetActiveSheet(idx)

		// 先写头数据
		streamWriter, err := file.NewStreamWriter(sheets[i].SheetName)
		if err != nil {
			return nil, err
		}

		data2 := make([]interface{}, len(sheets[i].Header))
		for j := range sheets[i].Header {
			data2[j] = sheets[i].Header[j]
		}

		cell, err := excelize.CoordinatesToCellName(1, 1)
		if err != nil {
			return nil, err
		}
		if err := streamWriter.SetRow(cell, data2, excelize.RowOpts{StyleID: styleID}); err != nil {
			return nil, err
		}
		// 再写数据
		col := 2

		sheetDataSlice := data[sheets[i].SheetName]

		for j := range sheetDataSlice {
			sheetDataChan := sheetDataSlice[j]
			for sheetData := range sheetDataChan {
				data3 := make([]interface{}, len(sheetData))
				for k := range sheetData {
					data3[k] = sheetData[k]
				}

				cell, err = excelize.CoordinatesToCellName(1, col)
				if err != nil {
					return nil, err
				}
				if err := streamWriter.SetRow(cell, data3); err != nil {
					return nil, err
				}
				col++
			}
		}
		// 刷新数据
		if err := streamWriter.Flush(); err != nil {
			return nil, err
		}
	}
	file.DeleteSheet("Sheet1")
	file.SetActiveSheet(0)

	logging.Get().Info().Int64("cost", time.Now().UnixMilli()-start).Msg("WriteToExcel end")

	return file, nil
}

// 把多个excel打包成一个zip文件返回,
func ZipExcelFile(files chan *excelize.File) (io.Reader, error) {
	b := new(bytes.Buffer)

	zw := zip.NewWriter(b)

	for {
		file, ok := <-files
		if !ok {
			break
		}
		logging.Get().Info().Str("filePath", file.Path).Msg("ZipExcelFile get file")
		hdr := zip.FileHeader{Name: file.Path}
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			return nil, err
		}

		buff, err := file.WriteToBuffer()
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(w, buff)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	if err := zw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	logging.Get().Info().Msg("ZipExcelFile get all file, zip complete")

	return b, nil
}

func CheckFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func DeleteFile(filename string) error {
	if CheckFileIsExist(filename) {
		return os.Remove(filename)
	}
	return nil
}

func SaveFile(reader io.Reader, filenamePrefix string) error {

	filename := filenamePrefix + ".zip"

	if CheckFileIsExist(filename) {
		// 如果文件存在就先删除该文件
		if err := DeleteFile(filename); err != nil {
			return err
		}
	}

	f, err := os.Create(filename) // 创建文件
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.Get().Err(err).Msg("SaveFile.Close")
		}
	}()

	w := bufio.NewWriter(f)

	_, err = w.ReadFrom(reader)
	if err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}
