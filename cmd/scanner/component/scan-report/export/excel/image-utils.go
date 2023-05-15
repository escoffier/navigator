package excel

import (
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func GenBaseInfoChan(image model.ImageWithCorrelateData) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenBaseInfoChan")
			}
		}()
		defer close(out)

		info := GenImageBaseInfo(image)
		out <- info
	}()
	return out
}

func GenVulnInfoChan(baseImage model.ImageBaseResponse, vuln []*model.Vuln) chan []string {
	out := make(chan []string, 1)
	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenVulnInfoChan")
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

func GenSensitiveFileChan(baseImage model.ImageBaseResponse, files []*model.ImageSensitiveFile) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenSensitiveFileChan")
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

func GenWebShellChan(baseImage model.ImageBaseResponse, files []*scannermodel.Webshell) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenWebShellChan")
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

func GenVirusChan(baseImage model.ImageBaseResponse, files []*model.ImageVirus) chan []string {
	out := make(chan []string, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenVirusChan")
			}
		}()
		defer close(out)
		for i := range files {
			file := files[i]
			info := GenVirusInfo(baseImage, *file)
			out <- info
		}
	}()
	return out
}

func GenEnvChan(baseImage model.ImageBaseResponse, files []*model.ImageEnv) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenEnvChan")
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

func GenImageResourceChan(baseImage model.ImageBaseResponse, files []*model.ImageContainerResources) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("GenImageResourceChan")
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

func GenAppOrBaseImageChan(images []*model.ImageBaseResponse) chan []string {
	out := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
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

func GenVulnInfo(image model.ImageBaseResponse, vuln model.Vuln) []string {

	info := []string{
		getImageName(image),
		image.RegistryUrl,
		vuln.Name,
		model.GetSeverityView(vuln.SeverityInt),
		vuln.PkgName,
		vuln.PkgVersion,
		getVulnIsFixed(vuln.FixedBy),
		getVulnCnnvdNumber(vuln),
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
		getVulnFixSuggestion(vuln),
		vuln.FixedBy,
		getVulnReference(vuln),
		vuln.GetVulnClass(),
		getVulnIsKernel(vuln),
	}

	return info
}

func GenSensitiveFileInfo(image model.ImageBaseResponse, file model.ImageSensitiveFile) []string {

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

func getImageName(image model.ImageBaseResponse) string {
	return fmt.Sprintf("%s:%s", image.FullRepoName, image.Tag)
}

func GenResponseInfo(image model.ImageBaseResponse, file model.ImageContainerResources) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Name, file.ResourceName, file.Namespace, file.ClusterName}
	return info
}

func GenVirusInfo(image model.ImageBaseResponse, file model.ImageVirus) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Name, file.Filename, file.Filepath}
	return info
}

func GenWebShellInfo(image model.ImageBaseResponse, file scannermodel.Webshell) []string {
	split := strings.Split(file.FileName, "/")

	name, path := file.FileName, ""
	if len(split) > 1 {
		path = strings.Join(split[:len(split)-1], "/")
		name = split[len(split)-1]
	}

	level := "确定"
	if file.Level == "maybe" {
		level = "疑似"
	}
	info := []string{getImageName(image), image.RegistryUrl, name, path, level, file.MaliciousData}
	return info
}

func GenEnvInfo(image model.ImageBaseResponse, file model.ImageEnv) []string {
	info := []string{getImageName(image), image.RegistryUrl, file.Key, file.Value}
	if !file.Normal {
		info = append(info, "异常")
	} else {
		info = append(info, "正常")
	}
	return info
}

func GenBaseOrAppImageInfo(image model.ImageBaseResponse) []string {
	info := []string{getImageName(image), image.RegistryUrl}
	return info
}

// 攻击路径
func getVulnDifficultyAttackingLocation(attr map[string]string) string {
	return attr["AV"]
}

// 是否自动化触发
func getVulnWhetherAutoTrigger(attr map[string]string) string {
	return attr["UI"]
}

// 所需权限级别
func getVulnRequiredPermissionLevel(attr map[string]string) string {
	return attr["PR"]
}

// 攻击复杂度
func getVulnAttackComplexity(attr map[string]string) string {
	return attr["AC"]
}

// 信息泄露风险
func getVulnLeakageRisk(attr map[string]string) string {
	return attr["C"]
}

// 信息/系统篡改风险
func getVulnTamperingRisk(attr map[string]string) string {
	return attr["A"]
}

// 造成 DoS 风险
func getVulnDosRisk(attr map[string]string) string {
	return attr["I"]
}

// 权限范围扩大
func getVulnExpandedScope(attr map[string]string) string {
	return attr["S"]
}

// 修复建议
func getVulnFixSuggestion(vuln model.Vuln) string {
	if vuln.Metadata != nil {
		return vuln.Metadata.CNNVDs.FixSuggestion
	}
	return ""
}

// 参考链接
func getVulnReference(vuln model.Vuln) string {
	if len(vuln.Link) > 0 {
		return strings.Join(vuln.Link, "\n")
	}
	return ""
}

// 是否内核漏洞
func getVulnIsKernel(vu model.Vuln) string {
	// 提供开关临时关闭内核漏洞的判断
	kernelVuln := os.Getenv("IDENTITY_KERNEL_VULN")
	if kernelVuln != consts.FalseString {
		if util.ExistBit1(vu.Flag, model.VulnFlagKernel) {
			return "是"
		}
	}

	return "否"
}

func getVulnCvssScore(vuln model.Vuln) string {
	if vuln.Metadata != nil {
		return vuln.Metadata.CVSS.CVSSv3Score
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

func GenImageBaseInfo(data model.ImageWithCorrelateData) []string {

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
		im.Os,
		FormatTime(im.LastSyncAt, consts.ExportTimeFormat),
		IsBaseImage(im.Flag),
	}
	if util.ExistBit1(im.Flag, model.FlagImageNotMaintained) {
		info[10] = fmt.Sprintf("%s(%s)", im.Os, "此操作系统已经不再维护，可能导致漏洞扫描结果不准确，建议尽快升级")
	}
	suggest := append([]string{}, im.VulnFixSuggestion...)
	suggest = append(suggest, im.SensitiveFixSuggestion...)
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
	if model.ExistFlag(flag, model.FlagHasSoftware) {
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
	if model.ExistFlag(flag, model.FlagReinforced) {
		qus = append(qus, "已加固镜像")
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

func GenImageBaseInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
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

func GetImageSheetInfo(executeType string) []common.ExcelMetaData {

	sheets := make([]common.ExcelMetaData, 8)
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

func GetVulnSheetInfo() []common.ExcelMetaData {
	sheets := make([]common.ExcelMetaData, 2)
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

func GenImageVulnInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
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

func GenImageSensitiveFileInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
		SheetName: "敏感文件",

		Header: []string{
			"镜像名称", "来源仓库", "敏感文件名", "文件路径", "文件类型",
		},
	}
	return data
}

func GenImageVirusInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
		SheetName: "恶意文件信息",

		Header: []string{
			"镜像名称", "来源仓库", "恶意文件名", "文件名", "文件路径",
		},
	}
	return data
}

func GenImageWebshellInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
		SheetName: "Webshell信息",

		Header: []string{
			"镜像名称", "来源仓库", "文件名", "路径", "风险程度", "代码段",
		},
	}
	return data
}

func GenImageEnvInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
		SheetName: "环境变量",

		Header: []string{
			"镜像名称", "来源仓库", "变量名", "变量值", "属性",
		},
	}
	return data
}

func GenImageResourcesInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
		SheetName: "关联容器",

		Header: []string{
			"镜像名称", "来源仓库", "容器名称", "关联资源", "命名空间", "集群",
		},
	}
	return data
}

func GenImageTypeInfoMeta() common.ExcelMetaData {
	data := common.ExcelMetaData{
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
