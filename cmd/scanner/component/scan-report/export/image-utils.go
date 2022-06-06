package export

import (
	"fmt"
	"strings"
	"time"

	"github.com/shopspring/decimal"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var VulnAttr map[string]map[string]string

func GenBaseInfoChan(image model.ImageList, status model.ImageResponse) chan []string {
	out := make(chan []string)
	go func() {
		defer close(out)
		info := GenImageBaseInfo(image, status)
		out <- info
	}()
	return out
}

func GenVulnInfoChan(imageDetail model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail model.ImageList) {
		defer close(out)
		vulns := imageDetail.ImageScanVuln.Vulns
		for i := range vulns {
			vuln := vulns[i]
			info := GenVulnInfo(imageDetail, *vuln)
			out <- info
		}
	}(imageDetail)
	return out
}

func GenSensitiveFileChan(imageDetail model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail model.ImageList) {
		defer close(out)
		files := imageDetail.ImageScanVuln.SensitiveFiles
		for i := range files {
			file := files[i]
			info := GenSensitiveFileInfo(imageDetail, file)
			out <- info
		}
	}(imageDetail)
	return out
}

func GenWebShellChan(imageDetail model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail model.ImageList) {
		defer close(out)
		files := imageDetail.ImageScanWebshell
		for i := range files {
			file := files[i]
			info := GenWebShellInfo(imageDetail, file)
			out <- info
		}
	}(imageDetail)
	return out
}

func GenVirusChan(imageDetail model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail model.ImageList) {
		defer close(out)
		files := imageDetail.ImageScanVirus
		for i := range files {
			file := files[i]
			info := GenVirusInfo(imageDetail, file)
			out <- info
		}
	}(imageDetail)
	return out
}

func GenEnvChan(imageDetail model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail model.ImageList) {
		defer close(out)
		files := imageDetail.ImageScanEnv
		for i := range files {
			file := files[i]
			info := GenEnvInfo(imageDetail, file)
			out <- info
		}
	}(imageDetail)
	return out
}

func GenImageResourceChan(image model.ImageList, resources []model.TensorContainer) chan []string {
	out := make(chan []string)
	go func(image model.ImageList, resources []model.TensorContainer) {
		defer close(out)
		for i := range resources {
			info := GenResponseInfo(image, resources[i])
			out <- info
		}
	}(image, resources)
	return out
}

func GenAppOrBaseImageChan(images []model.ImageList) chan []string {
	out := make(chan []string)
	go func(imageDetail []model.ImageList) {
		defer close(out)
		for i := range images {
			info := GenBaseOrAppImageInfo(images[i])
			out <- info
		}
	}(images)
	return out
}

func GenVulnInfo(image model.ImageList, vuln model.Vuln) []string {

	if VulnAttr == nil {
		VulnAttr = make(map[string]map[string]string)
		// 攻击位置难易
		VulnAttr["AV"] = map[string]string{
			"N": "网络访问",
			"L": "本地访问",
			"P": "物理访问",
			"":  "相邻网络访问",
		}
		// 是否自动化触发
		VulnAttr["UI"] = map[string]string{
			"N": "自动",
			"R": "非自动",
		}
		// 所需权限级别 and 攻击复杂度
		VulnAttr["AC"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息泄露风险
		VulnAttr["C"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		// 信息/系统篡改风险
		VulnAttr["A"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
		//  权限范围扩大
		VulnAttr["S"] = map[string]string{
			"C": "扩大",
			"U": "不变",
		}
		// 造成 DoS 风险
		VulnAttr["PR"] = map[string]string{
			"N": "无",
			"L": "低",
			"H": "高",
		}
	}

	m := make(map[string]string)

	if vuln.Metadata != nil {
		split := strings.Split(vuln.Metadata.CVSS.CVSSv3Vector, "/")
		for i := range split {
			attr := strings.Split(split[i], ":")
			if len(attr) >= 2 {
				m[attr[0]] = attr[1]
			}
		}
	}

	info := []string{
		getImageName(image),
		image.Library,

		vuln.Name,
		model.GetSeverityView(vuln.SeverityInt),
		vuln.PkgName,
		vuln.PkgVersion,
		getVulnIsFixed(vuln.FixedBy),
		getVulnCnnvdNumber(vuln),
		getVulnCvssScore(vuln),
		vuln.Description,
		vuln.Target, // 攻击路径
		getVulnDifficultyAttackingLocation(m),
		getVulnWhetherAutoTrigger(m),
		getVulnRequiredPermissionLevel(m),
		getVulnAttackComplexity(m),
		getVulnLeakageRisk(m),
		getVulnTamperingRisk(m),
		getVulnDosRisk(m),
		getVulnExpandedScope(m),
		getVulnFixSuggestion(vuln),
		vuln.FixedBy,
		getVulnReference(vuln),
	}

	return info
}

func GenSensitiveFileInfo(image model.ImageList, file model.Sensitive) []string {

	info := make([]string, 5)
	if file.Name == "" {
		return info
	}

	info[0] = getImageName(image)
	info[1] = image.Library
	info[3] = file.Name

	// 暂时没有文件类型
	split := strings.Split(file.Name, "/")
	if len(split) >= 2 {
		// 文件名
		info[2] = split[len(split)-1]
	}

	return info
}

func getImageName(image model.ImageList) string {
	return fmt.Sprintf("%s:%s", image.FullRepoName, image.Tags)
}

func GenResponseInfo(image model.ImageList, file model.TensorContainer) []string {
	info := []string{getImageName(image), image.Library, file.Name, file.ResourceName, file.Namespace, file.ClusterKey}
	return info
}

func GenVirusInfo(image model.ImageList, file model.VirusFileInfo) []string {
	info := []string{getImageName(image), image.Library, file.Virusname, file.Filename, file.Filepath}
	return info
}

func GenWebShellInfo(image model.ImageList, file model.WebshellFileInfo) []string {
	info := []string{getImageName(image), image.Library, file.Filename, strings.Join(file.Codes, ";"), file.Filepath, ToString(file.Score)}
	return info
}

func GenEnvInfo(image model.ImageList, file model.SummaryEnv) []string {

	info := []string{getImageName(image), image.Library, file.EnvName, file.EnvValue}
	if file.IsAbnormal > 0 {
		info = append(info, "异常")
	} else {
		info = append(info, "正常")
	}
	return info
}

func GenBaseOrAppImageInfo(image model.ImageList) []string {
	info := []string{getImageName(image), image.Library}
	return info
}

// 攻击位置难易
func getVulnDifficultyAttackingLocation(attr map[string]string) string {
	if VulnAttr["AV"] != nil {
		if res := VulnAttr["AV"][attr["AV"]]; res != "" {
			return res
		}
	}
	return "相邻网络访问"
}

// 是否自动化触发
func getVulnWhetherAutoTrigger(attr map[string]string) string {
	if VulnAttr["UI"] != nil {
		if res := VulnAttr["UI"][attr["UI"]]; res != "" {
			return res
		}
	}
	return "非自动"
}

// 所需权限级别
func getVulnRequiredPermissionLevel(attr map[string]string) string {
	if VulnAttr["AC"] != nil {
		if res := VulnAttr["UI"][attr["AC"]]; res != "" {
			return res
		}
	}
	return "无"
}

// 攻击复杂度
func getVulnAttackComplexity(attr map[string]string) string {
	if VulnAttr["AC"] != nil {
		if res := VulnAttr["UI"][attr["AC"]]; res != "" {
			return res
		}
	}
	return "相邻网络访问"
}

// 信息泄露风险
func getVulnLeakageRisk(attr map[string]string) string {
	if VulnAttr["C"] != nil {
		if res := VulnAttr["C"][attr["C"]]; res != "" {
			return res
		}
	}
	return "无"
}

// 信息/系统篡改风险
func getVulnTamperingRisk(attr map[string]string) string {
	if VulnAttr["A"] != nil {
		if res := VulnAttr["A"][attr["A"]]; res != "" {
			return res
		}
	}
	return "无"
}

// 造成 DoS 风险
func getVulnDosRisk(attr map[string]string) string {
	if VulnAttr["PR"] != nil {
		if res := VulnAttr["PR"][attr["PR"]]; res != "" {
			return res
		}
	}
	return "无"
}

// 权限范围扩大
func getVulnExpandedScope(attr map[string]string) string {
	if VulnAttr["PR"] != nil {
		if res := VulnAttr["PR"][attr["PR"]]; res != "" {
			return res
		}
	}
	return "不变"
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

func ByteToMB(b int) string {
	mb := float64(b) / (1024 * 1024)
	f, _ := decimal.NewFromFloat(mb).Round(2).Float64()
	return ToString(f) + "MB"
}

func GenImageBaseInfo(image model.ImageList, status model.ImageResponse) []string {
	info := []string{
		getImageName(image),
		image.Library,
		ToString(100 - image.ImageScanVuln.RiskScore),
		getImageAttr(image.Flag, status.Trusted), // 属性
		getImageOnline(status.Online),
		getImageSecurityQuestion(image.Flag),
		FormatTime(status.CompleteTime, consts.ExportTimeFormat),
		image.Digest,
		image.Tags,
		ByteToMB(image.Size),
		image.OS,
		FormatTime(image.FirstPushTime.UnixMilli(), consts.ExportTimeFormat),
		IsBaseImage(image.Flag),
	}
	if image.Registry != nil {
		info[1] = image.Registry.Url
	}
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
		qus = append(qus, "特权启动")
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

func getImageAttr(flag uint64, trusted int64) string {
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
	if trusted == consts.TrustedImage {
		qus = append(qus, "可信镜像")
	} else {
		qus = append(qus, "非可信镜像")
	}

	return strings.Join(qus, ",")
}

func GenImageBaseInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
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
		},
	}

	return data
}

func GetImageSheetInfo(executeType consts.ExportType) []ExcelMetaData {

	sheets := make([]ExcelMetaData, 8)
	sheets[0] = GenImageBaseInfoMeta()
	sheets[1] = GenImageVulnInfoMeta()
	sheets[2] = GenImageSensitiveFileInfoMeta()
	sheets[3] = GenImageVirusInfoMeta()
	sheets[4] = GenImageWebshellInfoMeta()
	sheets[5] = GenImageEnvInfoMeta()
	sheets[6] = GenImageResourcesInfoMeta()
	sheets[7] = GenImageTypeInfoMeta()

	if executeType == consts.ExportImage {
		for i := range sheets {
			if sheets[i].SheetName != GenImageTypeInfoMeta().SheetName && sheets[i].SheetName != GenImageBaseInfoMeta().SheetName {
				sheets[i].Header = sheets[i].Header[2:]
			}
		}
	}

	return sheets
}

func GenImageVulnInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
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
			"攻击路径",
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
		},
	}
	return data
}

func GenImageSensitiveFileInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "敏感文件",

		Header: []string{
			"镜像名称", "来源仓库", "敏感文件名", "文件路径", "文件类型",
		},
	}
	return data
}

func GenImageVirusInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "恶意文件信息",

		Header: []string{
			"镜像名称", "来源仓库", "恶意文件名", "文件名", "文件路径",
		},
	}
	return data
}

func GenImageWebshellInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "Webshell信息",

		Header: []string{
			"镜像名称", "来源仓库", "文件名", "代码段", "路径", "评分",
		},
	}
	return data
}

func GenImageEnvInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "环境变量",

		Header: []string{
			"镜像名称", "来源仓库", "变量名", "变量值", "属性",
		},
	}
	return data
}

func GenImageResourcesInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "关联容器",

		Header: []string{
			"镜像名称", "来源仓库", "容器名称", "关联资源", "命名空间", "集群",
		},
	}
	return data
}

func GenImageTypeInfoMeta() ExcelMetaData {
	data := ExcelMetaData{
		SheetName: "基础镜像/应用镜像信息",

		Header: []string{
			"镜像名称", "来源仓库",
		},
	}
	return data
}
