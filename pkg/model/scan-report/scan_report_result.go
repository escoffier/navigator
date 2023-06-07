package scan_report

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ScanReportResultBuilder struct {
	result      *ScanReportResult
	vulns       map[string]*ImageVuln // VulnerabilityID+PkgName+Version
	viri        map[string]*Virus     // Name
	contentType TensorScanReportContentType
}

func NewScanReportResultBuilder(contentType TensorScanReportContentType) *ScanReportResultBuilder {
	data := &ScanReportResultData{
		ImageCount: &ImageCount{},
		VulnCount:  &VulnCount{},
	}

	vluns := make(map[string]*ImageVuln)
	viri := make(map[string]*Virus)
	return &ScanReportResultBuilder{result: &ScanReportResult{Data: data}, vulns: vluns, viri: viri, contentType: contentType}
}

func (s *ScanReportResultBuilder) BuildByImagesInfo(info []*ImageInfo) {
	data := s.result.Data
	data.ImageCount.TotalCount += int64(len(info)) // 增加镜像总数

	for _, v := range info {
		logging.GetLogger().Debug().Msgf("build image info, image id: %d", v.ImageList.ID)
		// 可信镜像
		if v.IsTrusted == 1 {
			data.ImageCount.TrustedCount++
		}
		// 存在漏洞镜像
		if len(v.VulnInfo) != 0 {
			data.ImageCount.VulnCount++
		}
		// 存在敏感文件
		if len(v.SensitiveFile) != 0 {
			data.ImageCount.SensitiveFileCount++
		}
		// 存在恶意文件
		if len(v.MaliciousInfo) != 0 {
			data.ImageCount.MaliciousCount++
		}
		// 存在webshell
		if len(v.WebshellInfo) != 0 {
			data.ImageCount.WebshellCount++
		}
		// 存在异常环境变量
		if v.ScanEnableCollection.EnvEnable == 1 {
			data.ImageCount.WebshellCount++
		}
		// 存在不允许开源许可
		if v.ScanEnableCollection.LicenseEnable == 1 {
			data.ImageCount.LicenceCount++
		}
		// 存在不合规软件
		if v.ScanEnableCollection.SoftwareEnable == 1 {
			data.ImageCount.SoftwareCount++
		}
		// 存在特权启动
		if v.PrivilegedBoot == 1 {
			data.ImageCount.PrivilegedCount++
		}
		// 可修复镜像
		if v.HasFixedVuln == 1 {
			data.ImageCount.FixableCount++
		}
		// 已加固镜像
		if v.IsReinforce == 1 {
			data.ImageCount.FixedCount++
		}
		// 在线镜像
		if v.ContainerUUID != 0 {
			data.ImageCount.OnlineCount++
		}

		// 病毒列表
		if s.contentType&TensorScanReportContentTypeVirus == TensorScanReportContentTypeVirus {
			// 病毒
			for i := range v.MaliciousInfo {
				vi := &Virus_ImageViru{
					Path:  filepath.Join(v.MaliciousInfo[i].VirusInfo.FilePath, v.MaliciousInfo[i].VirusInfo.FileName),
					Image: fmt.Sprintf("%s/%s:%s", v.Library, v.FullRepoName, v.Tags),
				}

				virus, ok := s.viri[v.MaliciousInfo[i].VirusInfo.VirusName]
				if !ok {
					virus = &Virus{
						Name:   v.MaliciousInfo[i].VirusInfo.VirusName,
						Images: nil,
					}
					s.viri[v.MaliciousInfo[i].VirusInfo.VirusName] = virus // 通过病毒名称建立索引
					data.Viri = append(data.Viri, virus)
				}

				virus.Images = append(virus.Images, vi)
			}
		}

		var vulns []*Vuln

		for i := range v.VulnInfo {
			// 漏洞类型
			var vulnType string

			for m := range v.VulnInfo[i].Metadata.CNVDs {
				if v.VulnInfo[i].Metadata.CNVDs[m].Title != "" {
					vulnType = v.VulnInfo[i].Metadata.CNVDs[m].Title
					break
				}
			}

			logging.GetLogger().Debug().Msgf("image_id: %d, vuln id: %s", v.ImageList.ID, v.VulnInfo[i].Name)

			if !strings.Contains(v.VulnInfo[i].Name, "CVE") {
				continue
			}

			imageVuln, ok := s.vulns[fmt.Sprintf(
				"%s%s",
				v.VulnInfo[i].Name,
				v.VulnInfo[i].PkgName,
			)]

			if ok {
				// 当需要镜像展示漏洞列表时
				if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability && imageVuln != nil {
					imageVuln.Images = append(imageVuln.Images, fmt.Sprintf("%s:%s", v.Library+"/"+v.FullRepoName, v.Tags))
				}
			} else {
				data.VulnCount.TotalCount++ // 漏洞总数加1

				level := VlunLevel(VlunLevel_value[v.VulnInfo[i].Severity])

				// 漏洞类型计数
				switch level {
				case VlunLevel_CRITICAL:
					data.VulnCount.CriticalCount++
				case VlunLevel_HIGH:
					data.VulnCount.HighCount++
				case VlunLevel_MEDIUM:
					data.VulnCount.MediumCount++
				case VlunLevel_LOW:
					data.VulnCount.LowCount++
				case VlunLevel_NEGLIGIBLE:
					data.VulnCount.NegligibleCount++
				case VlunLevel_UNKNOWN:
					data.VulnCount.UnknownCount++
				default:
					logging.GetLogger().Debug().Msgf(
						"invalid vuln level, level num: %d, id: %s",
						level,
						v.VulnInfo[i].Name,
					)
				}

				// 只记录高危或者高的漏洞
				// 当漏洞编号没有CVE时，不展示漏洞编号
				if level != VlunLevel_CRITICAL && level != VlunLevel_HIGH {
					s.vulns[fmt.Sprintf(
						"%s%s",
						v.VulnInfo[i].Name,
						v.VulnInfo[i].PkgName,
					)] = nil
					continue
				}

				var cvss3 float64
				if v.VulnInfo[i].Metadata != nil {

					score, err := strconv.ParseFloat(v.VulnInfo[i].Metadata.CVSS.CVSSv3Score, 64)
					if err != nil {
						cvss3 = score
					}
				}

				imageVuln = &ImageVuln{}

				// 当需要展示漏洞镜像列表时
				if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability {
					imageVuln.Images = []string{fmt.Sprintf("%s:%s", v.Library+"/"+v.FullRepoName, v.Tags)}
				}

				vuln := &Vuln{
					Id:    v.VulnInfo[i].Name,
					Level: level,
					Cvss3: cvss3,
				}
				if v.VulnInfo[i].Metadata != nil {
					vuln.Cnnvd = v.VulnInfo[i].Metadata.CNNVDs.Number
				}

				vuln.Type = vulnType

				// 当需要展示修复建议时
				if s.contentType&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix {
					vuln.FixVersoin = v.VulnInfo[i].FixedBy
					if v.VulnInfo[i].Metadata != nil {
						vuln.FixSuggestion = v.VulnInfo[i].Metadata.CNNVDs.FixSuggestion
					}
				}

				imageVuln.Vuln = vuln

				s.vulns[fmt.Sprintf(
					"%s%s",
					v.VulnInfo[i].Name,
					v.VulnInfo[i].PkgName,
				)] = imageVuln

				if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability {
					data.ImageVulns = append(data.ImageVulns, imageVuln)
				}

				// 当只有修复建议且漏洞可修复时才保存镜像的漏洞信息
				if s.contentType&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix {
					// 只保存可修复并且有修复建议的漏洞
					if v.HasFixedVuln == 1 && imageVuln.GetVuln().GetFixVersoin() != "" {
						vulns = append(vulns, imageVuln.Vuln)
					}
				}
			}
		}

		// 镜像评分大于80不在风险列表展示
		// 没有修复建议不在修复建议列表展示
		if 100-v.RiskScore > 80 && v.HasFixedVuln == 0 {
			continue
		}

		riskImage := &Image{
			Name:  v.Library + "/" + v.FullRepoName,
			Tag:   v.Tags,
			Score: 100 - v.RiskScore,
			Vulns: vulns,
		}
		if v.HasFixedVuln == 1 && len(vulns) > 0 {
			riskImage.Fixedable = 1
		}

		if t := s.contentType; t&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix ||
			t&TensorScanReportContentTypeRisk == TensorScanReportContentTypeRisk {
			data.Images = append(data.Images, riskImage)
		}
	}
}

func (s *ScanReportResultBuilder) GetResult() *ScanReportResult {
	return s.result
}

func (s *ScanReportResultBuilder) SetStartTime(t int64) *ScanReportResultBuilder {
	s.result.StartTimestamp = t
	return s
}

func (s *ScanReportResultBuilder) SetEndTime(t int64) *ScanReportResultBuilder {
	s.result.EndTimestamp = t
	return s
}

func (s *ScanReportResultBuilder) SetName(name string) *ScanReportResultBuilder {
	s.result.Name = name
	return s
}

func (s *ScanReportResultBuilder) SetContentType(contentTypes []int64) *ScanReportResultBuilder {
	s.result.ContentTypes = contentTypes
	return s
}

func (s *ScanReportResultBuilder) SetTpye(t int64) *ScanReportResultBuilder {
	s.result.Type = t
	return s
}
