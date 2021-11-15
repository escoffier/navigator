package scan_report

import (
	"fmt"
	"path/filepath"
)

type ScanReportResultBuilder struct {
	result      *ScanReportResult
	vulns       map[string]*ImageVuln // VulnerabilityID+PkgName+InstalledVersion
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
		if v.ContainerUUID != "" {
			data.ImageCount.OnlineCount++
		}

		// 镜像评分大于80不在风险列表展示
		// 没有修复建议不在修复建议列表展示
		if 100-v.RiskScore > 80 && v.HasFixedVuln == 0 {
			continue
		}

		riskImage := &Image{
			Name:      v.Library + "/" + v.FullRepoName,
			Tag:       v.Tags,
			Score:     100 - v.RiskScore,
			Fixedable: int64(v.HasFixedVuln),
		}

		if t := s.contentType; t&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix ||
			t&TensorScanReportContentTypeRisk == TensorScanReportContentTypeRisk {
			data.Images = append(data.Images, riskImage)
		}

		for i := range v.VulnInfo {
			for j := range v.VulnInfo[i].Vulns {
				// 漏洞类型
				var vulnType string

				for m := range v.VulnInfo[i].Vulns[j].Cnvd {
					if v.VulnInfo[i].Vulns[j].Cnvd[m].Title != "" {
						vulnType = v.VulnInfo[i].Vulns[j].Cnvd[m].Title
					}
				}

				for k := range v.VulnInfo[i].Vulns[j].Trivy {

					imageVuln, ok := s.vulns[fmt.Sprintf(
						"%s%s%s",
						v.VulnInfo[i].Vulns[j].Trivy[k].VulnerabilityID,
						v.VulnInfo[i].Vulns[j].Trivy[k].PkgName,
						v.VulnInfo[i].Vulns[j].Trivy[k].InstalledVersion,
					)]

					if ok {
						// 当需要镜像展示漏洞列表时
						if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability {
							imageVuln.Images = append(imageVuln.Images, fmt.Sprintf("%s:%s", v.Library+"/"+v.FullRepoName, v.Tags))
						}
					} else {
						var detail string
						if len(v.VulnInfo[i].Vulns[j].Cnvd) > 0 && v.VulnInfo[i].Vulns[j].Cnvd[0].Description != "" {
							detail = v.VulnInfo[i].Vulns[j].Cnvd[0].Description
						} else {
							detail = v.VulnInfo[i].Vulns[j].Trivy[k].Description
						}

						var cvss3 float64
						for _, v := range v.VulnInfo[i].Vulns[j].Trivy[k].CVSS {
							if v.V3Score != 0 {
								cvss3 = v.V3Score
								break
							}
						}

						imageVuln = &ImageVuln{}

						// 当需要镜像展示漏洞列表时
						if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability {
							imageVuln.Images = []string{fmt.Sprintf("%s:%s", v.Library+"/"+v.FullRepoName, v.Tags)}
						}

						vuln := &Vuln{
							Id:     v.VulnInfo[i].Vulns[j].CVEID,
							Level:  VlunLevel(VlunLevel_value[v.VulnInfo[i].Vulns[j].Trivy[k].Severity]),
							Cnnvd:  v.VulnInfo[i].Vulns[j].Cnnvd.Number,
							Cvss3:  cvss3,
							Detail: detail,
						}

						// 如果cnvd的title为空，则取trivy的title字段(英文版的)
						if vulnType != "" {
							vuln.Type = vulnType
						} else {
							vuln.Type = v.VulnInfo[i].Vulns[j].Trivy[k].Title
						}

						// 当需要展示修复建议时
						if s.contentType&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix {
							vuln.FixSuggestion = v.VulnInfo[i].Vulns[j].Cnnvd.FixSuggestion
							vuln.FixVersoin = v.VulnInfo[i].Vulns[j].Trivy[k].FixedVersion
						}

						imageVuln.Vuln = vuln

						s.vulns[fmt.Sprintf(
							"%s%s%s",
							v.VulnInfo[i].Vulns[j].Trivy[k].VulnerabilityID,
							v.VulnInfo[i].Vulns[j].Trivy[k].PkgName,
							v.VulnInfo[i].Vulns[j].Trivy[k].InstalledVersion,
						)] = imageVuln

						if s.contentType&TensorScanReportContentTypeVulnerability == TensorScanReportContentTypeVulnerability {
							data.ImageVulns = append(data.ImageVulns, imageVuln)
						}

						// 漏洞类型计数
						switch vuln.Level {
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
						}

						data.VulnCount.TotalCount++
					}

					// 当只有修复建议且漏洞可修复时才保存镜像的漏洞信息
					if s.contentType&TensorScanReportContentTypeFix == TensorScanReportContentTypeFix {
						if riskImage.GetFixedable() == 1 && imageVuln.GetVuln().GetFixVersoin() != "" {
							riskImage.Vulns = append(riskImage.Vulns, imageVuln.Vuln)
						}
					}
				}
			}
		}

		if s.contentType&TensorScanReportContentTypeVirus == TensorScanReportContentTypeVirus {
			// 病毒
			for i := range v.MaliciousInfo {
				vi := &Virus_ImageViru{
					Path:  filepath.Join(v.MaliciousInfo[i].VirusInfo.FilePath, v.MaliciousInfo[i].VirusInfo.FileName),
					Image: fmt.Sprintf("%s%s%s", v.Library, v.FullRepoName, v.Tags),
				}

				virus, ok := s.viri[v.MaliciousInfo[i].VirusInfo.VirusName]
				if !ok {
					virus = &Virus{
						Name:   v.MaliciousInfo[i].VirusInfo.VirusName,
						Images: nil,
					}
					s.viri[v.MaliciousInfo[i].VirusInfo.VirusName] = virus
				}

				virus.Images = append(virus.Images, vi)
			}
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
