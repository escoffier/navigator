package saveresult

import (
	"fmt"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 为了兼容以前的扫描代码，写一个转换层
func ConvertVirus(imageID int64, data []model.PerLayerMaliciousResult) ([]*model.ImageVirus, []*model.ScanIssueToImage) {
	virus := make([]*model.ImageVirus, 0)
	issue := make([]*model.ScanIssueToImage, 0)
	for i := range data {
		vir := data[i]
		for j := range vir.VirusInfos {
			viru := &model.ImageVirus{
				Filename: vir.VirusInfos[j].VirusName,
				Filepath: vir.VirusInfos[j].FilePath,
				Name:     vir.VirusInfos[j].VirusName,
			}
			viru.UniqueID = viru.GenUniqueVuln()

			virus = append(virus, viru)
			issue = append(issue, &model.ScanIssueToImage{
				SecurityIssue: model.FlagHasMalicious,
				UniqueTarget:  viru.UniqueID,
				ImageID:       imageID,
				LayerDigest:   vir.LayerDigest,
			})
		}
	}

	return virus, issue
}

func ConvertSensitive(imageID int64, data []model.PerLayerSensitiveResult) ([]*model.ImageSensitiveFile, []*model.ScanIssueToImage) {
	virus := make([]*model.ImageSensitiveFile, 0)
	issue := make([]*model.ScanIssueToImage, 0)
	for i := range data {
		vir := data[i]
		for j := range vir.Sensitives {
			viru := &model.ImageSensitiveFile{
				Name:          vir.Sensitives[j].Name,
				Description:   vir.Sensitives[j].Description,
				DescriptionEn: vir.Sensitives[j].DescriptionEn,
				DescriptionZh: vir.Sensitives[j].DescriptionZh,
			}
			viru.UniqueID = viru.GenUniqueVuln()
			virus = append(virus, viru)
			issue = append(issue, &model.ScanIssueToImage{
				SecurityIssue: model.FlagHasSensitive,
				UniqueTarget:  viru.UniqueID,
				ImageID:       imageID,
				LayerDigest:   vir.LayerDigest,
			})
		}
	}

	return virus, issue
}

func ConvertWebshell(imageID int64, data []model.PerLayerWebshellResult) ([]*model.ImageWebShell, []*model.ScanIssueToImage) {
	webshell := make([]*model.ImageWebShell, 0)
	issue := make([]*model.ScanIssueToImage, 0)
	for i := range data {
		vir := data[i]
		for j := range vir.WebShellInfos {
			viru := &model.ImageWebShell{
				Filename: vir.WebShellInfos[j].FileName,
				Filepath: vir.WebShellInfos[j].FilePath,
				Score:    vir.WebShellInfos[j].Score,
				Codes:    vir.WebShellInfos[j].Codes,
			}
			viru.UniqueID = viru.GenUniqueVuln()
			webshell = append(webshell, viru)
			issue = append(issue, &model.ScanIssueToImage{
				SecurityIssue: model.FlagHasWebshell,
				UniqueTarget:  viru.UniqueID,
				ImageID:       imageID,
				LayerDigest:   vir.LayerDigest,
			})
		}
	}

	return webshell, issue
}

func ConvertSoftware(imageID int64, data []model.Software) ([]*model.ImageSoftware, []*model.ScanIssueToImage) {
	software := make([]*model.ImageSoftware, 0)
	issue := make([]*model.ScanIssueToImage, 0)
	for i := range data {
		sf := &model.ImageSoftware{
			Name:    data[i].Name,
			Version: data[i].Version,
			License: data[i].License,
		}
		sf.UniqueID = sf.GenUniqueVuln()
		software = append(software, sf)
		iss := &model.ScanIssueToImage{
			SecurityIssue: model.FlagHasWebshell,
			UniqueTarget:  sf.UniqueID,
			ImageID:       imageID,
			LayerDigest:   data[i].LayerDigest,
		}
		if data[i].AbnormalLicense {
			iss.Flag = util.SetBit1(iss.Flag, model.FlagHasExceptLicense)
		}
		if data[i].AbnormalSoft {
			iss.Flag = util.SetBit1(iss.Flag, model.FlagHasSoftware)
		}

		issue = append(issue, iss)
	}
	return software, issue
}

// func ConvertLicense(imageID int64, data []model.PerLayerLicenseResult) ([]*model.ImageLicense, []*model.ScanIssueToImage) {
// 	licenses := make([]*model.ImageLicense, 0)
// 	issue := make([]*model.ScanIssueToImage, 0)
// 	for i := range data {
// 		vir := data[i]
// 		for j := range vir.LicenseInfos {
// 			viru := &model.ImageLicense{
// 				Value:       vir.LicenseInfos[j].Value,
// 				Description: vir.LicenseInfos[j].Descripion,
// 				Name:        vir.LicenseInfos[j].Name,
// 			}
// 			viru.UniqueID = viru.GenUniqueVuln()
// 			licenses = append(licenses, viru)
// 			issue = append(issue, &model.ScanIssueToImage{
// 				SecurityIssue: model.FlagHasExceptLicense,
// 				UniqueTarget:  viru.UniqueID,
// 				ImageID:       imageID,
// 				LayerDigest:   vir.LayerDigest,
// 			})
// 		}
// 	}
//
// 	return licenses, issue
// }

func ConvertEnv(imageID int64, data []model.EnvKeyValue) []*model.ImageEnv {
	envs := make([]*model.ImageEnv, 0)
	for i := range data {
		env := &model.ImageEnv{
			Key:     data[i].Key,
			Value:   data[i].Value,
			Normal:  data[i].IsAbnormal != consts.EnvIsAbnormal,
			ImageID: imageID,
		}
		env.UniqueID = env.GenUniqueVuln()
		envs = append(envs, env)
	}

	return envs
}

func ConvertVuln(imageID int64, trivyRes report.Report) ([]*model.Vuln, []*model.VulnImage) {

	vulns := make([]*model.Vuln, 0)
	vulnImages := make([]*model.VulnImage, 0)
	for i := range trivyRes.Results {
		vus := make([]*model.Vuln, 0)
		for j := range trivyRes.Results[i].Vulnerabilities {
			trivyVuln := trivyRes.Results[i].Vulnerabilities[j]

			vu := model.Vuln{
				Name:        trivyVuln.VulnerabilityID,
				Namespace:   strings.ToLower(trivyRes.Results[i].Type),
				Description: trivyVuln.Description,
				Link:        trivyVuln.References,
				Severity:    trivyVuln.Severity,
				SeverityInt: model.GetSeverityInt(trivyVuln.Severity),
				PkgName:     trivyVuln.PkgName,
				PkgVersion:  trivyVuln.InstalledVersion,
				FixedBy:     trivyVuln.FixedVersion,
				Target:      trivyRes.Results[i].Target,
			}

			// 取第一个，适配以前的设计
			for _, cvss := range trivyVuln.CVSS {
				vu.Metadata = &model.VulnMatedata{
					CVSS: model.CVSSVulnerabilityInfo{
						CVSSv3Score:  fmt.Sprintf("%f", cvss.V3Score),
						CVSSv3Vector: cvss.V3Vector,
					},
				}
			}

			switch string(trivyRes.Results[i].Class) {
			case report.ClassOSPkg:
				vu.Flag = util.SetBit1(vu.Flag, model.VulnFlagClassOSPkg)
			case report.ClassLangPkg:
				vu.Flag = util.SetBit1(vu.Flag, model.VulnFlagClassLangPkg)
			case report.ClassConfig:
				vu.Flag = util.SetBit1(vu.Flag, model.VulnFlagClassConfig)
			}

			if trivyVuln.FixedVersion != "" {
				vu.Flag = util.SetBit1(vu.Flag, model.VulnFlagHasFixed)
			}
			vu.UniqueVuln = vu.GenUniqueVuln()
			vulnImages = append(vulnImages, &model.VulnImage{
				UniqueVuln:  vu.UniqueVuln,
				ImageId:     imageID,
				LayerDigest: trivyVuln.Layer.Digest,
			})

			vus = append(vus, &vu)
		}

		for j := range trivyRes.Results[i].Packages {
			pkg := trivyRes.Results[i].Packages[j]
			for k := range vus {
				// 是否内核漏洞
				if vus[k].PkgName == pkg.Name && vus[k].PkgVersion == pkg.Version && IsKernelPkg(pkg) {
					vus[i].Flag = util.SetBit1(vus[i].Flag, model.VulnFlagKernel)
				}
				// 开源协议
				if vus[k].PkgName == pkg.Name && vus[k].PkgVersion == pkg.Version {
					vus[k].License = pkg.License
				}
			}
		}

		vulns = append(vulns, vus...)
	}
	return vulns, vulnImages
}
