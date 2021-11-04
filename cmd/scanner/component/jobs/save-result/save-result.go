package save_result

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	pull_image "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	scanner_vuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	image_cache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"
)

const (
	JobName = "save-result"
)

type Config struct {
	task    task.Task
	subtask task.SubTask
}

type ScanResultHandle struct {
	config Config
}

var (
	// virusSingleScore   = 40.0
	webshellNineToTen  = 40.0
	webshellSixToEight = 30.0
	webshellFourToFive = 20.0
	maxVulnscore       = 50.0
	constMapScore      = map[string]model.ConstMapScore{
		"Critical":   {MaxScore: 25, SingleScore: 25},
		"High":       {MaxScore: 20, SingleScore: 20},
		"Medium":     {MaxScore: 15, SingleScore: 15},
		"Low":        {MaxScore: 10, SingleScore: 10},
		"Negligible": {MaxScore: 5, SingleScore: 5},
		"Unknown":    {MaxScore: 5, SingleScore: 5},
		"Sensitive":  {MaxScore: 10, SingleScore: 5},
	}
)

func (s *ScanResultHandle) caculateScore(severity string, num int64) float64 {
	score := constMapScore[severity].SingleScore * float64(num)
	if score >= constMapScore[severity].MaxScore {
		score = constMapScore[severity].MaxScore
	}
	return score
}

func (s *ScanResultHandle) calculateWebshellScore(webshell model.WebShellInfo, flag *int) float64 {
	if (webshell.Score >= 4 && webshell.Score <= 5) && !((*flag & 2) == 2) {
		*flag += 2
		return webshellFourToFive
	} else if (webshell.Score >= 6 && webshell.Score <= 8) && !((*flag & 4) == 4) {
		*flag += 4
		return webshellSixToEight
	} else if (webshell.Score >= 9 && webshell.Score <= 10) && !((*flag & 8) == 8) {
		*flag += 8
		return webshellNineToTen
	} else {
		return 0
	}
}

func (s *ScanResultHandle) makeSeverityHistogramAndVulnScore(scanDetails *model.ScanDetailScanImage) {
	sevHistorgram := model.SeverityHistogramInfo{}
	for _, reuslts := range scanDetails.VulnDetails {
		for _, vuln := range reuslts.Vulns {
			for _, trivyVuln := range vuln.Trivy {
				switch trivyVuln.Severity {
				case "CRITICAL":
					sevHistorgram.NumCritical++
				case "HIGH":
					sevHistorgram.NumHigh++
				case "MEDIUM":
					sevHistorgram.NumMedium++
				case "LOW":
					sevHistorgram.NumLow++
				case "UNKNOWN":
					sevHistorgram.NumUnknown++
				}
			}
		}
	}
	criticalScore := s.caculateScore("Critical", sevHistorgram.NumCritical)
	highScore := s.caculateScore("High", sevHistorgram.NumHigh)
	mediumScore := s.caculateScore("Medium", sevHistorgram.NumMedium)
	lowScore := s.caculateScore("Low", sevHistorgram.NumLow)
	negligibleScore := s.caculateScore("Negligible", sevHistorgram.NumNegligible)
	unknownScore := s.caculateScore("Unknown", sevHistorgram.NumUnknown)
	scanDetails.VulnScore = criticalScore + highScore + mediumScore + lowScore + negligibleScore + unknownScore
	if scanDetails.VulnScore > maxVulnscore {
		scanDetails.VulnScore = maxVulnscore
	}
	scanDetails.SeverityHistogram = sevHistorgram
}

func (s *ScanResultHandle) defalutEnvFill(scanDetails *model.ScanDetailScanImage, param jobs.Param) {
	configJson, ok := param["configJson"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'configJson' in parameter")
		return
	}

	config := model.ConfigFile{}
	err := json.Unmarshal([]byte(configJson), &config)
	if err != nil {
		logging.GetLogger().Error().Msg("ScanEnv can't unmarshal configJson")
		return
	}
	envs := component.ParseConfigEnv(config.Config.Env)
	if len(envs) != 0 {
		scanDetails.EnvDetails = append(scanDetails.EnvDetails, envs...)
	}
}

func (s *ScanResultHandle) arrangeVulnDetails(trivyReport *report.Report, layers []string, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	vulnQuery := scanner_vuln.GetScannerVuln()
	fixedFlag := 0
	for i, v := range trivyReport.Results {
		mp := make(map[string]*model.NewVulnDetail)
		scanDetails.VulnDetails = append(scanDetails.VulnDetails, model.SingleScanDetail{Class: string(v.Class), Target: v.Target, Type: v.Type})
		// 筛选去重trivy的漏洞
		for _, vuln := range v.Vulnerabilities {
			if fixedFlag == 0 && vuln.FixedVersion != "" {
				fixedFlag = 1
			}
			if detail, ok := mp[vuln.VulnerabilityID]; ok {
				detail.Trivy = append(detail.Trivy, vuln)
			} else {
				tmp := &model.NewVulnDetail{}
				tmp.Trivy = append(tmp.Trivy, vuln)
				mp[vuln.VulnerabilityID] = tmp

			}
		}

		// 整合漏洞数据
		scanDetails.VulnDetails[i].Vulns = make([]model.NewVulnDetail, 0, len(mp))
		for k, trivyDetail := range mp {
			tmpDetail, err := vulnQuery.GetVulnDetail(k)
			if err != nil {
				trivyDetail.CVEID = k
				scanDetails.VulnDetails[i].Vulns = append(scanDetails.VulnDetails[i].Vulns, *trivyDetail)
				continue
			}
			trivyDetail.CVEID = k
			trivyDetail.Cnnvd = tmpDetail.Cnnvd
			trivyDetail.Cnvd = tmpDetail.Cnvd
			scanDetails.VulnDetails[i].Vulns = append(scanDetails.VulnDetails[i].Vulns, *trivyDetail)
		}
	}
	// scanDetails对应Vuln_info_json 整合完毕
	for _, v := range layers {
		tmp := &model.LayerScanDetail{}
		for i := range trivyReport.Results {
			tmpVulnDetails := &model.LayerVulnDetail{}
			tmpVulnDetails.Class = string(trivyReport.Results[i].Class)
			tmpVulnDetails.Target = trivyReport.Results[i].Target
			tmpVulnDetails.Type = trivyReport.Results[i].Type
			tmpVulnDetails.Vulns = make(map[string]*model.NewVulnDetail)
			tmp.VulnDetails = append(tmp.VulnDetails, *tmpVulnDetails)
		}
		layerMp[v] = tmp
	}

	// 整合层级需要入库的数据
	for i, v := range scanDetails.VulnDetails { // 这一层量级为个位数
		for _, vuln := range v.Vulns { // 漏洞数
			for _, trivyVvuln := range vuln.Trivy { // 个位数
				layerVulns, ok := layerMp[trivyVvuln.Layer.Digest].VulnDetails[i].Vulns[vuln.CVEID]
				if !ok {
					tmp := &model.NewVulnDetail{CVEID: vuln.CVEID, Cnvd: vuln.Cnvd, Cnnvd: vuln.Cnnvd}
					tmp.Trivy = append(tmp.Trivy, trivyVvuln)
					layerMp[trivyVvuln.Layer.Digest].VulnDetails[i].Vulns[vuln.CVEID] = tmp
				} else {
					layerVulns.Trivy = append(layerVulns.Trivy, trivyVvuln)
				}
			}
		}
	}
	scanDetails.HasFixedVuln = fixedFlag
	s.makeSeverityHistogramAndVulnScore(scanDetails)
}

func (s *ScanResultHandle) arrangeMalicious(maliciousResult []model.PerLayerMaliciousResult, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	imageMaliciousLen := 0
	for _, v := range maliciousResult {
		tmpMalicious := make([]model.Malicious, 0, len(v.VirusInfos))
		imageMaliciousLen += len(v.VirusInfos)
		for _, virus := range v.VirusInfos {
			singleMalicous := model.Malicious{}
			singleMalicous.VirusInfo = virus
			tmpMalicious = append(tmpMalicious, singleMalicous)
		}
		if len(v.VirusInfos) != 0 {
			_, ok := layerMp[v.LayerDigest]
			if ok {
				layerMp[v.LayerDigest].MaliciousDetails = tmpMalicious
			} else {
				layerMp[v.LayerDigest] = &model.LayerScanDetail{}
				layerMp[v.LayerDigest].MaliciousDetails = tmpMalicious
			}
		}
	}
	if imageMaliciousLen != 0 {
		imageMalicious := make([]model.Malicious, 0, imageMaliciousLen)
		for _, v := range layerMp {
			imageMalicious = append(imageMalicious, v.MaliciousDetails...)
		}
		scanDetails.MaliciousDetails = imageMalicious
	}
	if imageMaliciousLen > 0 {
		scanDetails.MaliciousScore = 40
	}
}

func (s *ScanResultHandle) arrangeSensitive(sensitivesResult []model.PerLayerSensitiveResult, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	imageSensitiveLen := 0
	for _, v := range sensitivesResult {
		imageSensitiveLen += len(v.Sensitives)
		_, ok := layerMp[v.LayerDigest]
		if ok {
			layerMp[v.LayerDigest].Sentitives = append(layerMp[v.LayerDigest].Sentitives, v.Sensitives...)
		} else {
			layerMp[v.LayerDigest] = &model.LayerScanDetail{}
			layerMp[v.LayerDigest].Sentitives = append(layerMp[v.LayerDigest].Sentitives, v.Sensitives...)
		}
	}
	imageSensitive := make([]model.Sensitive, 0, imageSensitiveLen)
	for _, v := range layerMp {
		imageSensitive = append(imageSensitive, v.Sentitives...)
	}
	scanDetails.Sentitives = imageSensitive
	sensitiveScore := s.caculateScore("Sensitive", int64(imageSensitiveLen))
	scanDetails.SensitiveScore = sensitiveScore
}

func (s *ScanResultHandle) arrangeWebshell(webshellInfoReuslt []model.PerLayerWebshellResult, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	imageWebshellLen := 0
	webshellFlag := 0
	for _, v := range webshellInfoReuslt {
		tmpWebshell := make([]model.Webshell, 0, len(v.WebShellInfos))
		imageWebshellLen += len(v.WebShellInfos)
		for _, webshell := range v.WebShellInfos {
			scanDetails.WebShellScore += s.calculateWebshellScore(webshell, &webshellFlag)
			singleWebshell := model.Webshell{}
			singleWebshell.WebShellInfo = webshell
			tmpWebshell = append(tmpWebshell, singleWebshell)
		}
		_, ok := layerMp[v.LayerDigest]
		if ok {
			layerMp[v.LayerDigest].WebshellInfos = append(layerMp[v.LayerDigest].WebshellInfos, tmpWebshell...)
		} else {
			layerMp[v.LayerDigest] = &model.LayerScanDetail{}
			layerMp[v.LayerDigest].WebshellInfos = append(layerMp[v.LayerDigest].WebshellInfos, tmpWebshell...)
		}
	}
	imageWebshell := make([]model.Webshell, 0, imageWebshellLen)
	for _, v := range layerMp {
		imageWebshell = append(imageWebshell, v.WebshellInfos...)
	}
	scanDetails.WebshellInfos = append(scanDetails.WebshellInfos, imageWebshell...)

}

func (s *ScanResultHandle) arrangeEnv(envReuslt []model.EnvKeyValue, scanDetails *model.ScanDetailScanImage) {
	scanDetails.EnvDetails = append(scanDetails.EnvDetails, envReuslt...)
}

func (s *ScanResultHandle) arrangeLicense(licenseResult []model.PerLayerLicenseResult, scanDetails *model.ScanDetailScanImage) {
	for _, v := range licenseResult {
		scanDetails.LicenseDetail = append(scanDetails.LicenseDetail, v.LicenseInfos...)
	}
}

func (s *ScanResultHandle) logPostgresLayer(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageId int64) {
	scannerOrm := store.GetScannerDb()
	for k, v := range layerMp {
		tmpScanLayer := model.ScanLayer{ImageId: imageId}
		tmpScanLayer.LayerDigest = k
		if v.VulnDetails != nil {
			vulnJson, err := json.Marshal(v.VulnDetails)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.VulnInfoJSON = vulnJson
		}

		if v.MaliciousDetails != nil {
			maliciousJson, err := json.Marshal(v.MaliciousDetails)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.MaliciousInfoJSON = maliciousJson
		}

		if v.Sentitives != nil {
			sensitiveJson, err := json.Marshal(v.Sentitives)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.SensitiveFileJSON = sensitiveJson
		}

		if v.WebshellInfos != nil {
			webshellJson, err := json.Marshal(v.WebshellInfos)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.WebshellInfoJSON = webshellJson
		}

		scannerOrm.InsertToScanLayer(ctx, &tmpScanLayer)
	}
}

func (s *ScanResultHandle) logPostgresImage(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageId int64) {
	scannerOrm := store.GetScannerDb()
	tmpScanImage := model.ScanImage{ImageId: imageId}
	if scanDetails.MaliciousDetails != nil {
		maliciousJson, err := json.Marshal(scanDetails.MaliciousDetails)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.MaliciousInfoJSON = maliciousJson
	}

	if scanDetails.Sentitives != nil {
		sensitiveJson, err := json.Marshal(scanDetails.Sentitives)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.SensitiveFileJSON = sensitiveJson
	}

	if scanDetails.VulnDetails != nil {
		vulnJson, err := json.Marshal(scanDetails.VulnDetails)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.VulnInfoJSON = vulnJson
	}

	if scanDetails.WebshellInfos != nil {
		webshellJson, err := json.Marshal(scanDetails.WebshellInfos)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.WebshellInfoJSON = webshellJson
	}

	if scanDetails.EnvDetails != nil {
		envJson, err := json.Marshal(scanDetails.EnvDetails)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.EnvJSON = envJson
	}

	if scanDetails.Software != nil {
		softwareJson, err := json.Marshal(scanDetails.Software)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.SoftwareJSON = softwareJson
	}

	if scanDetails.LicenseDetail != nil {
		licenseJson, err := json.Marshal(scanDetails.LicenseDetail)
		if err != nil {
			logging.GetLogger().Error().Err(err)
		}
		tmpScanImage.LicenseInfoJSON = licenseJson
	}

	severityCountJson, err := json.Marshal(scanDetails.SeverityHistogram)
	if err != nil {
		logging.GetLogger().Error().Err(err)
	} else {
		tmpScanImage.SeverityHistogramJSON = severityCountJson
	}

	// 计分
	tmpScanImage.VirusScore = scanDetails.MaliciousScore
	tmpScanImage.VulnScore = scanDetails.VulnScore
	tmpScanImage.WebshellScore = scanDetails.WebShellScore
	tmpScanImage.SensitiveScore = scanDetails.SensitiveScore
	tmpScanImage.RiskScore = tmpScanImage.VulnScore + math.Min(40, scanDetails.MaliciousScore+scanDetails.WebShellScore) + tmpScanImage.SensitiveScore

	collectionJson, err := json.Marshal(scanDetails.ScanEnableCollection)
	if err != nil {
		logging.GetLogger().Error().Err(err)
	} else {
		tmpScanImage.ScanEnableCollectionJson = string(collectionJson)
	}
	tmpScanImage.Status = model.ScanStatusSucceeded
	tmpScanImage.HasFixedVuln = scanDetails.HasFixedVuln
	scannerOrm.InsertToScanImage(ctx, &tmpScanImage)
}

func (s *ScanResultHandle) logPostgresVuln(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageId int64) {
	scannerOrm := store.GetScannerDb()
	for _, v := range scanDetails.VulnDetails {
		for _, vuln := range v.Vulns {

			// var err error
			tmpMatedate := model.VulnMatedata{}
			if vuln.Cnvd != nil {
				tmpMatedate.CNVDs = vuln.Cnvd
			}
			if vuln.Cnnvd.Number != "" {
				tmpMatedate.CNNVDs = vuln.Cnnvd
			}
			for _, trivyVuln := range vuln.Trivy {
				tmpMate := tmpMatedate
				for _, cvss := range trivyVuln.CVSS {
					tmpMate.CVSS.CVSSv3Score = fmt.Sprintf("%f", cvss.V3Score)
					tmpMate.CVSS.CVSSv3Vector = cvss.V3Vector
					break
				}
				mateDateJson, err := json.Marshal(tmpMate)
				if err != nil {
					logging.GetLogger().Error().Err(err)
				}
				linkjson, err := json.Marshal(trivyVuln.References)
				if err != nil {
					logging.GetLogger().Error().Err(err)
				}

				tmpVuln := model.Vuln{Name: vuln.CVEID, Namespace: v.Type, Target: v.Target, Description: trivyVuln.Description,
					MetadataJSON: mateDateJson, PkgName: trivyVuln.PkgName, PkgVersion: trivyVuln.InstalledVersion,
					LinkJSON: linkjson, FixedBy: trivyVuln.FixedVersion, Severity: trivyVuln.Severity}
				err = scannerOrm.InsertToVuln(ctx, &tmpVuln, imageId)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msgf("InsertoVuln failed ")
				}
			}
		}
	}
}

func (s *ScanResultHandle) updateRiskVulnCacheEntry(ctx context.Context, param jobs.Param, scanDetails *model.ScanDetailScanImage) {
	jobUrl, ok := param["url"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'url' in parameter")
		return
	}
	jobTag, ok := param["tag"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'tag' in parameter")
		return
	}
	jobRepo, ok := param["repoName"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'repoName' in parameter")
		return
	}

	url := strings.Replace(jobUrl, "https://", "", 1)
	url = strings.Replace(url, "http://", "", 1)
	image := "riskexp-image-vulns-" + url + "/" + jobRepo + ":" + jobTag
	sumData := model.ImageVulnsSumData{}
	sumData.CriticalNum = scanDetails.SeverityHistogram.NumCritical
	sumData.HighNum = scanDetails.SeverityHistogram.NumHigh
	sumData.MediumNum = scanDetails.SeverityHistogram.NumMedium
	sumData.LowNum = scanDetails.SeverityHistogram.NumLow
	sumData.UnknownNum = scanDetails.SeverityHistogram.NumUnknown
	bytes, err := json.Marshal(sumData)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Risk Vuln json Marshal error")
		return
	}
	redis, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Redis 0 can't get ")
		return
	}
	err = redis.Set(ctx, image, bytes, time.Hour*144).Err()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Updata risk cache error image:%v", image)
	}
}

func (s *ScanResultHandle) updateRiskVirusCacheEntry(ctx context.Context, param jobs.Param, scanDetails *model.ScanDetailScanImage) {
	jobUrl, ok := param["url"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'url' in parameter")
		return
	}
	jobTag, ok := param["tag"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'tag' in parameter")
		return
	}
	jobRepo, ok := param["repoName"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'repoName' in parameter")
		return
	}

	url := strings.Replace(jobUrl, "https://", "", 1)
	url = strings.Replace(url, "http://", "", 1)
	image := "riskexp-image-virus-" + url + "/" + jobRepo + ":" + jobTag
	sumData := model.ImageVirusSumData{}
	sumData.CriticalNum = int64(len(scanDetails.MaliciousDetails))
	bytes, err := json.Marshal(sumData)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Risk Virus json Marshal error")
		return
	}
	redis, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Redis 0 can't get ")
		return
	}
	err = redis.Set(ctx, image, bytes, time.Hour*144).Err()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Updata risk cache error image:%v", image)
	}
}

func (s *ScanResultHandle) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	// get scan result from param
	scanResult, ok := param["scanResult"].(map[task.ScanType]interface{})
	if !ok {
		logging.GetLogger().Error().Msg("miss 'scanResult' in parameter")
		return nil, errors.New("miss 'scanResult' in parameter")
	}

	layers, ok := param["layers"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}

	// 结果集合
	var scanDetails model.ScanDetailScanImage
	layerMp := make(map[string]*model.LayerScanDetail)

	// 整合漏洞
	scanVuln, ok := scanResult["scan-vuln"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-vuln' in parameter")
		// return nil, errors.New("miss 'scan-vuln' in parameter")
	} else {
		trivyReport, ok := scanVuln["result"].(*report.Report)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'result' in parameter")
			// return nil, errors.New("miss 'result' in parameter")
		} else {
			s.arrangeVulnDetails(trivyReport, layers, &scanDetails, layerMp)
			if len(scanDetails.VulnDetails) > 0 {
				flag, ok := scanVuln["customFlag"]
				if ok && flag == 1 {
					v, ok := scanVuln["software"].([]model.Software)
					if ok && len(v) > 0 {
						scanDetails.Software = v
						scanDetails.ScanEnableCollection.SoftwareEnable = 1
					}
				}
			}
		}
	}

	// 整合病毒
	scanMalicious, ok := scanResult["scan-malicious"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-malicious' in parameter")
		// return nil, errors.New("miss 'scan-malicious' in parameter")
	} else {
		maliciousResult, ok := scanMalicious["result"].([]model.PerLayerMaliciousResult)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'maliciousResult' in parameter")
			// return nil, errors.New("miss 'maliciousResult' in parameter")
		} else {
			s.arrangeMalicious(maliciousResult, &scanDetails, layerMp)
		}
	}

	// 整合敏感文件
	scanSensitive, ok := scanResult["scan-sensitive"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-sensitive' in parameter")
		// return nil, errors.New("miss 'scan-malicious' in parameter")
	} else {
		sensitivesResult, ok := scanSensitive["result"].([]model.PerLayerSensitiveResult)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'sensitivesResult' in parameter")
			// return nil, errors.New("miss 'maliciousResult' in parameter")
		} else {
			s.arrangeSensitive(sensitivesResult, &scanDetails, layerMp)
			if len(scanDetails.Sentitives) > 0 {
				flag, ok := scanSensitive["customFlag"]
				if ok && flag == 1 {
					scanDetails.ScanEnableCollection.SensitiveEnable = 1
				}
			}
		}
	}

	// 整合webshell
	scanWebshell, ok := scanResult["scan-webshell"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-webshell' in parameter")
	} else {
		webshellResult, ok := scanWebshell["result"].([]model.PerLayerWebshellResult)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'webshellResult' in parameter")
		} else {
			s.arrangeWebshell(webshellResult, &scanDetails, layerMp)
		}
	}

	// 整合Env
	scanEnv, ok := scanResult["scan-env"].(scan.Artifact)
	if !ok {
		s.defalutEnvFill(&scanDetails, param)
		logging.GetLogger().Warn().Msg("miss 'scan-env' in parameter")
	} else {
		envReuslt, ok := scanEnv["result"].([]model.EnvKeyValue)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'envReuslt' in parameter")
		} else {
			s.arrangeEnv(envReuslt, &scanDetails)
			if len(scanDetails.EnvDetails) > 0 {
				flag, ok := scanEnv["customFlag"]
				if ok && flag == 1 {
					scanDetails.ScanEnableCollection.EnvEnable = 1
				}
			}
		}
	}

	// 整合License
	scanLicense, ok := scanResult["scan-license"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-license' in parameter")
	} else {
		licenseResult, ok := scanLicense["result"].([]model.PerLayerLicenseResult)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'licenseResult' in parameter")
		} else {
			s.arrangeLicense(licenseResult, &scanDetails)
			if len(scanDetails.LicenseDetail) > 0 {
				scanDetails.ScanEnableCollection.LicenseEnable = 1
			}
		}
	}

	s.logPostgresLayer(ctx, &scanDetails, layerMp, s.config.subtask.Image.Id)
	s.logPostgresImage(ctx, &scanDetails, layerMp, s.config.subtask.Image.Id)
	s.logPostgresVuln(ctx, &scanDetails, layerMp, s.config.subtask.Image.Id)
	s.updateRiskVulnCacheEntry(ctx, param, &scanDetails)
	s.updateRiskVirusCacheEntry(ctx, param, &scanDetails)

	_, ok = param["pullImageJob"].(pull_image.Config)
	if ok {
		client1, err := image_cache.NewLocalLayerManageClientT("/layer")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("delete layers Failed!")
		} else {
			for k := range layers {
				err := client1.DeleteLayer(layers[k])
				if err != nil {
					logging.GetLogger().Error().Err(err).Msgf("delete layer %v Failed", layers[k])
				}
			}
		}
	}
	// tmpScanImage.VulnInfoJSON,  = json.Marshal(scanDetails)

	// tmpScanImage.ImageId = 222
	// scannerOrm.InsertToScanImage(context.Background(), &tmpScanImage)

	return nil, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Err(err).Str("jobName", JobName).Msg("init job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &ScanResultHandle{}
	i.config.task = config.Info.Task
	i.config.subtask = config.Info.SubTask

	return i, nil
}
