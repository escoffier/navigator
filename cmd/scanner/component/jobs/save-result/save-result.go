package saveresult

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	pullImage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	scanVuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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

func (s *ScanResultHandle) transSeverityInt(level string) int {
	switch level {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN":
		return 1
	default:
		return 0
	}
}

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

func (s *ScanResultHandle) defaultEnvFill(scanDetails *model.ScanDetailScanImage, param jobs.Param) {
	configJSON, ok := param["configJson"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'configJson' in parameter")
		return
	}

	config := model.ConfigFile{}
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		logging.GetLogger().Err(err).Msg("ScanEnv can't unmarshal configJson")
		return
	}
	envs := component.ParseConfigEnv(config.Config.Env)
	if len(envs) != 0 {
		scanDetails.EnvDetails = append(scanDetails.EnvDetails, envs...)
	}
}

func (s *ScanResultHandle) AddRHSAAndCnnvd(vulnDetails *model.SingleScanDetail, vulnDetail model.NewVulnDetail, flag int) {
	tmpDetail := vulnDetail
	rhsaFlag := 0
	for _, v := range vulnDetail.Trivy[0].References {
		if strings.Contains(v, "/errata/RHSA") {
			index := strings.LastIndex(v, "/")
			tmpDetail.CVEID = v[index+1:]
			rhsaFlag = 1
			break
		}
	}
	if flag == 0 {
		if rhsaFlag == 1 {
			vulnDetails.Vulns = append(vulnDetails.Vulns, tmpDetail)
		}
		if tmpDetail.Cnnvd.Number != "" {
			tmpDetail.CVEID = tmpDetail.Cnnvd.Number
			vulnDetails.Vulns = append(vulnDetails.Vulns, tmpDetail)
		}
	}
}

func (s *ScanResultHandle) arrangeVulnDetails(trivyReport *report.Report, layers []string, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	vulnQuery := scanVuln.GetScannerVuln()
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
				s.AddRHSAAndCnnvd(&scanDetails.VulnDetails[i], *trivyDetail, 0)
				continue
			}
			trivyDetail.CVEID = k
			trivyDetail.Cnnvd = tmpDetail.Cnnvd
			trivyDetail.Cnvd = tmpDetail.Cnvd
			s.AddRHSAAndCnnvd(&scanDetails.VulnDetails[i], *trivyDetail, 0)
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
				if trivyVvuln.Layer.Digest == "" {
					continue
				}
				_, ok := layerMp[trivyVvuln.Layer.Digest]
				if !ok {
					logging.GetLogger().Warn().Msgf("Maybe layer Error layer Digest:%v", trivyVvuln.Layer.Digest)
					continue
				}
				if len(layerMp[trivyVvuln.Layer.Digest].VulnDetails) <= i {
					logging.GetLogger().Warn().Msgf("Maybe Result len Error layerMpLen:%v,i:%v", len(layerMp[trivyVvuln.Layer.Digest].VulnDetails), i)
					continue
				}
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

func (s *ScanResultHandle) logPostgresLayer(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) {
	scannerOrm := store.GetScannerDb()
	for k, v := range layerMp {
		tmpScanLayer := model.ScanLayer{ImageID: imageID}
		tmpScanLayer.LayerDigest = k
		if v.VulnDetails != nil {
			var tmpSingleDetails []model.SingleScanDetail
			for _, t := range v.VulnDetails {
				var tmpVulnDetails []model.NewVulnDetail
				for _, tt := range t.Vulns {
					tmpVulnDetails = append(tmpVulnDetails, *tt)
				}
				tmpSingleDetails = append(tmpSingleDetails, model.SingleScanDetail{Class: t.Class, Type: t.Type, Target: t.Target, Vulns: tmpVulnDetails})
			}
			vulnJSON, err := json.Marshal(tmpSingleDetails)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.VulnInfoJSON = vulnJSON
		}

		if len(v.MaliciousDetails) > 0 {
			maliciousJSON, err := json.Marshal(v.MaliciousDetails)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.MaliciousInfoJSON = maliciousJSON
		}

		if len(v.Sentitives) > 0 {
			sensitiveJSON, err := json.Marshal(v.Sentitives)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.SensitiveFileJSON = sensitiveJSON
		}

		if len(v.WebshellInfos) > 0 {
			webshellJSON, err := json.Marshal(v.WebshellInfos)
			if err != nil {
				logging.GetLogger().Error().Err(err)
			}
			tmpScanLayer.WebshellInfoJSON = webshellJSON
		}

		scannerOrm.InsertToScanLayer(ctx, &tmpScanLayer)
	}
}

func (s *ScanResultHandle) logPostgresImage(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) {
	scannerOrm := store.GetScannerDb()
	tmpScanImage := model.ScanImage{
		ID:                   0,
		ImageID:              imageID,
		RiskScore:            scanDetails.VulnScore + math.Min(40, scanDetails.MaliciousScore+scanDetails.WebShellScore) + scanDetails.SensitiveScore,
		VulnScore:            scanDetails.VulnScore,
		SensitiveScore:       scanDetails.SensitiveScore,
		VirusScore:           scanDetails.MaliciousScore,
		WebshellScore:        scanDetails.WebShellScore,
		VulnInfo:             scanDetails.VulnDetails,
		MaliciousInfo:        scanDetails.MaliciousDetails,
		WebshellInfo:         scanDetails.WebshellInfos,
		SensitiveFile:        scanDetails.Sentitives,
		LicenseInfo:          scanDetails.LicenseDetail,
		Software:             scanDetails.Software,
		EnvKeyValue:          scanDetails.EnvDetails,
		SeverityHistogram:    scanDetails.SeverityHistogram,
		ScanEnableCollection: scanDetails.ScanEnableCollection,
		HasFixedVuln:         scanDetails.HasFixedVuln,
		Status:               model.ScanStatusSucceeded,
	}

	tmpScanImage.Serialize()
	if err := scannerOrm.InsertToScanImage(ctx, &tmpScanImage); err != nil {
		logging.GetLogger().Err(err).Int64("imageID", tmpScanImage.ImageID).Msg("save scan result InsertToScanImage")
		return
	}
	// 更改imagelist表
	if err := s.UpdateImageFlag(ctx, tmpScanImage.ImageID, &tmpScanImage); err != nil {
		logging.GetLogger().Err(err).Int64("imageID", tmpScanImage.ImageID).Msg("save scan result UpdateImageFlag")
		return
	}
}

func (s *ScanResultHandle) UpdateImageFlag(ctx context.Context, imageID int64, scan *model.ScanImage) error {
	imageDal := store.GetScannerOrmDb()

	image, _, err := imageDal.SearchImage(ctx, store.SearchImageParam{InIds: []int64{imageID}, Fields: []string{"id", "flag"}}, nil)
	if err != nil {
		return err
	}
	if len(image) == 0 {
		return fmt.Errorf("not find image:%d", imageID)
	}
	updater := map[string]interface{}{"flag": scan.GenImageFlag(image[0].Flag)}
	err = imageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater, nil)
	return err
}

func (s *ScanResultHandle) logPostgresVuln(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) {
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
				mateDateJSON, err := json.Marshal(tmpMate)
				if err != nil {
					logging.GetLogger().Error().Err(err)
				}
				linkjson, err := json.Marshal(trivyVuln.References)
				if err != nil {
					logging.GetLogger().Error().Err(err)
				}

				tmpVuln := model.Vuln{Name: vuln.CVEID, Namespace: v.Type, Target: v.Target, Description: trivyVuln.Description,
					MetadataJSON: mateDateJSON, PkgName: trivyVuln.PkgName, PkgVersion: trivyVuln.InstalledVersion,
					LinkJSON: linkjson, FixedBy: trivyVuln.FixedVersion, Severity: trivyVuln.Severity, SeverityInt: s.transSeverityInt(trivyVuln.Severity)}
				err = scannerOrm.InsertToVuln(ctx, &tmpVuln, imageID)
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("InsertoVuln failed ")
				}
			}
		}
	}
}

func (s *ScanResultHandle) logPostgresWebFrame(ctx context.Context, param jobs.Param) {
	jobURL, ok := param["url"].(string)
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
	scanResult, ok := param["scanResult"].(map[task.ScanType]interface{})
	if !ok {
		logging.GetLogger().Error().Msg("miss 'scanResult' in parameter")
		return
	}

	scanMalicious, ok := scanResult["scan-malicious"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-malicious' in parameter")
		return
	}
	scanWebFrame, ok := scanMalicious["webFrame"].([]model.WebFrameInfo)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'webFrame' in parameter")
		return
	}
	if len(scanWebFrame) == 0 {
		return
	}
	var err error
	url := strings.TrimPrefix(jobURL, "http://") // trimPrefix http or https
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimRight(url, "/")
	imageID := fmt.Sprintf("%s/%s:%s", url, jobRepo, jobTag)
	imageUUID := util.GenerateUUID(imageID)
	tmpWebFrame := model.WebFrameScan{}
	tmpWebFrame.ImageUUID = imageUUID
	tmpWebFrame.WebFrameInfoJSON, err = json.Marshal(scanWebFrame)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("marshal scanWebFram error")
		return
	}
	scannerOrm := store.GetScannerDb()
	err = scannerOrm.InsertToWebFrame(ctx, &tmpWebFrame)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("log postgres Web_Frame failed")
	}
}

func (s *ScanResultHandle) updateRiskVulnCacheEntry(ctx context.Context, param jobs.Param, scanDetails *model.ScanDetailScanImage) {
	jobURL, ok := param["url"].(string)
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

	url := strings.Replace(jobURL, "https://", "", 1)
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
	jobURL, ok := param["url"].(string)
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

	url := strings.Replace(jobURL, "https://", "", 1)
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
		s.defaultEnvFill(&scanDetails, param)
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

	s.logPostgresLayer(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	s.logPostgresImage(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	s.logPostgresVuln(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	s.updateRiskVulnCacheEntry(ctx, param, &scanDetails)
	s.updateRiskVirusCacheEntry(ctx, param, &scanDetails)
	s.logPostgresWebFrame(ctx, param)
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		if imageName, ok := param["imageName"]; ok {
			if im, ok := imageName.(string); ok {
				if err := rmImage(im); err != nil {
					logging.GetLogger().Err(err).Str("imageName", im).Msg("docker rm image")
				}
			}
		}
		return nil, nil
	}
	_, ok = param["pullImageJob"].(pullImage.Config)
	if ok {
		client1, err := imageCache.NewLocalLayerManageClientT("/layer")
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

func rmImage(imageName string) error {
	osCmd := exec.Command("docker", "rmi", imageName)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("scan-image docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	logging.GetLogger().Info().Msgf("scan-image docker delete image：%s", imageName)

	return nil
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
