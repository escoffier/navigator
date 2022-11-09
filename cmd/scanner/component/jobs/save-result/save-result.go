package saveresult

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	pullImage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	scanVuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	JobName = "save-result"
)

var (
	compile = regexp.MustCompile("/errata/(RHSA-[0-9]+[-:][0-9]+)")
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
		vulnType := os.Getenv("RISK_OVERVIEW_VULN_TYPE")
		if len(vulnType) > 0 {
			typeList := strings.Split(vulnType, ",")
			if !util.ContainsString(typeList, reuslts.Class) {
				continue
			}
		}

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

// 对于redhat下的漏洞，做特殊处理,详情见以下：
// https://access.redhat.com/errata-search/#/
// https://access.redhat.com/errata/RHBA-2022:6141
// https://access.redhat.com/errata/RHSA-2022:6103
func (s *ScanResultHandle) AddRHSAAndCnnvd(vulnDetails *model.SingleScanDetail, vulnDetail model.NewVulnDetail) {
	vuln := vulnDetail
	for i := range vulnDetail.Trivy {
		for j := range vulnDetail.Trivy[i].References {
			ref := vulnDetail.Trivy[i].References[j]
			sub := compile.FindStringSubmatch(ref)
			if len(sub) == 2 {
				vuln.CVEID = sub[1]
				vulnDetails.Vulns = append(vulnDetails.Vulns, vuln)
			}
		}
	}
	if vuln.Cnnvd.Number != "" {
		vuln.CVEID = vuln.Cnnvd.Number
		vulnDetails.Vulns = append(vulnDetails.Vulns, vuln)
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
				s.AddRHSAAndCnnvd(&scanDetails.VulnDetails[i], *trivyDetail)
				continue
			}
			trivyDetail.CVEID = k
			trivyDetail.Cnnvd = tmpDetail.Cnnvd
			trivyDetail.Cnvd = tmpDetail.Cnvd
			s.AddRHSAAndCnnvd(&scanDetails.VulnDetails[i], *trivyDetail)
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

func (s *ScanResultHandle) logPostgresLayer(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) error {
	scannerOrm := store.GetScannerDb()
	var err error
	for layerDigest, layer := range layerMp {

		var uniqueVulns []uint64

		if layer.VulnDetails != nil {
			for _, t := range layer.VulnDetails {
				for _, tt := range t.Vulns {
					for _, vu := range tt.Trivy {
						vuln := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, tt.CVEID, vu.PkgName, vu.InstalledVersion))
						// 因为结构体里的嵌套结构都是值引用，可能会有空的情况
						if vuln > 0 {
							uniqueVulns = append(uniqueVulns, vuln)
						}
					}
				}
			}
		}

		scanLayer := model.ScanLayer{
			ImageID:       imageID,
			LayerDigest:   layerDigest,
			VulnInfo:      uniqueVulns,
			MaliciousInfo: layer.MaliciousDetails,
			WebshellInfo:  layer.WebshellInfos,
			SensitiveFile: layer.Sentitives,
		}

		err = scannerOrm.InsertToScanLayer(ctx, &scanLayer)
		if err != nil {
			// 一条出错，不影响其他的数据写入
			logging.GetLogger().Err(err).Str("LayerDigest", scanLayer.LayerDigest).Int64("imageID", scanLayer.ImageID).Msg("save scan result InsertToScanLayer")
		}
	}
	return err
}

func (s *ScanResultHandle) logPostgresImage(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) error {
	scannerOrm := store.GetScannerDb()
	tmpScanImage := &model.ScanImage{
		ID:             0,
		ImageID:        imageID,
		RiskScore:      scanDetails.VulnScore + math.Min(40, scanDetails.MaliciousScore+scanDetails.WebShellScore) + scanDetails.SensitiveScore,
		VulnScore:      scanDetails.VulnScore,
		SensitiveScore: scanDetails.SensitiveScore,
		VirusScore:     scanDetails.MaliciousScore,
		WebshellScore:  scanDetails.WebShellScore,
		// VulnInfo:             scanDetails.VulnDetails,
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

	if err := scannerOrm.InsertToScanImage(ctx, tmpScanImage); err != nil {
		logging.GetLogger().Err(err).Int64("imageID", tmpScanImage.ImageID).Msg("save scan result InsertToScanImage")
		return err
	}
	// 更改imagelist表
	if err := s.UpdateImageFlag(ctx, tmpScanImage.ImageID, tmpScanImage); err != nil {
		logging.GetLogger().Err(err).Int64("imageID", tmpScanImage.ImageID).Msg("save scan result UpdateImageFlag")
		return err
	}
	return nil
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

func (s *ScanResultHandle) logPostgresVuln(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) error {
	vulnDal := store.GetSingeVulnDao()

	vulns := make([]*model.Vuln, 0, 20)
	vulnImages := make([]*model.VulnImage, 0, 20)

	for _, v := range scanDetails.VulnDetails {
		for _, vuln := range v.Vulns {
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

				vu := &model.Vuln{
					Target:      v.Target,
					Name:        vuln.CVEID,
					Namespace:   strings.ToLower(v.Type),
					Description: trivyVuln.Description,
					Link:        trivyVuln.References,
					Severity:    trivyVuln.Severity,
					SeverityInt: model.GetSeverityInt(trivyVuln.Severity),
					Metadata:    &tmpMate,
					PkgName:     trivyVuln.PkgName,
					PkgVersion:  trivyVuln.InstalledVersion,
					FixedBy:     trivyVuln.FixedVersion,
					Class:       v.Class,
				}

				vulns = append(vulns, vu)
				vulnImages = append(vulnImages, &model.VulnImage{ImageId: imageID, UniqueVuln: vu.GenUniqueVuln()})
			}
		}
	}

	if err := vulnDal.CreateVuln(ctx, vulns); err != nil {
		// 部分写入失败后还是要写入ivan_scanner_vuln_images表数据，所以不能直接返回
		logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("save-result CreateVuln")
	}

	if err := vulnDal.CreateVulnImage(ctx, imageID, vulnImages); err != nil {
		logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("save-result CreateVulnImage")
		return err
	}
	return nil
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
		logging.GetLogger().Err(err).Msg("marshal scanWebFram error")
		return
	}
	scannerOrm := store.GetScannerDb()
	err = scannerOrm.InsertToWebFrame(ctx, &tmpWebFrame)
	if err != nil {
		logging.GetLogger().Err(err).Msg("log postgres Web_Frame failed")
	}
}

func (s *ScanResultHandle) updateRiskVulnCacheEntry(ctx context.Context, param jobs.Param, scanDetails *model.ScanDetailScanImage) {
	jobURL, ok := param["url"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'url' in parameter")
		return
	}
	jobTag, ok := param["tag"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'tag' in parameter")
		return
	}
	jobRepo, ok := param["repoName"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'repoName' in parameter")
		return
	}

	data := model.ImageRiskOverRedis{
		Key: fmt.Sprintf("riskexp-image-vulns-%s/%s:%s",
			strings.Replace(strings.Replace(jobURL, "https://", "", 1), "http://", "", 1), jobRepo, jobTag),
		Data: model.ImageRiskOver{
			CriticalNum: scanDetails.SeverityHistogram.NumCritical,
			HighNum:     scanDetails.SeverityHistogram.NumHigh,
			MediumNum:   scanDetails.SeverityHistogram.NumMedium,
			LowNum:      scanDetails.SeverityHistogram.NumLow,
			UnknownNum:  scanDetails.SeverityHistogram.NumUnknown,
		},
	}
	if err := s.SetRedisData(ctx, data); err != nil {
		logging.GetLogger().Err(err).Msg("updateRiskVulnCacheEntry SetRedisData")
	}
}

func (s *ScanResultHandle) updateRiskVirusCacheEntry(ctx context.Context, param jobs.Param, scanDetails *model.ScanDetailScanImage) {
	jobURL, ok := param["url"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'url' in parameter")
		return
	}
	jobTag, ok := param["tag"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'tag' in parameter")
		return
	}
	jobRepo, ok := param["repoName"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("SetRedisData miss 'repoName' in parameter")
		return
	}

	data := model.ImageRiskOverRedis{
		Key: fmt.Sprintf("riskexp-image-virus-%s/%s:%s",
			strings.Replace(strings.Replace(jobURL, "https://", "", 1), "http://", "", 1), jobRepo, jobTag),
		Data: model.ImageRiskOver{CriticalNum: int64(len(scanDetails.MaliciousDetails))},
	}
	if err := s.SetRedisData(ctx, data); err != nil {
		logging.GetLogger().Err(err).Msg("updateRiskVirusCacheEntry SetRedisData")
	}
}

func (s *ScanResultHandle) updateImageOs(ctx context.Context, os *ftypes.OS, imageId int64) error {
	orm := store.GetScannerOrmDb()

	if os == nil {
		return fmt.Errorf("not get os info for image:%d", imageId)
	}

	bys, err := json.Marshal(os)
	if err != nil {
		return err
	}
	update := map[string]interface{}{"os": string(bys)}

	if err := orm.UpdateImage(ctx, fmt.Sprintf("id = %d", imageId), update, nil); err != nil {
		return err
	}
	return nil
}

func (s *ScanResultHandle) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {

	// get scan result from param
	r := make(map[string]interface{})
	scanResult, ok := param["scanResult"].(map[task.ScanType]interface{})
	if !ok {
		logging.GetLogger().Error().Msg("miss 'scanResult' in parameter")
		r["pullFailed"] = true
		return r, errors.New("miss 'scanResult' in parameter")
	}

	layers, ok := param["layers"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layersFilePath' in parameter")
		r["pullFailed"] = true
		return r, errors.New("miss 'layersFilePath' in parameter")
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
		// 更新os信息
		if err := s.updateImageOs(ctx, trivyReport.Metadata.OS, s.config.subtask.Image.ID); err != nil {
			logging.GetLogger().Err(err).Msg("updateImageOs")
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
	var err error

	err = s.logPostgresLayer(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	// 先写漏洞表和漏洞关联表，再写入ivan_scanner_scan_images和ivan_scanner_images_list表，防止镜像已打上有漏洞的标记，确查不出漏洞的情况
	err = s.logPostgresVuln(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	err = s.logPostgresImage(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
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
			logging.GetLogger().Err(err).Msg("delete layers Failed!")
		} else {
			for k := range layers {
				err := client1.DeleteLayer(layers[k])
				if err != nil {
					logging.GetLogger().Err(err).Msgf("delete layer %v Failed", layers[k])
				}
			}
		}
	}

	return nil, err
}

func rmImage(imageName string) error {
	osCmd := exec.Command("docker", "rmi", imageName)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan-image docker delete image：%s:%v", imageName, osCmd.Args)
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
