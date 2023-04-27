package saveresult

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	pullImage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/pull-image"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
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
	config   Config
	MqWriter mq.Writer
	PvcPath  string
}

var (
	webshellNineToTen  = 40.0
	webshellSixToEight = 30.0
	webshellFourToFive = 20.0
	maxVulnscore       = 50.0
)

func GenSensitiveScore(num int64) float64 {
	res := 5 * num
	if res > 10 {
		return 10
	}
	return float64(res)
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

	for i := range imageSensitive {
		if !strings.HasPrefix(imageSensitive[i].Name, "/") {
			imageSensitive[i].Name = "/" + imageSensitive[i].Name
		}
	}

	scanDetails.Sentitives = imageSensitive
	scanDetails.SensitiveScore = GenSensitiveScore(int64(imageSensitiveLen))
}

func (s *ScanResultHandle) arrangeWebshell(webshellInfoReuslt scannermodel.WebshellResult, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail) {
	for _, v := range webshellInfoReuslt.FileInfos {
		_, ok := layerMp[v.LayerDigest]
		if ok {
			layerMp[v.LayerDigest].WebshellInfos = append(layerMp[v.LayerDigest].WebshellInfos, v.Md5Hash)
		} else {
			layerMp[v.LayerDigest] = &model.LayerScanDetail{}
			layerMp[v.LayerDigest].WebshellInfos = append(layerMp[v.LayerDigest].WebshellInfos, v.Md5Hash)
		}
	}
	if len(webshellInfoReuslt.FileInfos) > 0 {
		scanDetails.WebShellScore += 30
	}
	scanDetails.WebshellInfos = webshellInfoReuslt.FileInfos

}

func (s *ScanResultHandle) arrangeEnv(envReuslt []model.EnvKeyValue, scanDetails *model.ScanDetailScanImage) {
	scanDetails.EnvDetails = append(scanDetails.EnvDetails, envReuslt...)
}

func (s *ScanResultHandle) arrangeLicense(licenseResult []model.PerLayerLicenseResult, scanDetails *model.ScanDetailScanImage) {
	for _, v := range licenseResult {
		scanDetails.LicenseDetail = append(scanDetails.LicenseDetail, v.LicenseInfos...)
	}
}

func (s *ScanResultHandle) logPostgresLayer(ctx context.Context, layerMp map[string]*model.LayerScanDetail, imageID int64) error {
	scannerOrm := store.GetScannerDb()
	var err error
	for layerDigest, layer := range layerMp {
		scanLayer := model.ScanLayer{
			ImageID:       imageID,
			LayerDigest:   layerDigest,
			VulnInfo:      layer.Vulns,
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

func (s *ScanResultHandle) logPostgresWebshell(ctx context.Context, scanDetails *model.ScanDetailScanImage, layerMp map[string]*model.LayerScanDetail, imageID int64) error {
	scannerOrm := store.GetSingeWebsehllDao()
	webshells := []scannermodel.Webshell{}
	for k, _ := range scanDetails.WebshellInfos {
		webshells = append(webshells, scanDetails.WebshellInfos[k].TransToWebshell())
	}
	err := scannerOrm.CreateWebshell(ctx, webshells)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("create webshell error")
		return err
	}
	err = scannerOrm.CreateWebshellImage(ctx, imageID, webshells)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("create webshellImage error")
		return err
	}
	return nil
}

func (s *ScanResultHandle) logPostgresScanImageResult(ctx context.Context, scanDetails *model.ScanDetailScanImage, imageID int64) error {
	scannerOrm := store.GetScannerDb()
	tmpScanImage := &model.ScanImage{
		ID:                   0,
		ImageID:              imageID,
		RiskScore:            scanDetails.VulnScore + math.Min(40, scanDetails.MaliciousScore+scanDetails.WebShellScore) + scanDetails.SensitiveScore,
		VulnScore:            scanDetails.VulnScore,
		SensitiveScore:       scanDetails.SensitiveScore,
		VirusScore:           scanDetails.MaliciousScore,
		WebshellScore:        scanDetails.WebShellScore,
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
	afterFlag := scan.GenImageFlag(image[0].Flag)
	updater := map[string]interface{}{"flag": afterFlag}
	return imageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater, nil)
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

func (s *ScanResultHandle) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {

	var (
		imageScanVirus      []model.PerLayerMaliciousResult
		imageScanSensitive  []model.PerLayerSensitiveResult
		imageScanEnv        []model.EnvKeyValue
		imageScanSoftware   []model.Software
		imageScanVulnResult *report.Report // 漏洞
	)

	imageID := s.config.subtask.Image.ID

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
			imageScanVirus = maliciousResult
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
			imageScanSensitive = sensitivesResult
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
		webshellResult, ok := scanWebshell["result"].(scannermodel.WebshellResult)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'webshellResult' in parameter")
		} else {
			// imageScanWebshell = webshellResult
			s.arrangeWebshell(webshellResult, &scanDetails, layerMp)
		}
	}

	// 整合Env
	scanEnv, ok := scanResult["scan-env"].(scan.Artifact)
	if !ok {
		s.defaultEnvFill(&scanDetails, param)
		logging.GetLogger().Warn().Msg("miss 'scan-env' in parameter")
		// fixme 糟糕的写法
		imageScanEnv = scanDetails.EnvDetails
	} else {
		envReuslt, ok := scanEnv["result"].([]model.EnvKeyValue)
		if !ok {
			logging.GetLogger().Error().Msg("miss 'envReuslt' in parameter")
		} else {
			imageScanEnv = envReuslt
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
	// 不合规软件
	vulnResult, ok := scanResult["scan-vuln"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-vuln' in parameter")
	} else {
		if software, ok := vulnResult["software"].([]model.Software); ok {
			imageScanSoftware = software
		}
	}

	scanResultSaveSrv := NewScanResultSave()

	imageName, ok := param["imageName"].(string)
	if !ok {
		imageName = ""
	}

	vulnResult, ok = scanResult["scan-vuln"].(scan.Artifact)
	if !ok {
		logging.GetLogger().Warn().Msg("miss 'scan-vuln' in parameter")
	} else {
		trivyReport, ok := vulnResult["result"].(*report.Report)
		if !ok || trivyReport == nil {
			logging.GetLogger().Error().Msg("miss 'result' in parameter")
		} else {
			imageScanVulnResult = trivyReport
		}
	}
	// if imageName != "" {
	// 	if err := scanResultSaveSrv.UpdateRiskCacheEntry(ctx, fmt.Sprintf("riskexp-image-virus-%s", imageName),
	// 		model.SeverityHistogramInfo{NumCritical: int64(len(scanDetails.MaliciousDetails))}); err != nil {
	// 		logging.GetLogger().Err(err).Msg("UpdateRiskCacheEntry")
	// 	}
	// }

	// 保存漏洞
	if imageScanVulnResult != nil {
		vulns, vulnImages := ConvertVuln(imageID, *imageScanVulnResult)

		logging.GetLogger().Info().Int("data", len(vulns)).Msg("save-result ConvertVuln")
		// 存漏洞数据
		for i := range vulns {
			vulns[i] = scanResultSaveSrv.AddVulnMeta(ctx, vulns[i])
		}

		if err := scanResultSaveSrv.VulnDal.CreateVuln(ctx, vulns); err != nil {
			logging.GetLogger().Err(err).Msg("CreateVuln")
		}

		if err := scanResultSaveSrv.VulnDal.CreateVulnImage(ctx, imageID, vulnImages); err != nil {
			logging.GetLogger().Err(err).Msg("CreateVulnImage")
		}

		// 更新os信息
		if err := scanResultSaveSrv.UpdateImageOs(ctx, imageScanVulnResult.Metadata.OS, s.config.subtask.Image.ID); err != nil {
			logging.GetLogger().Err(err).Msg("updateImageOs")
		}

		// 漏洞层级信息（原来的逻辑，暂时不删除）
		for i := range vulnImages {
			if layerMp[vulnImages[i].LayerDigest].Vulns == nil {
				layerMp[vulnImages[i].LayerDigest].Vulns = make([]uint64, 0)
			}
			layerMp[vulnImages[i].LayerDigest].Vulns = append(layerMp[vulnImages[i].LayerDigest].Vulns, vulnImages[i].UniqueVuln)
		}

		// scanImage数据，以供保存（原来的逻辑，暂时不删除）
		scanDetails.VulnScore = scanResultSaveSrv.GenVulnScore(ctx, vulns)
		scanDetails.SeverityHistogram = scanResultSaveSrv.GenSeverityHistogram(ctx, vulns)
	}

	// 敏感文件
	if imageScanSensitive != nil {
		data, issueToImages := ConvertSensitive(imageID, imageScanSensitive)
		if err := scanResultSaveSrv.ImageScanResultDal.CreateSensitive(ctx, data); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateSensitive")
		}
		if err := scanResultSaveSrv.ImageScanResultDal.CreateScanSensitiveToImage(ctx, imageID, issueToImages); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateSensitive CreateScanIssueToImage")
		}
	}

	// 病毒
	if imageScanVirus != nil {
		data, issueToImages := ConvertVirus(imageID, imageScanVirus)
		if err := scanResultSaveSrv.ImageScanResultDal.CreateVirus(ctx, data); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateVirus")
		}
		if err := scanResultSaveSrv.ImageScanResultDal.CreateScanVirusToImage(ctx, imageID, issueToImages); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateVirus CreateScanIssueToImage")
		}
	}

	// ENV
	if imageScanEnv != nil {
		data := ConvertEnv(imageID, imageScanEnv)
		if err := scanResultSaveSrv.ImageScanResultDal.CreateImageEnv(ctx, imageID, data); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateImageEnv")
		}
	}

	// Soft
	if imageScanSoftware != nil {
		data, issueToImages := ConvertSoftware(imageID, imageScanSoftware)
		logging.GetLogger().Info().Int("data", len(data)).Int64("imageID", imageID).Int("issueToImages", len(issueToImages)).Msg("imageScanSoftware")
		if err := scanResultSaveSrv.ImageScanResultDal.CreateSoftware(ctx, data); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateSoftware")
		}
		if err := scanResultSaveSrv.ImageScanResultDal.CreateSoftwareToImage(ctx, imageID, issueToImages); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("CreateLicense CreateScanIssueToImage")
		}

		// 把异常license和异常soft存入scanImage表中兼容之前的逻辑
		licenseAdd := make(map[string]bool)
		for i := range imageScanSoftware {
			if imageScanSoftware[i].AbnormalSoft {
				scanDetails.Software = append(scanDetails.Software, imageScanSoftware[i])
			}
			if imageScanSoftware[i].AbnormalLicense && !licenseAdd[imageScanSoftware[i].License] {
				scanDetails.LicenseDetail = append(scanDetails.LicenseDetail, model.LicenseInfo{Name: imageScanSoftware[i].License})
				licenseAdd[imageScanSoftware[i].License] = true
			}
		}
	}

	var err error
	// err = s.logPostgresLayer(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	// // 先写漏洞表和漏洞关联表，再写入ivan_scanner_scan_images和ivan_scanner_images_list表，防止镜像已打上有漏洞的标记，确查不出漏洞的情况
	// err = s.logPostgresVuln(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	// err = s.logPostgresImage(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	err = s.logPostgresWebshell(ctx, &scanDetails, layerMp, s.config.subtask.Image.ID)
	if os.Getenv("IS_MAIN_CLUSTER") != "true" {
		for _, v := range scanDetails.WebshellInfos {
			saveInfo := scannermodel.WebshellSaveInfo{}
			tmpData, err := os.ReadFile(v.FilePath)
			if err != nil {
				logging.GetLogger().Err(err).Msg("Read file error")
				continue
			}
			saveInfo.FileMd5 = v.Md5Hash
			saveInfo.Data = tmpData
			saveByte, err := json.Marshal(saveInfo)
			if err != nil {
				logging.GetLogger().Err(err).Msg("marshal Webshell Save Info error")
				continue
			}
			logging.GetLogger().Info().Msgf("%v send to kafka", v.Md5Hash)
			err = Send2Kafka(s.MqWriter, saveByte)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("%v send to kafka error", v.Md5Hash)
			}
		}
	} else {
		for _, v := range scanDetails.WebshellInfos {
			tmpData, err := os.ReadFile(v.FilePath)
			if err != nil {
				logging.GetLogger().Err(err).Msg("Read Webshell File error")
				continue
			}
			err = s.saveWebshell(v.Md5Hash, tmpData)
			if err != nil {
				logging.GetLogger().Err(err).Msg("save Webshell File error")
				continue
			}
		}
	}

	err = s.logPostgresLayer(ctx, layerMp, s.config.subtask.Image.ID)

	// 先写漏洞表和漏洞关联表，再写入ivan_scanner_scan_images和ivan_scanner_images_list表，防止镜像已打上有漏洞的标记，确查不出漏洞的情况
	err = s.logPostgresScanImageResult(ctx, &scanDetails, s.config.subtask.Image.ID)

	// 把漏洞统计写入redis，风险探索使用
	if imageName != "" {
		if err := scanResultSaveSrv.UpdateRiskCacheEntry(ctx, fmt.Sprintf("riskexp-image-vulns-%s", imageName), model.ImageSeverityScore{
			RiskScore: 100 - (int64(scanDetails.VulnScore + math.Min(40, scanDetails.MaliciousScore+scanDetails.WebShellScore) + scanDetails.SensitiveScore))}); err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("UpdateRiskCacheEntry")
		}
	}

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

func (s *ScanResultHandle) createFile(name string) (*os.File, error) {
	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
	if err != nil {
		return nil, err
	}
	return os.Create(name)
}

func init() {
	logging.GetLogger().Info().Msgf("want to register job :%v", JobName)
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Err(err).Str("jobName", JobName).Msg("init job err")
	}
}

func (s *ScanResultHandle) PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (s *ScanResultHandle) saveWebshell(fileMd5 string, data []byte) error {
	dstPath := filepath.Join(s.PvcPath, "webshell", fileMd5)
	if s.PathExists(dstPath) {
		return nil
	}
	tmpFs, err := s.createFile(dstPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create webshell file error")
		return err
	}
	_, err = io.Copy(tmpFs, bytes.NewReader(data))
	if err != nil {
		logging.GetLogger().Err(err).Msg("copy webshell file error")
		return err
	}
	return nil
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &ScanResultHandle{}
	mqFactory := mq.GetClientFactory()
	mqWriter, err := mqFactory.Writer(context.Background())
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init mq error")
	}
	i.MqWriter = mqWriter
	i.config.task = config.Info.Task
	i.config.subtask = config.Info.SubTask
	i.PvcPath = global.ScannerOpts.PvcPath
	return i, nil
}
