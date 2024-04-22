package kafkaScan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultReportSrv struct {
	taskDal         imagesecStore.ScanTaskDal
	imageDal        imagesecStore.ImageMetaDal
	scanResultDal   imagesecStore.ScanResultDal
	issueDal        imagesecStore.ScanIssueDal
	versionDal      imagesecStore.ScanDbMetaDal
	mqReader        mq.Reader
	vulnMatcher     VulnMatcher
	redisCli        *redis.Client
	imageDetectSrv  ImageDetectTaskService
	detectImageChan chan DetectImageData
	OnlineVulnChan  chan []*imagesecModel.Vuln
	Log             *scannerUtils.LogEvent
}

type DetectImageData struct {
	ImageUniqueID uint64
	SubtaskID     int64
	CreatedAt     int64
	// AllInCache    bool
	// 本来想着做一步优化，但是会引入一个问题：
	// 对于老版本的集群，是扫描器扫描后，直接写数据库保存漏洞等数据，然后把其他结果发送kafka
	// 如果在写入数据库后，发送 kafka失败，就不会执行后续检测逻辑，此时就会出现一种情况是：有扫描数据，但是安全状态还是未知
	// 鉴于我们的 kafka 及数据库经常重启,需要做一下兼容。
	// 镜像表中的flag 字段保存很多信息，但是 flag 的更新逻辑是，读取数据->计算值->再更新回数据库，这种方式难免会有数据更新冲突，
	// 解决办法是用事务，因为更新 flag 是一个很频繁的操作，如果用事务会严重影响性能
	// 对于上面这种情况，即使所有数据在缓存中，也要重新检测
}

func (s *ScanResultReportSrv) matchVuln(ctx context.Context, data *imagesecTypes.ReportScanResult) (report.Results, error) {
	results := make(report.Results, 0)
	for i := range data.OriginArtifact {
		// match vuln by image artifact
		rp, err := s.vulnMatcher.MatchVuln(ctx, data.OriginArtifact[i])
		if err != nil {
			s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
				Msg("failed to match vuln")
			return nil, err
		}
		results = append(results, rp...)

	}

	return results, nil
}

func (s *ScanResultReportSrv) CreateScanResult(ctx context.Context, data imagesecTypes.ReportScanResult) error {
	if err := s.UpdateSubtaskScanFinished(ctx, data); err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Msg("UpdateSubtaskScanFinished")
		return err
	}
	image, err := s.GetImageInfo(ctx, data.TaskID, data.SubTaskID)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("GetImageInfo")
		return err
	}

	correlate := &imagesecModel.ImageWithCorrelateData2{Image: image}

	correlate.Image.OS = data.OS
	if !data.IgnoreVulnPkg {
		// fixme 如果都是老集群，漏洞发现就没有数据
		vulns, _ := s.CreatePkgVuln(ctx, &data, correlate)
		// 在线镜像的漏洞
		if util.ExistBit1(image.Flag, imagesecModel.FlagImageOnline) {
			go func() { s.OnlineVulnChan <- vulns }()
		}
	}

	_ = s.CreateSensitive(ctx, data, correlate)
	_ = s.CreateMalware(ctx, data, correlate)
	_ = s.CreateWebshell(ctx, data, correlate)
	_ = s.CreateLicense(ctx, data, correlate)
	_ = s.CreateWebFrameInfo(ctx, data)

	go func() { _ = s.SetRiskScore(ctx, correlate) }()

	go func() { _ = s.UpdateImage(ctx, image.ID, correlate) }()

	go func() {
		dd := DetectImageData{
			ImageUniqueID: image.UniqueID,
			SubtaskID:     data.SubTaskID,
			CreatedAt:     time.Now().UnixMilli(),
		}
		s.detectImageChan <- dd
	}()

	// 存入缓存信息
	go func() { _ = s.CreateScanLayer(ctx, &data, correlate) }()

	s.Log.Info().Str("result", data.LogStr()).
		Str("image", image.GetImageName()).
		Msg("get scan result and create succeed")

	return nil
}

func (s *ScanResultReportSrv) CreateScanLayer(ctx context.Context, data *imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) error {

	license := make(map[string]imagesecModel.ScanLayerData)
	malware := make(map[string]imagesecModel.ScanLayerData)
	webshell := make(map[string]imagesecModel.ScanLayerData)
	sensitive := make(map[string]imagesecModel.ScanLayerData)
	vuln := make(map[string]imagesecModel.ScanLayerData)
	pkg := make(map[string]imagesecModel.ScanLayerData)

	for i := range data.VulnCache {
		v := data.VulnCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := vuln[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.Vuln,
				Layer:     v.Layer,
				Issue:     imagesecModel.VulnCacheData,
			}
			ca.SetEmpty()
			vuln[v.Layer] = ca
		}

		for j := range correlate.Vuln {
			lic := correlate.Vuln[j]
			ca := vuln[v.Layer]
			ca.Vuln = append(ca.Vuln, &imagesecModel.Vuln{UniqueID: lic.UniqueID})
			vuln[v.Layer] = ca
		}
	}

	for i := range data.VulnCache {
		v := data.VulnCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := pkg[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.Vuln,
				Layer:     v.Layer,
				Issue:     imagesecModel.PKGCacheData,
			}
			ca.SetEmpty()
			pkg[v.Layer] = ca
		}

		for j := range correlate.Pkg {
			lic := correlate.Pkg[j]
			ca := pkg[v.Layer]
			ca.Pkg = append(ca.Pkg, lic)
			pkg[v.Layer] = ca
		}
	}

	for i := range data.LicenseCache {
		v := data.LicenseCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := license[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.License,
				Layer:     v.Layer,
				Issue:     imagesecModel.LicenseCacheData,
			}
			ca.SetEmpty()
			license[v.Layer] = ca
		}

		for j := range correlate.License {
			lic := correlate.License[j]
			if lic.Layer != v.Layer {
				continue
			}

			ca := license[v.Layer]
			ca.License = append(ca.License, lic)
			license[v.Layer] = ca
		}
	}

	for i := range data.WebshellCache {
		v := data.WebshellCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := webshell[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.Webshell,
				Layer:     v.Layer,
				Issue:     imagesecModel.WebshellCacheData,
			}
			ca.SetEmpty()
			webshell[v.Layer] = ca
		}
		for j := range correlate.Webshell {
			lic := correlate.Webshell[j]
			if lic.Layer != v.Layer {
				continue
			}

			ca := webshell[v.Layer]
			ca.Webshell = append(ca.Webshell, lic)
			webshell[v.Layer] = ca
		}
	}

	for i := range data.MalwareCache {
		v := data.MalwareCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := malware[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.Avira,
				Layer:     v.Layer,
				Issue:     imagesecModel.MalwareCacheData,
			}
			ca.SetEmpty()
			malware[v.Layer] = ca
		}

		for j := range correlate.Malware {
			lic := correlate.Malware[j]
			if lic.Layer != v.Layer {
				continue
			}

			ca := malware[v.Layer]
			ca.Malware = append(ca.Malware, lic)
			malware[v.Layer] = ca
		}
	}

	for i := range data.SensitiveCache {
		v := data.SensitiveCache[i]
		if !v.CanInCache {
			continue
		}
		if _, ok := sensitive[v.Layer]; !ok {
			ca := imagesecModel.ScanLayerData{
				DbVersion: data.DBVersion.Sensitive,
				Layer:     v.Layer,
				Issue:     imagesecModel.SensitiveCacheData,
			}
			ca.SetEmpty()
			sensitive[v.Layer] = ca
		}

		for j := range correlate.Sensitive {
			lic := correlate.Sensitive[j]
			if lic.Layer != v.Layer {
				continue
			}

			ca := sensitive[v.Layer]
			ca.Sensitive = append(ca.Sensitive, lic)
			sensitive[v.Layer] = ca
		}
	}

	layerCache := make([]*imagesecModel.ScanLayerData, 0)
	for ly := range license {
		v := license[ly]
		layerCache = append(layerCache, &v)
	}
	for ly := range malware {
		v := malware[ly]
		layerCache = append(layerCache, &v)
	}
	for ly := range sensitive {
		v := sensitive[ly]
		layerCache = append(layerCache, &v)
	}
	for ly := range webshell {
		v := webshell[ly]
		layerCache = append(layerCache, &v)
	}
	for ly := range vuln {
		v := vuln[ly]
		layerCache = append(layerCache, &v)
	}
	for ly := range pkg {
		v := pkg[ly]
		layerCache = append(layerCache, &v)
	}

	// 对于没做版本管理的 job，暂时就用发版时的版本
	sv := os.Getenv("SOFT_VERSION")
	if sv == "" {
		sv = "latest"
	}
	for i := range layerCache {
		if layerCache[i].DbVersion == "" {
			layerCache[i].DbVersion = sv
		}
	}
	if err := s.scanResultDal.CreateScanLayerData(ctx, layerCache); err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Msg("create scan layer data")
		return err
	}

	layerFiles := make([]*imagesecModel.LayerFile, 0)
	for i := range layerCache {
		layerFiles = append(layerFiles, layerCache[i].GenLayerFile()...)
	}
	if err := s.scanResultDal.CreateScanLayerFile(ctx, layerFiles); err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Msg("create scan layer file ")
		return err
	}

	s.Log.Info().Int64("subtaskID", data.SubTaskID).Int("layerCache", len(layerCache)).Msg("create scan layer data")
	return nil
}

func (s *ScanResultReportSrv) CreateScanResultForDataMigrate(ctx context.Context, data imagesecTypes.ReportScanResult) error {

	image := imagesecModel.Image{UniqueID: data.ImageUniqueID}

	correlate := &imagesecModel.ImageWithCorrelateData2{Image: image}
	_ = s.CreateSensitive(ctx, data, correlate)
	_ = s.CreateMalware(ctx, data, correlate)
	_ = s.CreateWebshell(ctx, data, correlate)

	s.Log.Info().Int64("imageID", image.ID).Int64("subtaskID", data.SubTaskID).Msg("succeed")

	return nil
}

func (s *ScanResultReportSrv) UpdateImage(ctx context.Context, imageID int64, data *imagesecModel.ImageWithCorrelateData2) error {

	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{ID: imageID})

	if err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("SearchImage")
		return err
	}
	if len(image) == 0 {
		err = fmt.Errorf("not find image:%d", imageID)
		s.Log.Err(err).Int64("imageID", imageID).Msg("SearchImage")
		return err
	}

	flag := image[0].Flag

	if data.Image.OS.Eosl {
		flag = util.SetBit1(flag, imagesecModel.FlagImageNotMaintained)
	} else {
		flag = util.SetBit0(flag, imagesecModel.FlagImageNotMaintained)
	}

	fixed := false
	// 漏洞统计
	vulnStatic := make(map[int64]bool)
	for i := range data.Vuln {
		if data.Vuln[i].Class == report.ClassOSPkg && data.Vuln[i].FixedVersion != "" && !data.Vuln[i].KernelVuln {
			fixed = true
		}

		si := data.Vuln[i].SeverityInt
		switch si {
		case imagesecModel.SeverityCriticalInt:
			vulnStatic[imagesecModel.FlagImageHasCriticalVuln] = true
		case imagesecModel.SeverityHighInt:
			vulnStatic[imagesecModel.FlagImageHasHighVuln] = true
		case imagesecModel.SeverityMediumInt:
			vulnStatic[imagesecModel.FlagImageHasMediumVuln] = true
		case imagesecModel.SeverityLowInt:
			vulnStatic[imagesecModel.FlagImageHasLowVuln] = true
		case imagesecModel.SeverityUnknownInt:
			vulnStatic[imagesecModel.FlagImageHasUnknownVun] = true
		}
	}
	if fixed {
		flag = util.SetBit1(flag, imagesecModel.FlagHasFixedVuln)
	} else {
		flag = util.SetBit0(flag, imagesecModel.FlagHasFixedVuln)
	}

	for i := imagesecModel.FlagImageHasUnknownVun; i <= imagesecModel.FlagImageHasCriticalVuln; i++ {
		if vulnStatic[int64(i)] {
			flag = util.SetBit1(flag, uint64(i))
		} else {
			flag = util.SetBit0(flag, uint64(i))
		}
	}

	baseImage := data.ToImageBaseResponse()

	if len(baseImage.Suggests) > 0 {
		flag = util.SetBit1(flag, imagesecModel.FlagImageHasFixSuggest)
	} else {
		flag = util.SetBit0(flag, imagesecModel.FlagImageHasFixSuggest)
	}

	if image[0].Flag == flag && image[0].OS == data.Image.OS {
		s.Log.Info().Int64("imageID", imageID).Msg("UpdateImage image is same not update")
		return nil
	}
	updater := map[string]interface{}{
		"flag": flag,
	}
	osString, err := json.Marshal(data.Image.OS)
	if err == nil {
		updater["os"] = osString
	}

	if err := s.imageDal.UpdateImage(ctx, imagesecModel.UpdateImageParam{ID: imageID, Updater: updater}); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("UpdateImage")
		return err
	}
	s.Log.Info().Int64("imageID", imageID).Interface("updater", updater).Msg("UpdateImage")
	return nil
}

func (s *ScanResultReportSrv) GetImageInfo(ctx context.Context, taskID, subtaskID int64) (imagesecModel.Image, error) {
	empty := imagesecModel.Image{}
	subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
		SubtaskID: subtaskID,
		TaskID:    taskID,
	})
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("SearchScanTask")
		return empty, err
	}
	if len(subtask) == 0 {
		s.Log.Info().Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("not find subtask")
		return empty, fmt.Errorf("not find subtask:%d", subtaskID)
	}
	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueId: subtask[0].ImageUniqueID})
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("SearchImage")
		return empty, err
	}

	if len(image) == 0 {
		s.Log.Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("not find image")
		return empty, fmt.Errorf("not find image:%d", subtask[0].ImageUniqueID)
	}
	s.Log.Info().Int64("imageID", image[0].ID).Msg("GetImageInfo")
	im := image[0]
	return *im, nil
}

func (s *ScanResultReportSrv) UpdateSubtaskScanFinished(ctx context.Context, data imagesecTypes.ReportScanResult) error {
	subtask, _, err := s.taskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: data.SubTaskID})
	if err != nil {
		s.Log.Err(err).Int64("subTaskID", data.SubTaskID).Msg("SearchScanSubtask")
		return err
	}
	if len(subtask) == 0 {
		return fmt.Errorf("not find subtask:%d", data.SubTaskID)
	}
	if subtask[0].Status >= imagesecModel.TaskStatusPause {
		return fmt.Errorf("subtask now stastus is %s,can not update scan data", subtask[0].StatusStr)
	}

	updater := map[string]interface{}{
		"finished_at": time.Now().UnixMilli(),
		"status":      imagesecModel.TaskStatusScanFinished,
		"status_str":  imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusScanFinished),
	}
	if data.StatusStr == imagesecModel.TaskStatusFailedStr {
		updater["status"] = imagesecModel.TaskStatusFailed
		updater["status_str"] = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed)
		updater["msg"] = data.Msg
		updater["reason"] = imagesecModel.TaskFailedReasonScanner
	}

	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      data.SubTaskID,
		Updater: updater,
	}); err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("UpdateSubtaskScanFinished")
		return err
	}
	s.Log.Info().Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Interface("updater", updater).
		Msg("UpdateSubtaskScanFinished succeed")
	return nil
}

func (s *ScanResultReportSrv) CreatePkgVuln(ctx context.Context, data *imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) ([]*imagesecModel.Vuln, error) {
	emp := make([]*imagesecModel.Vuln, 0)
	// match vuln
	imageUniqueID := correlate.Image.UniqueID
	results, err := s.matchVuln(ctx, data)
	if err != nil {
		s.Log.Err(err).Int64("taskID", data.TaskID).Int64("subtaskID", data.SubTaskID).
			Msg("not match vuln")
		return emp, err
	}

	s.Log.Debug().Interface("matchVulnResult", results).Msg("matchVuln")

	s.StatisticsMathRes(results)

	pkgs := make([]*imagesecModel.Pkg, 0)
	pkgToImage := make([]*imagesecModel.PkgToImage, 0)
	vuln := make([]*imagesecModel.Vuln, 0)
	vulnView := make([]*imagesecModel.VulnView, 0)
	vulnIssue := make([]*imagesecModel.VulnToImage, 0)

	pkgMap := make(map[uint64]*imagesecModel.Pkg)

	for i := range results {
		res := results[i]
		for j := range res.Packages {
			pk := res.Packages[j]
			pkg := &imagesecModel.Pkg{
				OSFamily:   data.OS.Family,
				OSName:     data.OS.Name,
				Name:       pk.Name,
				Version:    pk.Version,
				PkgType:    res.Type,
				SrcName:    pk.SrcName,
				SrcVersion: pk.SrcVersion,
				License:    pk.License,
				DependsOn:  nil, // 暂时没有这些数据
				Filepath:   pk.FilePath,
				Class:      string(res.Class),
			}

			pkg.Serialize()
			if err := pkg.Check(); err != nil {
				s.Log.Err(err).Interface("pkg", pkg).Msg("PkgCheck")
				continue
			}
			pkg.UniqueID = pkg.GenUniqueID()
			pkgMap[pkg.UniqueID] = pkg
			pkgs = append(pkgs, pkg)
			p2i := &imagesecModel.PkgToImage{
				UniqueTarget:  pkg.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   pk.Layer.Digest,
			}
			p2i.UniqueID = p2i.GenUniqueID()

			pkgToImage = append(pkgToImage, p2i)
		}

		for j := range res.Vulnerabilities {
			vul := res.Vulnerabilities[j]

			vu := &imagesecModel.Vuln{
				Name:          vul.VulnerabilityID,
				PkgName:       vul.PkgName,
				PkgVersion:    vul.InstalledVersion,
				PkgType:       res.Type,
				DescriptionEn: vul.Description,
				References:    vul.References,
				Class:         string(res.Class),
				CVSS:          make(map[string]imagesecModel.Cvss),
				CweIds:        vul.CweIDs,
				Title:         vul.Title,
				PublishAt:     util.GetTimeUnixMilli(vul.PublishedDate),
				ModifyAt:      util.GetTimeUnixMilli(vul.LastModifiedDate),
				Severity:      imagesecModel.GetSeverityInt(strings.ToUpper(vul.Severity)),
				FixedVersion:  vul.FixedVersion,
				Target:        vul.PkgPath,
				CreatedAt:     time.Now().UnixMilli(),
				UpdatedAt:     time.Now().UnixMilli(),
			}

			vu.PkgUniqueID = vu.GenPkgUniqueID(data.OS)
			vu.UniqueID = vu.GenUniqueID()

			if pkg, ok := pkgMap[vu.PkgUniqueID]; ok {
				vu.SrcName = pkg.SrcName
			}

			for key, v := range vul.CVSS {
				vu.CVSS[string(key)] = imagesecModel.Cvss{
					V2Score:  v.V2Score,
					V2Vector: v.V2Vector,
					V3Score:  v.V3Score,
					V3Vector: v.V3Vector,
				}
			}

			vu = s.vulnMatcher.AddDetailVuln(ctx, vu)

			vu.Serialize()
			if err := vu.Check(); err != nil {
				s.Log.Err(err).Str("vulnName", vu.Name).Msg("VulnCheck")
				continue
			}

			vuln = append(vuln, vu)
			v2i := &imagesecModel.VulnToImage{
				UniqueTarget:  vu.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   vul.Layer.Digest,
			}

			vulnIssue = append(vulnIssue, v2i)
			vulnView = append(vulnView, vu.GenVulnView())
		}

	}

	// 加上漏洞缓存的数据
	cacheLayer := make([]string, 0)
	for _, ly := range data.VulnCache {
		if ly.InCache {
			cacheLayer = append(cacheLayer, ly.Layer)
		}
	}

	vulnLayerParam := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.VulnCacheData, AddDetail: true}
	vulnLayerData, err := s.scanResultDal.SearchScanLayerData(ctx, vulnLayerParam)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return emp, err
	}

	for i := range vulnLayerData {
		vuln = append(vuln, vulnLayerData[i].Vuln...)

		for j := range vulnLayerData[i].Vuln {
			ses := vulnLayerData[i].Vuln[j]
			vulnView = append(vulnView, ses.GenVulnView())

			vulnIssue = append(vulnIssue, &imagesecModel.VulnToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
			})
		}
	}

	// 加上软件缓存的数据
	pkgLayerParam := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.PKGCacheData, AddDetail: true}
	pkgLayerData, err := s.scanResultDal.SearchScanLayerData(ctx, pkgLayerParam)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return emp, err
	}

	for i := range pkgLayerData {
		pkgs = append(pkgs, pkgLayerData[i].Pkg...)

		for j := range pkgLayerData[i].Pkg {

			ses := pkgLayerData[i].Pkg[j]
			pkgMap[ses.UniqueID] = ses

			p2i := &imagesecModel.PkgToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
			}
			p2i.UniqueID = p2i.GenUniqueID()

			pkgToImage = append(pkgToImage, p2i)
		}
	}

	pkgs = imagesecModel.DuplicatePkg(pkgs)

	if err := s.scanResultDal.CreateVuln(ctx, imagesecModel.CreateVulnParam{Data: vuln}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateVuln")
		return emp, err
	}

	if err := s.scanResultDal.CreatePkg(ctx, pkgs); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreatePkg")
		return emp, err
	}
	if err := s.issueDal.CreatePkgToImage(ctx, imagesecModel.CreatePkgToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          pkgToImage,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreatePkgToImage")
		return emp, err
	}

	if err := s.issueDal.CreateVulnToImage(ctx, imagesecModel.CreateVulnToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          vulnIssue,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateVulnToImage")
		return emp, err
	}

	correlate.Vuln = vulnView
	correlate.Pkg = pkgs

	s.Log.Info().Int("vulnCnt", len(vuln)).
		Int("pkgCnt", len(pkgs)).Uint64("imageUniqueID", imageUniqueID).
		Msg("CreatePkgVuln")
	return vuln, err
}

func (s *ScanResultReportSrv) CreateSensitive(ctx context.Context, data imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) error {

	imageUniqueID := correlate.Image.UniqueID
	res := make([]*imagesecModel.SensitiveFile, 0)
	issue := make([]*imagesecModel.SensitiveToImage, 0)

	for i := range data.Sensitives.SensitiveFiles {
		pre := data.Sensitives.SensitiveFiles[i]
		ses := &imagesecModel.SensitiveFile{
			Filename: pre.Filename,
			MD5:      pre.MD5,
			Layer:    pre.Layer,
		}

		res = append(res, ses)
		issue = append(issue, &imagesecModel.SensitiveToImage{
			UniqueTarget:  ses.GenUniqueID(),
			ImageUniqueID: imageUniqueID,
			LayerDigest:   pre.Layer,
		})
	}

	// 加上缓存的数据
	cacheLayer := make([]string, 0)
	for _, ly := range data.SensitiveCache {
		if ly.InCache {
			cacheLayer = append(cacheLayer, ly.Layer)
		}
	}

	param := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.SensitiveCacheData, AddDetail: true}
	layerData, err := s.scanResultDal.SearchScanLayerData(ctx, param)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return err
	}

	for i := range layerData {
		res = append(res, layerData[i].Sensitive...)

		for j := range layerData[i].Sensitive {
			ses := layerData[i].Sensitive[j]

			issue = append(issue, &imagesecModel.SensitiveToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   ses.Layer,
			})
		}
	}

	if err := s.scanResultDal.CreateSensitive(ctx, res); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateSensitive")
		return err
	}
	if err := s.issueDal.CreateSensitiveToImage(ctx, imagesecModel.CreateSensitiveToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateSensitiveToImage")
		return err
	}

	correlate.Sensitive = res
	correlate.SensitiveCnt = int64(len(res))
	s.Log.Info().Int("sentCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("CreateSensitive")
	return nil
}

func (s *ScanResultReportSrv) CreateWebFrameInfo(ctx context.Context, data imagesecTypes.ReportScanResult) error {
	if data.WebFrameInfo.ImageUUID <= 0 || len(data.WebFrameInfo.Data) == 0 {
		return nil
	}
	webs := make([]model.WebFrameInfo, 0)
	for i := range data.WebFrameInfo.Data {
		we := data.WebFrameInfo.Data[i]
		webs = append(webs, model.WebFrameInfo{
			FrameName: we.FrameName,
			Version:   we.Version,
			FilePath:  we.FilePath,
			FileName:  we.FileName,
			Language:  we.Language,
		})
	}

	err := s.scanResultDal.CreateWebFrameInfo(ctx, data.WebFrameInfo.ImageUUID, webs)
	if err != nil {
		s.Log.Err(err).Uint32("ImageUUID", data.WebFrameInfo.ImageUUID).
			Msg("CreateWebFrameInfo")
		return err
	}
	s.Log.Info().Uint32("ImageUUID", data.WebFrameInfo.ImageUUID).
		Msg("CreateWebFrameInfo")
	return nil
}

func (s *ScanResultReportSrv) ContinueCreateDetectTask(ctx context.Context) error {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Stack().Msg("ContinueCreateDetectTask")
				return
			}
		}()

		for task := range s.detectImageChan {
			// // 不再进行检测
			// if task.AllInCache {
			// 	updater := map[string]interface{}{
			// 		"updated_at": time.Now().UnixMilli(),
			// 		"status":     imagesecModel.TaskStatusDetectFinished,
			// 		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusDetectFinished),
			// 	}
			//
			// 	if err := s.taskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
			// 		ID:      task.SubtaskID,
			// 		Updater: updater,
			// 		Where:   fmt.Sprintf("status < %d", imagesecModel.TaskStatusPause),
			// 	}); err != nil {
			// 		s.Log.Err(err).Int64("subtaskID", task.SubtaskID).Interface("updater", updater).
			// 			Msg("UpdateScanSubtask")
			// 	}
			// 	continue
			// }

			// if task.RetryCnt > consts.DefaultMaxRetryCount {
			// 	s.Log.Info().Uint64("imageUniqueID", task.ImageUniqueID).
			// 		Msg("AddDetectTask exceed max retry")
			// 	continue
			// }
			// 防止主从延迟,现在强制走主库，暂时不需要做该项验证
			// if time.Now().Unix()-task.CreatedAt < consts.DefaultSlaveDelay {
			// 	time.Sleep(time.Millisecond * consts.DefaultSlaveDelay)
			// }

			imageSearchParam := imagesecModel.ImageSearchApiParam{UniqueId: task.ImageUniqueID}
			if err := s.imageDetectSrv.CreateImageDetectTask(
				ctx,
				imageSearchParam,
				imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityScan, ScanSubTaskID: task.SubtaskID},
				nil,
			); err != nil {
				s.Log.Err(err).Uint64("imageUniqueID", task.ImageUniqueID).
					Msg("AddDetectTask")
				continue
			}
			s.Log.Info().Uint64("imageUniqueID", task.ImageUniqueID).
				Msg("get finished scan subtask,create detect task succeed")
		}
	}()

	return nil
}

func (s *ScanResultReportSrv) CreateMalware(ctx context.Context, data imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	// if !data.Malware.Scanned {
	// 	s.Log.Info().Uint64("imageUniqueID", data.ImageUniqueID).
	// 		Msg("malware not scanned")
	// 	return nil
	// }

	imageUniqueID := correlate.Image.UniqueID
	res := make([]*imagesecModel.Malware, 0)
	issue := make([]*imagesecModel.MalwareToImage, 0)

	aviraV := &imagesecModel.ScanConfigDB{
		DBType:    imagesecModel.DBMetaTypeAvira,
		DBVersion: data.Malware.AviraDBVersion.Version,
	}
	aviraV.UniqueID = aviraV.GenUniqueID()

	clamV := &imagesecModel.ScanConfigDB{
		DBType:    imagesecModel.DBMetaTypeClamav,
		DBVersion: data.Malware.ClamAvDBVersion.Version,
	}
	clamV.UniqueID = aviraV.GenUniqueID()

	avir := data.Malware.AviraScanResults
	for j := range avir {
		for i := range avir[j].Malware {
			ses := &imagesecModel.Malware{
				Name:        avir[j].Malware[i].Name,
				Filename:    avir[j].FilePathInContainer, // 节点镜像
				Hash:        avir[j].MD5,
				MalwareType: avir[j].Malware[i].Type,
				Description: avir[j].Malware[i].Description,
				Version:     aviraV.UniqueID,
				Layer:       avir[j].Layer,
			}
			if ses.Filename == "" {
				ses.Filename = avir[j].Filename // 仓库镜像
			}
			res = append(res, ses)
			issue = append(issue, &imagesecModel.MalwareToImage{
				UniqueTarget:  ses.GenUniqueID(),
				ImageUniqueID: imageUniqueID,
				LayerDigest:   avir[j].Layer,
			})
		}
	}

	clam := data.Malware.ClamAvScanResults
	for j := range clam {
		for i := range clam[j].MalwareNames {
			ses := &imagesecModel.Malware{
				Name:     clam[j].MalwareNames[i],
				Filename: clam[j].FilePathInContainer,
				Hash:     clam[j].MD5,
				Version:  clamV.UniqueID,
				Layer:    clam[j].Layer,
			}
			if ses.Filename == "" {
				ses.Filename = clam[j].Filename // 仓库镜像
			}
			res = append(res, ses)
			issue = append(issue, &imagesecModel.MalwareToImage{
				UniqueTarget:  ses.GenUniqueID(),
				ImageUniqueID: imageUniqueID,
				LayerDigest:   clam[j].Layer,
			})
		}
	}

	// todo(liuqianli) 下期功能
	// if err := clamV.Check(); err == nil {
	// 	if err := s.versionDal.CreateScanDbMeta(ctx, clamV); err != nil {
	// 		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateDBVersion")
	// 	}
	// }
	//
	// if err := aviraV.Check(); err == nil {
	// 	if err := s.versionDal.CreateScanDbMeta(ctx, aviraV); err != nil {
	// 		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateDBVersion")
	// 	}
	// }

	// 加上缓存的数据
	cacheLayer := make([]string, 0)
	for _, ly := range data.MalwareCache {
		if ly.InCache {
			cacheLayer = append(cacheLayer, ly.Layer)
		}
	}
	param := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.MalwareCacheData, AddDetail: true}
	layerData, err := s.scanResultDal.SearchScanLayerData(ctx, param)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return err
	}

	for i := range layerData {
		res = append(res, layerData[i].Malware...)

		for j := range layerData[i].Malware {
			ses := layerData[i].Malware[j]

			issue = append(issue, &imagesecModel.MalwareToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   ses.Layer,
			})
		}
	}

	if err := s.scanResultDal.CreateMalware(ctx, res); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateMalware")
		return err
	}
	if err := s.issueDal.CreateMalwareToImage(ctx, imagesecModel.CreateMalwareToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateMalwareToImage")
		return err
	}
	correlate.Malware = res
	correlate.MalwareCnt = int64(len(res))

	s.Log.Info().Int("malwareCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("CreateMalware")
	return nil
}

func (s *ScanResultReportSrv) CreateWebshell(ctx context.Context, data imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) error {

	imageUniqueID := correlate.Image.UniqueID
	// if !data.WebshellView.Scanned {
	// 	s.Log.Info().Uint64("imageUniqueID", data.ImageUniqueID).
	// 		Msg("webshell not scanned")
	// 	return nil
	// }

	res1 := make([]*imagesecModel.Webshell, 0)
	res2 := make([]*imagesecModel.WebshellView, 0)
	issue := make([]*imagesecModel.WebshellToImage, 0)

	wv := &imagesecModel.ScanConfigDB{
		DBType:    imagesecModel.DBMetaTypeWebshell,
		DBVersion: data.Webshell.HmEngineVersion.Version,
	}

	wv.UniqueID = wv.GenUniqueID()

	for i := range data.Webshell.HmWebshells {
		pre := data.Webshell.HmWebshells[i]

		ses := &imagesecModel.Webshell{
			Filename:    pre.FilePathInContainer,
			MD5:         pre.MD5,
			FileMod:     pre.Mod,
			Code:        pre.Code,
			Size:        pre.Size,
			RiskLevel:   pre.RiskLevel,
			Description: pre.Description,
			Layer:       pre.Layer,
		}
		if ses.Filename == "" {
			ses.Filename = pre.Filename
		}
		ses.UniqueID = ses.GenUniqueID()
		ses.Version = wv.UniqueID

		res1 = append(res1, ses)
		res2 = append(res2, ses.ToWebshellView())

		issue = append(issue, &imagesecModel.WebshellToImage{
			UniqueTarget:  ses.UniqueID,
			ImageUniqueID: imageUniqueID,
			LayerDigest:   pre.Layer,
		})
	}

	// 加上缓存的数据
	cacheLayer := make([]string, 0)
	for _, ly := range data.WebshellCache {
		if ly.InCache {
			cacheLayer = append(cacheLayer, ly.Layer)
		}
	}
	param := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.WebshellCacheData, AddDetail: true}
	layerData, err := s.scanResultDal.SearchScanLayerData(ctx, param)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return err
	}

	for i := range layerData {
		res1 = append(res1, layerData[i].Webshell...)

		for j := range layerData[i].Webshell {
			ses := layerData[i].Webshell[j]

			res2 = append(res2, ses.ToWebshellView())

			issue = append(issue, &imagesecModel.WebshellToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   ses.Layer,
			})
		}
	}

	if err := s.scanResultDal.CreateWebshell(ctx, res1); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateWebshell")
		return err
	}
	if err := s.issueDal.CreateWebshellToImage(ctx, imagesecModel.CreateWebshellToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateWebshellToImage")
		return err
	}
	correlate.WebshellView = res2
	correlate.Webshell = res1
	correlate.WebshellCnt = int64(len(res2))

	s.Log.Info().Int("webshellCnt", len(res1)).Uint64("imageUniqueID", imageUniqueID).
		Msg("CreateWebshell")
	return nil
}

func (s *ScanResultReportSrv) CreateLicense(ctx context.Context, data imagesecTypes.ReportScanResult,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	imageUniqueID := correlate.Image.UniqueID

	res1 := make([]*imagesecModel.License, 0)
	issue := make([]*imagesecModel.LicenseToImage, 0)

	for i := range data.License {
		ly := data.License[i]
		ses := imagesecModel.License{
			Name:     ly.Name,
			Filename: ly.Filename,
			MD5:      ly.MD5,
			Content:  string(ly.Content),
			Layer:    ly.Layer,
		}
		ses.Serialize()

		res1 = append(res1, &ses)

		issue = append(issue, &imagesecModel.LicenseToImage{
			UniqueTarget:  ses.GenUniqueID(),
			ImageUniqueID: correlate.Image.UniqueID,
			LayerDigest:   data.License[i].Layer,
		})
	}

	// 加上缓存的数据
	cacheLayer := make([]string, 0)
	for _, ly := range data.LicenseCache {
		if ly.InCache {
			cacheLayer = append(cacheLayer, ly.Layer)
		}
	}
	param := imagesecModel.SearchScanLayerParam{Layers: cacheLayer, Issue: imagesecModel.LicenseCacheData, AddDetail: true}
	layerData, err := s.scanResultDal.SearchScanLayerData(ctx, param)
	if err != nil {
		s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("SearchScanLayerData")
		return err
	}

	for i := range layerData {
		res1 = append(res1, layerData[i].License...)

		for j := range layerData[i].License {
			ses := layerData[i].License[j]

			issue = append(issue, &imagesecModel.LicenseToImage{
				UniqueTarget:  ses.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   ses.Layer,
			})
		}
	}

	correlate.License = res1
	correlate.LicenseCnt = int64(len(res1))

	if err := s.scanResultDal.CreateLicense(ctx, res1); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).
			Msg("CreateLicense")
		return err
	}

	if err := s.issueDal.CreateLicenseToImage(ctx, imagesecModel.CreateLicenseToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		s.Log.Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("CreateLicenseToImage")
		return err
	}

	s.Log.Info().Int("licenseCnt", len(res1)).Uint64("imageUniqueID", imageUniqueID).
		Msg("CreateLicense")
	return nil
}

func (s *ScanResultReportSrv) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("scanner not in main cluster,ignore handle kafka msg")
		return nil
	}

	s.Log.Info().Msg("scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Stack().Msg("CreateScanResult")
			}
		}()

		if err := s.ReceiveMsg(ch); err != nil {
			s.Log.Err(err).Msg("CreateScanResult")
		}
	}()

	s.Log.Error().Msg("receive kafka started successfully")

	return nil
}

func (s *ScanResultReportSrv) ReceiveImageScanResult(ctx context.Context, msg kafka.Message) error {
	msg.Value = scannerUtils.UnzipByteSlice(msg.Value)
	var data imagesecTypes.ReportScanResult

	err := json.Unmarshal(msg.Value, &data)
	if err != nil {
		s.Log.Err(err).Str("data", string(msg.Value)).Msg("failed to unmarshal scan image result msg")
		return err
	}

	s.Log.Debug().Int64("subtaskID", data.SubTaskID).Interface("data", data).
		Msg("receive image scan result report")
	s.Log.Info().Str("result", data.LogStr()).Msg("receive image scan result report")
	s.Log.Info().Any("OriginArtifact", data.OriginArtifact).Msg("receive image scan result report")

	if data.StatusStr == imagesecModel.TaskStatusFailedStr {
		s.Log.Info().Str("result", data.LogStr()).Msg("scan failed just update scan subtask")
		if err := s.UpdateSubtaskScanFinished(ctx, data); err != nil {
			s.Log.Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Msg("CreateScanResult")
		}
		return nil
	}

	if err := s.CreateScanResult(ctx, data); err != nil {
		s.Log.Err(err).Msg("CreateScanResult")
		// 消费消息后，不管扫描结果入库是否成功，对于 kafka来说都是成功消费，所以只记录，不返回 error
	}

	return nil
}

func (s *ScanResultReportSrv) ReceiveMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(consts.NodeImageScanResultTopic, consts.NodeImageScanResultGroup, s.ReceiveImageScanResult)
	if err != nil {
		s.Log.Err(err).Msg("failed to sub message queue")
		return nil
	}
	s.Log.Info().Msg("sub message queue ok")
	<-stopCh
	s.Log.Info().Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

func (s *ScanResultReportSrv) SetRiskScore(ctx context.Context, correlate *imagesecModel.ImageWithCorrelateData2) error {
	score := correlate.GetRiskScore()
	key := fmt.Sprintf("riskexp-image-vulns-%s", correlate.Image.GetDockerPullImageName())
	re := model.ImageSeverityScore{RiskScore: score}
	bys, err := json.Marshal(re)
	if err != nil {
		s.Log.Err(err).Str("key", key).Msg("SetRiskScore")
		return err
	}
	if err := s.redisCli.Set(ctx, key, bys, -1).Err(); err != nil {
		s.Log.Err(err).Str("key", key).Msg("SetRiskScore")
		return err
	}
	return nil
}

// 在线镜像的漏洞
func (s *ScanResultReportSrv) UpdateVulnFlag(ctx context.Context) error {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("CreateOnlineVuln recover panic")
			}
		}()

		for vu := range s.OnlineVulnChan {
			if err := s.scanResultDal.CreateVuln(ctx, imagesecModel.CreateVulnParam{
				OnlineVuln: true,
				Data:       vu,
			}); err != nil {
				s.Log.Err(err).Msg("CreateOnlineVuln UpdateVulnOnline")
				continue
			}
			s.Log.Info().Int("onlineVuln", len(vu)).Msg("CreateOnlineVuln update online vuln")
		}
	}()

	return nil
}

func (s *ScanResultReportSrv) StatisticsMathRes(data report.Results) (int, int) {
	vulnCnt, pkgCnt := 0, 0
	for i := range data {
		pkgCnt += len(data[i].Packages)
		vulnCnt += len(data[i].Vulnerabilities)
	}
	s.Log.Info().Int("vulnCnt", vulnCnt).Int("pkgCnt", pkgCnt).Msg("mathVuln statisticsMathRes")
	return vulnCnt, pkgCnt
}

func (s *ScanResultReportSrv) AllInCache(ctx context.Context, res imagesecTypes.ReportScanResult) bool {
	// 说明是数据迁移或兼容老版本
	if res.IgnoreVulnPkg {
		return false
	}
	for i := range res.LicenseCache {
		ly := res.LicenseCache[i]
		if !ly.InCache {
			return false
		}
	}
	for i := range res.VulnCache {
		ly := res.VulnCache[i]
		if !ly.InCache {
			return false
		}
	}
	for i := range res.SensitiveCache {
		ly := res.SensitiveCache[i]
		if !ly.InCache {
			return false
		}
	}
	for i := range res.MalwareCache {
		ly := res.MalwareCache[i]
		if !ly.InCache {
			return false
		}
	}
	for i := range res.WebshellCache {
		ly := res.WebshellCache[i]
		if !ly.InCache {
			return false
		}
	}
	return true
}

func NewScanResultReportSrv(
	nodeTaskDal imagesecStore.ScanTaskDal,
	imageDal imagesecStore.ImageMetaDal,
	scanResultDal imagesecStore.ScanResultDal,
	issueDal imagesecStore.ScanIssueDal,
	versionDal imagesecStore.ScanDbMetaDal,
	imageDetectSrv ImageDetectTaskService,
	vulnMatcher VulnMatcher,
	mqReader mq.Reader,
	redisCli *redis.Client,
) *ScanResultReportSrv {
	if scanResultReportSrv != nil {
		return scanResultReportSrv
	}

	srv := &ScanResultReportSrv{
		taskDal:         nodeTaskDal,
		imageDal:        imageDal,
		scanResultDal:   scanResultDal,
		issueDal:        issueDal,
		mqReader:        mqReader,
		imageDetectSrv:  imageDetectSrv,
		versionDal:      versionDal,
		redisCli:        redisCli,
		vulnMatcher:     vulnMatcher,
		detectImageChan: make(chan DetectImageData),
		OnlineVulnChan:  make(chan []*imagesecModel.Vuln),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ReportScanResult"),
			scannerUtils.WithModule(consts.ModuleKafkaReport),
		),
	}

	_ = srv.ContinueCreateDetectTask(context.Background())
	_ = srv.UpdateVulnFlag(context.Background())

	scanResultReportSrv = srv

	return scanResultReportSrv
}

var scanResultReportSrv *ScanResultReportSrv
