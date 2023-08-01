package imagesecReport

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	vulnMatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"

	"github.com/boltdb/bolt"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannerModel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultReportSrv struct {
	nodeTaskDal     imagesecStore.ScanTaskDal
	imageDal        imagesecStore.ImageMetaDal
	scanResultDal   imagesecStore.ScanResultDal
	issueDal        imagesecStore.ScanIssueDal
	versionDal      imagesecStore.ScanDbMetaDal
	mqReader        mq.Reader
	pvcPath         string
	vulnDBVersion   *scannerModel.VulnDBVersion
	availableBoltDB *BoltDB
	redisCli        *redis.Client
	boltDBChan      chan *BoltDB
	imageDetectSrv  ImageDetectTaskService
	detectImageChan chan DetectImageData
	OnlineVulnChan  chan []*imagesecModel.Vuln
}

type DetectImageData struct {
	ImageUniqueID uint64
	SubtaskID     int64
	CreatedAt     int64
	RetryCnt      int64
}

type BoltDB struct {
	VulnBoltDB  *bolt.DB
	CnvdBoltDB  *bolt.DB
	CnnvdBoltDB *bolt.DB
}

func (s *ScanResultReportSrv) matchVuln(res *imagesecTypes.ScanResult) (report.Results, error) {
	// match vuln by image artifact
	matcher, err := vulnMatch.NewMatcher(vulnMatch.WithCachePath(vulnMatch.DefaultCachePath))
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", res.SubTaskID).Int64("taskID", res.TaskID).
			Msg("CreateScanResult failed to create vuln matcher")
		return nil, err
	}

	err = matcher.MatchVulnerability(res.OriginArtifact)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", res.SubTaskID).Int64("taskID", res.TaskID).
			Msg("CreateScanResult failed to match vuln")
		return nil, err
	}
	return matcher.Results(), nil
}

func (s *ScanResultReportSrv) CreateScanResult(ctx context.Context, data imagesecTypes.ScanResult) error {

	image, err := s.GetImageInfo(ctx, data.TaskID, data.SubTaskID)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("CreateScanResult GetImageInfo")
		return err
	}

	correlate := &imagesecModel.ImageWithCorrelateData2{Image: image}

	correlate.Image.OS = data.OS
	vulns, _ := s.CreatePkgVuln(ctx, data, image.UniqueID, correlate)

	_ = s.CreateSensitive(ctx, data, image.UniqueID, correlate)
	_ = s.CreateMalware(ctx, data, image.UniqueID, correlate)
	_ = s.CreateWebshell(ctx, data, image.UniqueID, correlate)
	_ = s.CreateLicense(ctx, data, image.UniqueID, correlate)
	_ = s.CreateWebFrameInfo(ctx, data)

	_ = s.SetRiskScore(ctx, correlate)

	// 更新镜像信息
	_ = s.UpdateImage(ctx, image.ID, correlate)
	// 在线镜像的漏洞
	if util.ExistBit1(image.Flag, imagesecModel.FlagImageOnline) {
		go func() { s.OnlineVulnChan <- vulns }()
	}

	go func() {
		dd := DetectImageData{
			ImageUniqueID: image.UniqueID,
			SubtaskID:     data.SubTaskID,
			CreatedAt:     time.Now().Unix(),
		}
		s.detectImageChan <- dd
	}()

	logging.Get().Info().Str("module", "KafkaReport").
		Int("malwareCnt", len(correlate.Malware)).
		Int("pkgCnt", len(correlate.Pkg)).
		Int("vulnCnt", len(correlate.Vuln)).
		Int("sensitiveCnt", len(correlate.Sensitive)).
		Int("WebshellCnt", len(correlate.Webshell)).
		Int("WeakPasswordCnt", len(correlate.WeakPassword)).
		Int("licenseCnt", len(correlate.License)).
		Int64("subtaskID", data.SubTaskID).
		Int64("taskID", data.TaskID).
		Str("image", image.GetImageName()).
		Msg("CreateScanResult get scan result and create succeed")

	if err := s.UpdateSubtaskScanFinished(ctx, data); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Msg("CreateScanResult")
		return err
	}

	return nil
}

func (s *ScanResultReportSrv) CreateScanResultForDataMigrate(ctx context.Context, data imagesecTypes.ScanResult) error {

	image := imagesecModel.Image{UniqueID: data.ImageUniqueID}

	correlate := &imagesecModel.ImageWithCorrelateData2{Image: image}
	_ = s.CreateSensitive(ctx, data, image.UniqueID, correlate)
	_ = s.CreateMalware(ctx, data, image.UniqueID, correlate)
	_ = s.CreateWebshell(ctx, data, image.UniqueID, correlate)

	logging.Get().Info().Str("module", "KafkaReport").Int64("imageID", image.ID).Int64("subtaskID", data.SubTaskID).Msg("CreateScanResult succeed")

	return nil
}

func (s *ScanResultReportSrv) UpdateImage(ctx context.Context, imageID int64, data *imagesecModel.ImageWithCorrelateData2) error {

	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{ID: imageID})

	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("imageID", imageID).Msg("SearchImage")
		return err
	}
	if len(image) == 0 {
		err = fmt.Errorf("not find image:%d", imageID)
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("imageID", imageID).Msg("SearchImage")
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
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("imageID", imageID).Msg("UpdateImage")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Int64("imageID", imageID).Interface("updater", updater).Msg("CreateScanResult UpdateImage")
	return nil
}

func (s *ScanResultReportSrv) GetImageInfo(ctx context.Context, taskID, subtaskID int64) (imagesecModel.Image, error) {
	empty := imagesecModel.Image{}
	subtask, _, err := s.nodeTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
		SubtaskID: subtaskID,
		TaskID:    taskID,
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("ScanResultReportSrv SearchScanTask")
		return empty, err
	}
	if len(subtask) == 0 {
		logging.Get().Info().Str("module", "KafkaReport").Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("ScanResultReportSrv not find subtask")
		return empty, err
	}
	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueId: subtask[0].ImageUniqueID})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("ScanResultReportSrv SearchImage")
		return empty, err
	}

	if len(image) == 0 {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("ScanResultReportSrv not find image")
		return empty, fmt.Errorf("not find image:%d", subtask[0].ImageUniqueID)
	}
	logging.Get().Info().Str("module", "KafkaReport").Int64("imageID", image[0].ID).Msg("ScanResultReportSrv GetImageInfo")
	return *(image[0]), nil
}

func (s *ScanResultReportSrv) UpdateSubtaskScanFinished(ctx context.Context, data imagesecTypes.ScanResult) error {
	subtask, _, err := s.nodeTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: data.SubTaskID})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subTaskID", data.SubTaskID).Msg("SearchScanSubtask")
		return err
	}
	if len(subtask) == 0 {
		return fmt.Errorf("not find subtask:%d", data.SubTaskID)
	}
	if subtask[0].Status > imagesecModel.TaskStatusSendFinished {
		return fmt.Errorf("subtask stastus is %s,can not save scan data", subtask[0].StatusStr)
	}

	updater := map[string]interface{}{
		"status":     imagesecModel.TaskStatusScanFinished,
		"status_str": imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusScanFinished),
	}
	if data.StatusStr == imagesecModel.TaskStatusFailedStr {
		updater["status"] = imagesecModel.TaskStatusFailed
		updater["status_str"] = imagesecModel.ScanStatusToStr(imagesecModel.TaskStatusFailed)
		updater["msg"] = data.Msg
		updater["reason"] = imagesecModel.TaskFailedReasonScanner
	}

	if err := s.nodeTaskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      data.SubTaskID,
		Updater: updater,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("ScanResultReportSrv UpdateSubtaskScanFinished")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Interface("updater", updater).
		Msg("ScanResultReportSrv UpdateSubtaskScanFinished succeed")
	return nil
}

func (s *ScanResultReportSrv) CreatePkgVuln(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) ([]*imagesecModel.Vuln, error) {
	emp := make([]*imagesecModel.Vuln, 0)
	// match vuln
	results, err := s.matchVuln(&data)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Int64("taskID", data.TaskID).Int64("subtaskID", data.SubTaskID).
			Msg("ScanResultReportSrv not match vuln")
		return emp, err
	}

	logging.Get().Debug().Str("module", "KafkaReport").Interface("matchVulnResult", results).Msg("matchVuln")

	statisticsMathRes(results)

	pkgs := make([]*imagesecModel.Pkg, 0)
	pkgToImage := make([]*imagesecModel.PkgToImage, 0)
	vuln := make([]*imagesecModel.Vuln, 0)
	vulnView := make([]*imagesecModel.VulnView, 0)
	vulnIssue := make([]*imagesecModel.VulnToImage, 0)

	pkgMap := make(map[uint64]*imagesecModel.Pkg)
	pkgLayerMap := make(map[uint64]string)

	for i := range data.VulnResults {
		res := data.VulnResults[i]
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
				License:    strings.TrimSpace(strings.ReplaceAll(pk.License, pk.Name, "")),
				DependsOn:  nil, // 暂时没有这些数据
				Filepath:   pk.FilePath,
				Class:      res.Class,
			}

			pkg.UniqueID = pkg.GenUniqueID()

			pkgMap[pkg.UniqueID] = pkg
			pkgs = append(pkgs, pkg)
			p2i := &imagesecModel.PkgToImage{
				UniqueTarget:  pkg.UniqueID,
				ImageUniqueID: imageUniqueID,
			}
			p2i.UniqueID = p2i.GenUniqueID()
			pkgToImage = append(pkgToImage, p2i)
		}
	}

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

			pkg.UniqueID = pkg.GenUniqueID()

			pkgMap[pkg.UniqueID] = pkg
			pkgs = append(pkgs, pkg)
			p2i := &imagesecModel.PkgToImage{
				UniqueTarget:  pkg.UniqueID,
				ImageUniqueID: imageUniqueID,
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

			vu = s.AddDetailVuln(ctx, vu)
			vu.Serialize()
			if err := vu.Check(); err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Str("vulnName", vu.Name).Msg("VulnCheck")
				continue
			}

			vuln = append(vuln, vu)
			v2i := &imagesecModel.VulnToImage{
				UniqueTarget:  vu.UniqueID,
				ImageUniqueID: imageUniqueID,
				LayerDigest:   pkgLayerMap[vu.PkgUniqueID],
			}

			vulnIssue = append(vulnIssue, v2i)
			vulnView = append(vulnView, vu.GenVulnView())
		}
	}

	pkgs = imagesecModel.DuplicatePkg(pkgs)

	if err := s.scanResultDal.CreateVuln(ctx, imagesecModel.CreateVulnParam{Data: vuln}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateVuln")
		return emp, err
	}

	if err := s.scanResultDal.CreatePkg(ctx, pkgs); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreatePkg")
		return emp, err
	}
	if err := s.issueDal.CreatePkgToImage(ctx, imagesecModel.CreatePkgToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          pkgToImage,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreatePkgToImage")
		return emp, err
	}

	if err := s.issueDal.CreateVulnToImage(ctx, imagesecModel.CreateVulnToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          vulnIssue,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateVulnToImage")
		return emp, err
	}

	correlate.Vuln = vulnView
	correlate.Pkg = pkgs

	logging.Get().Info().Str("module", "KafkaReport").Int("vulnCnt", len(vuln)).
		Int("pkgCnt", len(pkgs)).Uint64("imageUniqueID", imageUniqueID).
		Msg("ScanResultReportSrv CreatePkgVuln")
	return vuln, err
}

func (s *ScanResultReportSrv) CreateSensitive(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res := make([]*imagesecModel.SensitiveFile, 0)
	issue := make([]*imagesecModel.SensitiveToImage, 0)
	for i := range data.Sensitives.SensitiveFiles {
		pre := data.Sensitives.SensitiveFiles[i]
		ses := &imagesecModel.SensitiveFile{
			Filename:      pre.Filename,
			MD5:           pre.MD5,
			DescriptionEn: pre.DescriptionEn,
			DescriptionZh: pre.DescriptionZh,
		}

		res = append(res, ses)
		issue = append(issue, &imagesecModel.SensitiveToImage{
			UniqueTarget:  ses.GenUniqueID(),
			ImageUniqueID: imageUniqueID,
			LayerDigest:   pre.Layer,
		})
	}

	if err := s.scanResultDal.CreateSensitive(ctx, res); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitive")
		return err
	}
	if err := s.issueDal.CreateSensitiveToImage(ctx, imagesecModel.CreateSensitiveToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitiveToImage")
		return err
	}
	correlate.Sensitive = res
	logging.Get().Info().Str("module", "KafkaReport").Int("sentCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitive")
	return nil
}

func (s *ScanResultReportSrv) CreateWebFrameInfo(ctx context.Context, data imagesecTypes.ScanResult) error {
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
		logging.Get().Err(err).Str("module", "KafkaReport").Uint32("ImageUUID", data.WebFrameInfo.ImageUUID).
			Msg("ScanResultReportSrv CreateWebFrameInfo")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Uint32("ImageUUID", data.WebFrameInfo.ImageUUID).
		Msg("ScanResultReportSrv CreateWebFrameInfo")
	return nil
}

func (s *ScanResultReportSrv) GenBoltDBChan(ctx context.Context) chan *BoltDB {
	out := make(chan *BoltDB)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("GenBoltDBChan")
				return
			}
		}()

		defer close(out)

		for {
			if global.VulnDBVersion == nil || global.VulnDBVersion.VulnVersion.TrivyVersion.Version == "" ||
				global.VulnDBVersion.VulnVersion.CustomDBVersion.Version == "" {

				logging.Get().Info().Str("module", "KafkaReport").Msg("GenBoltDBChan not get global vuln db version")
				time.Sleep(time.Second * 10)
				continue
			}

			if s.vulnDBVersion == nil || s.vulnDBVersion.TrivyVersion.Version == "" || s.vulnDBVersion.CustomDBVersion.Version == "" ||
				s.vulnDBVersion.TrivyVersion.Version != global.VulnDBVersion.VulnVersion.TrivyVersion.Version ||
				s.vulnDBVersion.CustomDBVersion.Version != global.VulnDBVersion.VulnVersion.CustomDBVersion.Version ||
				s.availableBoltDB == nil {

				MustMkEmptyDir(filepath.Join(s.pvcPath, consts.NodeVulnDir))
				MustCopyFile(filepath.Join(global.PVCPath, scannerModel.TrivyDBPath), filepath.Join(s.pvcPath, consts.NodeTrivyDBPath))
				MustCopyFile(filepath.Join(global.PVCPath, scannerModel.CustomDBPath), filepath.Join(s.pvcPath, consts.NodeCustomDBPath))

				s.vulnDBVersion = &global.VulnDBVersion.VulnVersion

				boltDB := BoltDB{
					VulnBoltDB:  MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeTrivyDBPath)),
					CnvdBoltDB:  MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeCustomDBPath)),
					CnnvdBoltDB: MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeCustomDBPath)),
				}
				logging.Get().Info().Str("module", "KafkaReport").Msg("GenBoltDBChan rebuild boltdb")
				s.availableBoltDB = &boltDB
			}
			out <- s.availableBoltDB
		}
	}()
	return out
}

func (s *ScanResultReportSrv) ContinueCreateDetectTask(ctx context.Context) error {

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("ContinueCreateDetectTask")
				return
			}
		}()

		for task := range s.detectImageChan {

			if task.RetryCnt > consts.DefaultMaxRetryCount {
				logging.Get().Info().Str("module", "KafkaReport").Uint64("imageUniqueID", task.ImageUniqueID).
					Msg("AddDetectTask exceed max retry")
				continue
			}
			// 防止主从延迟,现在强制走主库，暂时不需要做该项验证
			// if time.Now().Unix()-task.CreatedAt < consts.DefaultSlaveDelay {
			// 	time.Sleep(time.Millisecond * consts.DefaultSlaveDelay)
			// }

			imageSearchParam := imagesecModel.ImageSearchApiParam{UniqueId: task.ImageUniqueID}
			if err := s.imageDetectSrv.CreateImageDetectTask(
				ctx,
				imageSearchParam,
				imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityScan, ScanSubTaskID: task.SubtaskID},
				make([]*imagesecModel.SecurityPolicy, 0),
			); err != nil {
				logging.Get().Err(err).Str("module", "KafkaReport").Uint64("imageUniqueID", task.ImageUniqueID).
					Msg("AddDetectTask")
				continue
			}
			logging.Get().Info().Str("module", "KafkaReport").Uint64("imageUniqueID", task.ImageUniqueID).
				Msg("get scan finished subtask,create detect task succeed")
		}
	}()
	return nil
}

func (s *ScanResultReportSrv) CreateMalware(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res := make([]*imagesecModel.Malware, 0)
	issue := make([]*imagesecModel.MalwareToImage, 0)

	aviraV := &imagesecModel.ScanDbMeta{
		DBType:    imagesecModel.DBMetaTypeAvira,
		DBVersion: data.Malwares.AviraDBVersion.Version,
	}
	aviraV.UniqueID = aviraV.GenUniqueID()

	clamV := &imagesecModel.ScanDbMeta{
		DBType:    imagesecModel.DBMetaTypeClamav,
		DBVersion: data.Malwares.ClamAvDBVersion.Version,
	}
	clamV.UniqueID = aviraV.GenUniqueID()

	avir := data.Malwares.AviraScanResults
	for j := range avir {
		for i := range avir[j].Malware {
			ses := &imagesecModel.Malware{
				Name:        avir[j].Malware[i].Name,
				Filename:    avir[j].FilePathInContainer, // 节点镜像
				Hash:        avir[j].Hash,
				MalwareType: avir[j].Malware[i].Type,
				Description: avir[j].Malware[i].Description,
				Version:     aviraV.UniqueID,
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

	clam := data.Malwares.ClamAvScanResults
	for j := range clam {
		for i := range clam[j].MalwareNames {
			ses := &imagesecModel.Malware{
				Name:     clam[j].MalwareNames[i],
				Filename: clam[j].FilePathInContainer,
				Hash:     clam[j].Hash,
				Version:  clamV.UniqueID,
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
	// 		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateDBVersion")
	// 	}
	// }
	//
	// if err := aviraV.Check(); err == nil {
	// 	if err := s.versionDal.CreateScanDbMeta(ctx, aviraV); err != nil {
	// 		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateDBVersion")
	// 	}
	// }

	if err := s.scanResultDal.CreateMalware(ctx, res); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalware")
		return err
	}
	if err := s.issueDal.CreateMalwareToImage(ctx, imagesecModel.CreateMalwareToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalwareToImage")
		return err
	}
	correlate.Malware = res
	logging.Get().Info().Str("module", "KafkaReport").Int("malwareCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalware")
	return nil
}

func (s *ScanResultReportSrv) CreateWebshell(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res1 := make([]*imagesecModel.Webshell, 0)
	res2 := make([]*imagesecModel.WebshellView, 0)
	issue := make([]*imagesecModel.WebshellToImage, 0)

	wv := &imagesecModel.ScanDbMeta{
		DBType:    imagesecModel.DBMetaTypeWebshell,
		DBVersion: data.Webshells.HmEngineVersion.Version,
	}

	wv.UniqueID = wv.GenUniqueID()

	for i := range data.Webshells.HmWebshells {
		pre := data.Webshells.HmWebshells[i]
		ses := &imagesecModel.Webshell{
			Filename:    pre.FilePathInContainer,
			MD5:         pre.MD5,
			FileMod:     pre.Mod,
			Code:        pre.Code,
			Size:        pre.Size,
			RiskLevel:   pre.RiskLevel,
			Description: pre.Description,
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
		})
	}

	if err := s.scanResultDal.CreateWebshell(ctx, res1); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateWebshell")
		return err
	}
	if err := s.issueDal.CreateWebshellToImage(ctx, imagesecModel.CreateWebshellToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateWebshellToImage")
		return err
	}
	correlate.Webshell = res2

	logging.Get().Info().Str("module", "KafkaReport").Int("webshellCnt", len(res1)).Uint64("imageUniqueID", imageUniqueID).
		Msg("ScanResultReportSrv CreateWebshell")
	return nil
}

func (s *ScanResultReportSrv) CreateLicense(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res1 := make([]*imagesecModel.License, 0)
	issue := make([]*imagesecModel.LicenseToImage, 0)

	for i := range data.License {
		ly := data.License[i]
		ses := imagesecModel.License{Name: ly.Name, Filename: ly.Filename, MD5: ly.MD5, Content: ly.Content}
		ses.Serialize()

		res1 = append(res1, &ses)

		issue = append(issue, &imagesecModel.LicenseToImage{
			UniqueTarget:  ses.GenUniqueID(),
			ImageUniqueID: imageUniqueID,
			LayerDigest:   data.License[i].Layer,
		})
	}

	correlate.License = res1

	if err := s.scanResultDal.CreateLicense(ctx, res1); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).
			Msg("ScanResultReportSrv CreateLicense")
		return err
	}

	if err := s.issueDal.CreateLicenseToImage(ctx, imagesecModel.CreateLicenseToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateLicenseToImage")
		return err
	}

	logging.Get().Info().Str("module", "KafkaReport").Int("licenseCnt", len(res1)).Uint64("imageUniqueID", imageUniqueID).
		Msg("CreateScanResult CreateLicense")
	return nil
}

func (s *ScanResultReportSrv) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "KafkaReport").Msg("CreateScanResult scanner not in main cluster,ignore handle kafka msg")
		return nil
	}

	logging.Get().Info().Str("module", "KafkaReport").Msg("CreateScanResult scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("CreateScanResult")
			}
		}()

		if err := s.ReceiveMsg(ch); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("CreateScanResult")
		}
	}()

	logging.Get().Error().Msg("CreateScanResult receive kafka started successfully")

	return nil
}

func (s *ScanResultReportSrv) ReceiveImageScanResult(ctx context.Context, msg kafka.Message) error {
	var data imagesecTypes.ScanResult
	err := json.Unmarshal(msg.Value, &data)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("data", string(msg.Value)).Msg("CreateScanResult failed to unmarshal scan image result msg")
		return err
	}

	logging.Get().Debug().Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Interface("data", data).
		Msg("CreateScanResult receive image scan result report")
	logging.Get().Info().Str("module", "KafkaReport").Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Str("msg", data.Msg).
		Msg("CreateScanResult receive image scan result report")

	if data.SubTaskID > 0 {
		if err := s.CreateScanResult(ctx, data); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("CreateScanResult")
			// 消费消息后，不管扫描结果入库是否成功，对于 kafka来说都是成功消费，所以只记录，不返回 error
		}
	}
	// subtaskID<=0 表示是数据迁移等情况
	if data.SubTaskID <= 0 {
		if err := s.CreateScanResultForDataMigrate(ctx, data); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("CreateScanResultForDataMigrate")
			// 消费消息后，不管扫描结果入库是否成功，对于 kafka来说都是成功消费，所以只记录，不返回 error
		}
	}

	return nil
}

func (s *ScanResultReportSrv) ReceiveMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(model.NodeImageScanResultTopic, model.NodeImageScanResultGroup, s.ReceiveImageScanResult)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("failed to sub message queue")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Msg("sub message queue ok")
	<-stopCh
	logging.Get().Info().Str("module", "KafkaReport").Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

func (s *ScanResultReportSrv) AddDetailVuln(ctx context.Context, vuln *imagesecModel.Vuln) *imagesecModel.Vuln {
	if vuln == nil {
		return vuln
	}

	timeoutCtx, canFunc := context.WithTimeout(ctx, 10*time.Minute)
	defer canFunc()

	var boltDB *BoltDB
	select {
	case boltDB = <-s.boltDBChan:
		break
	case <-timeoutCtx.Done():
		logging.Get().Info().Str("module", "KafkaReport").Msg("boltDBChan time out")
		return vuln
	}

	// boltData, err := GetVulnDetailFromBolt(boltDB.VulnBoltDB, vuln.Name)
	// if err != nil {
	// 	logging.Get().Err(err).Str("module", "KafkaReport").Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetVulnDetailFromBolt")
	// }
	cnnvdData, err := GetCnnvdFromBolt(boltDB.CnnvdBoltDB, vuln.Name)
	if err != nil {
		logging.Get().Info().Str("module", "KafkaReport").Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetCnnvdFromBolt not get cnnvd")
	}
	cnvdData, err := GetCnvdFromBolt(boltDB.CnvdBoltDB, vuln.Name)
	if err != nil {
		logging.Get().Info().Str("module", "KafkaReport").Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetCnvdFromBolt not get cnvd")
	}

	if cnnvdData != nil {
		vuln.CnnvdName = cnnvdData.Number
		vuln.CnnvdFixSuggestion = cnnvdData.FixSuggestion
		if len(vuln.References) == 0 {
			vuln.References = make([]string, 0)
		}
		if cnnvdData.RefLink != "" {
			vuln.References = append(vuln.References, cnnvdData.RefLink)
		}
	}
	if len(cnvdData) > 0 {
		vuln.CnvdTitle = cnvdData[0].Title
		vuln.DescriptionZh = cnvdData[0].Description
	}
	logging.Get().Debug().Str("module", "KafkaReport").Str("vulnID", vuln.Name).Msg("ScanResultReportSrv AddDetailVuln")
	return vuln
}

func (s *ScanResultReportSrv) SetRiskScore(ctx context.Context, correlate *imagesecModel.ImageWithCorrelateData2) error {
	score := correlate.GetRiskScore()
	key := fmt.Sprintf("riskexp-image-vulns-%s", correlate.Image.GetImageName())
	re := model.ImageSeverityScore{RiskScore: score}
	bys, err := json.Marshal(re)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("key", key).Msg("SetRiskScore")
		return err
	}
	if err := s.redisCli.Set(ctx, key, bys, -1).Err(); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("key", key).Msg("SetRiskScore")
		return err
	}
	return nil
}

func statisticsMathRes(data report.Results) (int, int) {
	vulnCnt, pkgCnt := 0, 0
	for i := range data {
		pkgCnt += len(data[i].Packages)
		vulnCnt += len(data[i].Vulnerabilities)
	}
	logging.Get().Info().Str("module", "KafkaReport").Int("vulnCnt", vulnCnt).Int("pkgCnt", pkgCnt).Msg("mathVuln statisticsMathRes")
	return vulnCnt, pkgCnt
}

func NewScanResultReportSrv(
	nodeTaskDal imagesecStore.ScanTaskDal,
	imageDal imagesecStore.ImageMetaDal,
	scanResultDal imagesecStore.ScanResultDal,
	issueDal imagesecStore.ScanIssueDal,
	versionDal imagesecStore.ScanDbMetaDal,
	imageDetectSrv ImageDetectTaskService,
	mqReader mq.Reader,
	redisCli *redis.Client,
) *ScanResultReportSrv {
	if scanResultReportSrv != nil {
		return scanResultReportSrv
	}

	srv := &ScanResultReportSrv{
		nodeTaskDal:     nodeTaskDal,
		imageDal:        imageDal,
		scanResultDal:   scanResultDal,
		issueDal:        issueDal,
		mqReader:        mqReader,
		pvcPath:         global.PVCPath,
		boltDBChan:      make(chan *BoltDB),
		imageDetectSrv:  imageDetectSrv,
		versionDal:      versionDal,
		redisCli:        redisCli,
		detectImageChan: make(chan DetectImageData),
		OnlineVulnChan:  make(chan []*imagesecModel.Vuln),
	}
	srv.boltDBChan = srv.GenBoltDBChan(context.Background())

	_ = srv.ContinueCreateDetectTask(context.Background())
	_ = srv.UpdateVulnFlag(context.Background())

	scanResultReportSrv = srv

	return scanResultReportSrv
}

var scanResultReportSrv *ScanResultReportSrv
