package nodereport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"

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
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultReportSrv struct {
	nodeTaskDal     imagesecStore.ScanTaskDal
	imageDal        imagesecStore.ImageMetaDal
	scanResultDal   imagesecStore.ScanResultDal
	issueDal        imagesecStore.ScanIssueDal
	versionDal      imagesecStore.ScanVersionDal
	mqReader        mq.Reader
	pvcPath         string
	vulnDBVersion   *scannermodel.VulnDBVersion
	availableBoltDB *BoltDB
	boltDBChan      chan *BoltDB
	imageDetectSrv  ImageDetectTaskService
	detectImageChan chan DetectImageData
}

type DetectImageData struct {
	ImageID       int64
	SubtaskID     int64
	ImageFromType string
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
	matcher, err := vulnmatch.NewMatcher(vulnmatch.WithCachePath(vulnmatch.DefaultCachePath))
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", res.SubTaskID).Int64("taskID", res.TaskID).Msg("failed to create vuln matcher")
		return nil, err
	}

	err = matcher.MatchVulnerability(res.OriginArtifact)
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", res.SubTaskID).Int64("taskID", res.TaskID).Msg("failed to match vuln")
		return nil, err
	}
	return matcher.Results(), nil
}

func (s *ScanResultReportSrv) CreateScanResult(ctx context.Context, data imagesecTypes.ScanResult) error {

	image, err := s.GetImageInfo(ctx, data.TaskID, data.SubTaskID)
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Msg("GetImageInfo")
		return err
	}

	correlate := &imagesecModel.ImageWithCorrelateData2{Image: image, Flag: image.Flag}

	correlate.Image.OS = data.OS

	_ = s.CreatePkgVuln(ctx, data, image.UniqueID, correlate)
	_ = s.CreateSensitive(ctx, data, image.UniqueID, correlate)
	_ = s.CreateMalware(ctx, data, image.UniqueID, correlate)
	_ = s.CreateWebshell(ctx, data, image.UniqueID, correlate)

	// 更新镜像信息
	// fixme 上面出错,镜像怎么更新
	_ = s.UpdateImage(ctx, image.ID, correlate)

	go func() {
		s.detectImageChan <- DetectImageData{
			ImageID:       image.ID,
			SubtaskID:     data.SubTaskID,
			ImageFromType: image.ImageFromType,
			CreatedAt:     time.Now().Unix(),
		}
	}()

	logging.Get().Info().Int64("imageID", image.ID).Int64("subtaskID", data.SubTaskID).Msg("CreateScanResult succeed")

	if err := s.UpdateSubtaskScanFinished(ctx, data); err != nil {
		logging.Get().Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Msg("CreateScanResult")
		return err
	}

	return nil
}

func (s *ScanResultReportSrv) UpdateImage(ctx context.Context, imageID int64, data *imagesecModel.ImageWithCorrelateData2) error {

	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{ImageID: imageID})

	if err != nil {
		logging.Get().Err(err).Int64("imageID", imageID).Msg("SearchImage")
		return err
	}
	if len(image) == 0 {
		err = fmt.Errorf("not find image:%d", imageID)
		logging.Get().Err(err).Int64("imageID", imageID).Msg("SearchImage")
		return err
	}

	flag := image[0].Flag

	if data.Image.OS.Eosl {
		flag = util.SetBit1(flag, model.FlagImageNotMaintained)
	} else {
		flag = util.SetBit0(flag, model.FlagImageNotMaintained)
	}

	if len(data.Sensitive) > 0 {
		flag = util.SetBit1(flag, model.FlagHasSensitive)
	} else {
		flag = util.SetBit0(flag, model.FlagHasSensitive)
	}

	if len(data.Vuln) > 0 {
		flag = util.SetBit1(flag, model.FlagHasVuln)
	} else {
		flag = util.SetBit0(flag, model.FlagHasVuln)
	}

	if len(data.Malware) > 0 {
		flag = util.SetBit1(flag, model.FlagHasMalicious)
	} else {
		flag = util.SetBit0(flag, model.FlagHasMalicious)
	}

	if len(data.Webshell) > 0 {
		flag = util.SetBit1(flag, model.FlagHasWebshell)
	} else {
		flag = util.SetBit0(flag, model.FlagHasWebshell)
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
			vulnStatic[model.FlagImageHasCriticalVuln] = true
		case imagesecModel.SeverityHighInt:
			vulnStatic[model.FlagImageHasHighVuln] = true
		case imagesecModel.SeverityMediumInt:
			vulnStatic[model.FlagImageHasMediumVuln] = true
		case imagesecModel.SeverityLowInt:
			vulnStatic[model.FlagImageHasLowVuln] = true
		case imagesecModel.SeverityUnknownInt:
			vulnStatic[model.FlagImageHasUnknownVun] = true
		}
	}
	if fixed {
		flag = util.SetBit1(flag, model.FlagHasFixedVuln)
	} else {
		flag = util.SetBit0(flag, model.FlagHasFixedVuln)
	}

	for i := model.FlagImageHasUnknownVun; i <= model.FlagImageHasCriticalVuln; i++ {
		if vulnStatic[int64(i)] {
			flag = util.SetBit1(flag, uint64(i))
		} else {
			flag = util.SetBit0(flag, uint64(i))
		}
	}

	baseImage := data.ToImageBaseResponse()

	if len(baseImage.SensitiveFixSuggestion) > 0 || len(baseImage.VulnFixSuggestion) > 0 {
		flag = util.SetBit1(flag, model.FlagImageHasFixSuggest)
	} else {
		flag = util.SetBit0(flag, model.FlagImageHasFixSuggest)
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
		logging.Get().Err(err).Int64("imageID", imageID).Msg("UpdateImage")
		return err
	}
	logging.Get().Info().Int64("imageID", imageID).Interface("updater", updater).Msg("CreateScanResult UpdateImage")
	return nil
}

func (s *ScanResultReportSrv) GetImageInfo(ctx context.Context, taskID, subtaskID int64) (imagesecModel.Image, error) {
	empty := imagesecModel.Image{}
	subtask, _, err := s.nodeTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
		SubtaskID: subtaskID,
		TaskID:    taskID,
	})
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("ScanResultReportSrv SearchScanTask")
		return empty, err
	}
	if len(subtask) == 0 {
		logging.Get().Info().Int64("subtaskID", subtaskID).Int64("taskID", taskID).Msg("ScanResultReportSrv not find subtask")
		return empty, err
	}
	image, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{UniqueId: subtask[0].ImageUniqueID})
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("ScanResultReportSrv SearchImage")
		return empty, err
	}

	if len(image) == 0 {
		logging.Get().Err(err).Int64("subtaskID", subtaskID).Int64("taskID", taskID).Uint64("ImageUniqueID", subtask[0].ImageUniqueID).Msg("ScanResultReportSrv not find image")
		return empty, fmt.Errorf("not find image:%d", subtask[0].ImageUniqueID)
	}
	logging.Get().Info().Int64("imageID", image[0].ID).Msg("ScanResultReportSrv GetImageInfo")
	return *(image[0]), nil
}

func (s *ScanResultReportSrv) UpdateSubtaskScanFinished(ctx context.Context, data imagesecTypes.ScanResult) error {
	subtask, _, err := s.nodeTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{SubtaskID: data.SubTaskID})
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", data.SubTaskID).Msg("SearchScanSubtask")
		return err
	}
	if len(subtask) == 0 {
		return fmt.Errorf("not find subtask:%d", data.SubTaskID)
	}
	if subtask[0].Status > imagesecModel.TaskStatusSendFinished {
		return fmt.Errorf("subtask stastus is %s,can not save scan data", subtask[0].StatusStr)
	}

	updater := map[string]interface{}{
		"status":     imagesecModel.ScanStatusStrToInt(data.StatusStr),
		"status_str": data.StatusStr,
	}
	if data.StatusStr == imagesecModel.TaskStatusFailedStr {
		updater["msg"] = data.Msg
		updater["reason"] = imagesecModel.TaskFailedReasonScanner
	}

	if err := s.nodeTaskDal.UpdateScanSubtask(ctx, imagesecModel.UpdateTaskParam{
		ID:      data.SubTaskID,
		Updater: updater,
	}); err != nil {
		logging.Get().Err(err).Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).
			Msg("ScanResultReportSrv UpdateSubtaskScanFinished")
		return err
	}
	logging.Get().Info().Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Interface("updater", updater).
		Msg("ScanResultReportSrv UpdateSubtaskScanFinished succeed")
	return nil
}

func (s *ScanResultReportSrv) CreatePkgVuln(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {

	// match vuln
	results, err := s.matchVuln(&data)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", data.TaskID).Int64("subtaskID", data.SubTaskID).
			Msg("ScanResultReportSrv not match vuln")
		return err
	}

	pkgs := make([]*imagesecModel.Pkg, 0)
	pkgToImage := make([]*imagesecModel.PkgToImage, 0)
	vuln := make([]*imagesecModel.Vuln, 0)
	vulnView := make([]*imagesecModel.VulnView, 0)
	vulnIssue := make([]*imagesecModel.VulnToImage, 0)

	pkgMap := make(map[uint64]*imagesecModel.Pkg)
	pkgLayerMap := make(map[uint64]string)

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
				License:    strings.Split(pk.License, " "),
				DependsOn:  nil, // 老版本没有这些数据
				Filepath:   pk.FilePath,
				Class:      string(res.Class),
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

			pkgLayerMap[pkg.GenUniqueID()] = pk.Layer.Digest

			pkgToImage = append(pkgToImage, p2i)
		}

		for j := range res.Vulnerabilities {
			vul := res.Vulnerabilities[j]

			vu := &imagesecModel.Vuln{
				PkgUniqueID:      0,
				Name:             vul.VulnerabilityID,
				PkgName:          vul.PkgName,
				PkgVersion:       vul.InstalledVersion,
				PkgType:          res.Type,
				Description:      vul.Description,
				References:       vul.References,
				Class:            string(res.Class),
				CVSS:             make(map[string]imagesecModel.Cvss),
				CweIds:           vul.CweIDs,
				Title:            vul.Title,
				PublishDate:      util.GetTimeUnixMilli(vul.PublishedDate),
				ModificationData: util.GetTimeUnixMilli(vul.LastModifiedDate),
				Severity:         imagesecModel.GetSeverityInt(strings.ToUpper(vul.Severity)),
				FixedVersion:     vul.FixedVersion,
				Target:           strings.TrimSpace(res.Target),
				CreatedAt:        time.Now().UnixMilli(),
				UpdatedAt:        time.Now().UnixMilli(),
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

			s.AddDetailVuln(ctx, vu)

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

	if err := s.scanResultDal.CreateVuln(ctx, vuln); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateVuln")
		return err
	}

	if err := s.scanResultDal.CreatePkg(ctx, pkgs); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreatePkg")
		return err
	}
	if err := s.issueDal.CreatePkgToImage(ctx, imagesecModel.CreatePkgToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          pkgToImage,
	}); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreatePkgToImage")
		return err
	}

	if err := s.issueDal.CreateVulnToImage(ctx, imagesecModel.CreateVulnToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          vulnIssue,
	}); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateVulnToImage")
		return err
	}

	correlate.Vuln = vulnView
	correlate.Pkg = pkgs

	logging.Get().Info().Int("vulnCnt", len(vuln)).Int("pkgCnt", len(pkgs)).Uint64("imageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreatePkgVuln")
	return err
}

func (s *ScanResultReportSrv) CreateSensitive(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res := make([]*imagesecModel.SensitiveFile, 0)
	issue := make([]*imagesecModel.SensitiveToImage, 0)
	for i := range data.Sensitives.SensitiveFiles {
		pre := data.Sensitives.SensitiveFiles[i]
		ses := &imagesecModel.SensitiveFile{Name: pre.Filename}

		res = append(res, ses)
		issue = append(issue, &imagesecModel.SensitiveToImage{
			UniqueTarget:  ses.GenUniqueID(),
			ImageUniqueID: imageUniqueID,
		})
	}

	if err := s.scanResultDal.CreateSensitive(ctx, res); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitive")
		return err
	}
	if err := s.issueDal.CreateSensitiveToImage(ctx, imagesecModel.CreateSensitiveToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitiveToImage")
		return err
	}
	correlate.Sensitive = res
	logging.Get().Info().Int("sentCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateSensitive")
	return nil
}

func (s *ScanResultReportSrv) GenBoltDBChan(ctx context.Context) chan *BoltDB {
	out := make(chan *BoltDB)
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Stack().Msg("GenBoltDBChan")
			return
		}
		defer close(out)

		for {
			if global.VulnDBVersion == nil || global.VulnDBVersion.VulnVersion.TrivyVersion.Version == "" ||
				global.VulnDBVersion.VulnVersion.CustomDBVersion.Version == "" {

				logging.Get().Info().Msg("GenBoltDBChan not get global vuln db version")
				time.Sleep(time.Second * 10)
				continue
			}

			if s.vulnDBVersion == nil || s.vulnDBVersion.TrivyVersion.Version == "" || s.vulnDBVersion.CustomDBVersion.Version == "" ||
				s.vulnDBVersion.TrivyVersion.Version != global.VulnDBVersion.VulnVersion.TrivyVersion.Version ||
				s.vulnDBVersion.CustomDBVersion.Version != global.VulnDBVersion.VulnVersion.CustomDBVersion.Version ||
				s.availableBoltDB == nil {

				MustMkEmptyDir(filepath.Join(s.pvcPath, consts.NodeVulnDir))
				// MustCopyFile(filepath.Join(global.PVCPath, scannermodel.TrivyDBPath), filepath.Join(s.pvcPath, consts.NodeTrivyDBPath))
				MustCopyFile(filepath.Join(global.PVCPath, scannermodel.CustomDBPath), filepath.Join(s.pvcPath, consts.NodeCustomDBPath))

				s.vulnDBVersion = &global.VulnDBVersion.VulnVersion

				boltDB := BoltDB{
					// VulnBoltDB:  MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeTrivyDBPath)),
					CnvdBoltDB:  MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeCustomDBPath)),
					CnnvdBoltDB: MustOpenBoltDB(filepath.Join(s.pvcPath, consts.NodeCustomDBPath)),
				}
				logging.Get().Info().Msg("GenBoltDBChan rebuild boltdb")
				s.availableBoltDB = &boltDB
			}
			out <- s.availableBoltDB
		}
	}()
	return out
}

func (s *ScanResultReportSrv) AddDetectTask(ctx context.Context) error {

	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Stack().Msg("AddDetectTask")
			return
		}

		for task := range s.detectImageChan {

			logging.Get().Info().Interface("detectTask", task).Msg("AddDetectTask get detect task")

			if task.RetryCnt > consts.DefaultMaxRetryCount {
				logging.Get().Info().Int64("imageID", task.ImageID).Msg("AddDetectTask exceed max retry")
				continue
			}
			// 防止主从延迟
			if time.Now().Unix()-task.CreatedAt < consts.DefaultSlaveDelay {
				time.Sleep(time.Second * consts.DefaultSlaveDelay)
			}
			imageSearchParam := imagesecModel.ImageListParam{ImageIds: []int64{task.ImageID}, ImageFromType: task.ImageFromType}

			if err := s.imageDetectSrv.CreateImageDetectTask(ctx, imageSearchParam, imagesecModel.SearchSecurityPolicyParam{},
				imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectPriorityScan, ScanSubTaskID: task.SubtaskID}); err != nil {
				logging.Get().Err(err).Int64("imageID", task.ImageID).Msg("AddDetectTask")
				continue
			}
			logging.Get().Info().Int64("imageID", task.ImageID).Msg("AddDetectTask succeed")
		}
	}()
	return nil
}

func (s *ScanResultReportSrv) CreateMalware(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res := make([]*imagesecModel.Malware, 0)
	issue := make([]*imagesecModel.MalwareToImage, 0)

	aviraV := &imagesecModel.MalwareVersion{
		EngineVersion: data.Malwares.AviraEngineVersion.Version,
		EngineComment: data.Malwares.AviraEngineVersion.Comment,
		Enable:        true,
	}
	aviraV.UniqueID = aviraV.GenUniqueID()

	clamV := &imagesecModel.MalwareVersion{
		EngineVersion: data.Malwares.ClamAvEngineVersion.Version,
		EngineComment: data.Malwares.ClamAvEngineVersion.Comment,
		Enable:        true,
	}
	clamV.UniqueID = aviraV.GenUniqueID()

	avir := data.Malwares.AviraScanResults
	for j := range avir {
		for i := range avir[j].Malware {
			ses := &imagesecModel.Malware{
				Name:        avir[j].Malware[i].Name,
				Filename:    avir[j].FilePathInContainer,
				Hash:        avir[j].Hash,
				MalwareType: avir[j].Malware[i].Type,
				Description: avir[j].Malware[i].Description,
				Version:     aviraV.UniqueID,
			}
			res = append(res, ses)
			issue = append(issue, &imagesecModel.MalwareToImage{
				UniqueTarget:  ses.GenUniqueID(),
				ImageUniqueID: imageUniqueID,
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
			res = append(res, ses)
			issue = append(issue, &imagesecModel.MalwareToImage{
				UniqueTarget:  ses.GenUniqueID(),
				ImageUniqueID: imageUniqueID,
			})
		}
	}
	if err := clamV.Check(); err == nil {
		if err := s.versionDal.CreateMalwareVersion(ctx, clamV); err != nil {
			logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalwareVersion")
		}
	}

	if err := aviraV.Check(); err == nil {
		if err := s.versionDal.CreateMalwareVersion(ctx, aviraV); err != nil {
			logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalwareVersion")
		}
	}

	if err := s.scanResultDal.CreateMalware(ctx, res); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalware")
		return err
	}
	if err := s.issueDal.CreateMalwareToImage(ctx, imagesecModel.CreateMalwareToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalwareToImage")
		return err
	}
	correlate.Malware = res
	logging.Get().Info().Int("malwareCnt", len(res)).Uint64("imageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateMalware")
	return nil
}

func (s *ScanResultReportSrv) CreateWebshell(ctx context.Context, data imagesecTypes.ScanResult, imageUniqueID uint64,
	correlate *imagesecModel.ImageWithCorrelateData2) error {
	res1 := make([]*imagesecModel.Webshell, 0)
	res2 := make([]*imagesecModel.WebshellView, 0)
	issue := make([]*imagesecModel.WebshellToImage, 0)

	wv := imagesecModel.WebshellVersion{
		EngineVersion: data.Webshells.HmEngineVersion.Version,
		EngineComment: data.Webshells.HmEngineVersion.Comment,
		EngineHash:    data.Webshells.HmEngineVersion.Hash,
		Enable:        true,
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
		ses.UniqueID = ses.GenUniqueID()
		ses.Version = wv.UniqueID

		res1 = append(res1, ses)
		res2 = append(res2, ses.ToWebshellView())

		issue = append(issue, &imagesecModel.WebshellToImage{
			UniqueTarget:  ses.UniqueID,
			ImageUniqueID: imageUniqueID,
		})
	}

	if err := s.versionDal.CreateWebshellVersion(ctx, &wv); err != nil {
		logging.Get().Debug().Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateWebshellVersion")
	}

	if err := s.scanResultDal.CreateWebshell(ctx, res1); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateWebshell")
		return err
	}
	if err := s.issueDal.CreateWebshellToImage(ctx, imagesecModel.CreateWebshellToImageParam{
		ImageUniqueID: imageUniqueID,
		Data:          issue,
	}); err != nil {
		logging.Get().Err(err).Uint64("ImageUniqueID", imageUniqueID).Msg("ScanResultReportSrv CreateWebshellToImage")
		return err
	}
	correlate.Webshell = res2

	logging.Get().Info().Int("webshellCnt", len(res1)).Uint64("imageUniqueID", imageUniqueID).
		Msg("ScanResultReportSrv CreateWebshell")
	return nil
}

func (s *ScanResultReportSrv) ReceiveNodeReport(ctx context.Context) error {

	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("ScanResultReportSrv scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	logging.Get().Info().Msg("ScanResultReportSrv scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Stack().Msg("ScanResultReportSrv")
		}

		if err := s.ReceiveMsg(ch); err != nil {
			logging.Get().Err(err).Msg("ScanResultReportSrv")
		}
	}()

	logging.Get().Error().Msg("ScanResultReportSrv receive kafka started successfully")

	return nil
}

func (s *ScanResultReportSrv) ReceiveImageScanResult(ctx context.Context, msg kafka.Message) error {
	var data imagesecTypes.ScanResult
	err := json.Unmarshal(msg.Value, &data)
	if err != nil {
		logging.Get().Err(err).Str("data", string(msg.Value)).Msg("failed to unmarshal scan image result msg")
		return err
	}

	logging.Get().Debug().Int64("subtaskID", data.SubTaskID).Interface("data", data).Msg("receive image scan result report")
	logging.Get().Info().Int64("subtaskID", data.SubTaskID).Int64("taskID", data.TaskID).Str("msg", data.Msg).
		Msg("receive image scan result report")

	if err := s.CreateScanResult(ctx, data); err != nil {
		logging.Get().Err(err).Msg("CreateScanResult")
		return err
	}

	return nil
}

func (s *ScanResultReportSrv) ReceiveMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(model.NodeImageScanResultTopic, model.NodeImageScanResultGroup, s.ReceiveImageScanResult)
	if err != nil {
		logging.Get().Err(err).Msg("failed to sub message queue")
		return err
	}
	logging.Get().Info().Msg("sub message queue ok")
	<-stopCh
	logging.Get().Info().Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

func (s *ScanResultReportSrv) AddDetailVuln(ctx context.Context, vuln *imagesecModel.Vuln) {
	if vuln == nil {
		return
	}

	timeoutCtx, canFunc := context.WithTimeout(ctx, 10*time.Minute)
	defer canFunc()

	var boltDB *BoltDB
	select {
	case boltDB = <-s.boltDBChan:
		break
	case <-timeoutCtx.Done():
		logging.Get().Info().Msg("boltDBChan time out")
		return
	}

	// boltData, err := GetVulnDetailFromBolt(boltDB.VulnBoltDB, vuln.Name)
	// if err != nil {
	// 	logging.Get().Err(err).Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetVulnDetailFromBolt")
	// }
	cnnvdData, err := GetCnnvdFromBolt(boltDB.CnnvdBoltDB, vuln.Name)
	if err != nil {
		logging.Get().Info().Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetCnnvdFromBolt not get cnnvd")
	}
	cnvdData, err := GetCnvdFromBolt(boltDB.CnvdBoltDB, vuln.Name)
	if err != nil {
		logging.Get().Info().Str("vulnID", vuln.Name).Msg("ScanResultReportSrv GetCnvdFromBolt not get cnvd")
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
	}
	logging.Get().Debug().Str("vulnID", vuln.Name).Msg("ScanResultReportSrv AddDetailVuln")
}

func NewScanResultReportSrv(
	nodeTaskDal imagesecStore.ScanTaskDal,
	imageDal imagesecStore.ImageMetaDal,
	scanResultDal imagesecStore.ScanResultDal,
	issueDal imagesecStore.ScanIssueDal,
	versionDal imagesecStore.ScanVersionDal,
	imageDetectSrv ImageDetectTaskService,
	mqReader mq.Reader,
) *ScanResultReportSrv {

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
		detectImageChan: make(chan DetectImageData),
	}
	srv.boltDBChan = srv.GenBoltDBChan(context.Background())

	return srv
}
