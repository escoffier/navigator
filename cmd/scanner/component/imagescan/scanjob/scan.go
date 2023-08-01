package scanjob

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	aviraengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/avira"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/hm"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/prepare"
	scanTrivy "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/trivy"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

var registryImageScan *RegistryImageScan

type RegistryImageScan struct {
	MqWriter mq.Writer

	ScanSubtaskChan chan imagesecTypes.ScanSubTask
	TaskQueue       *TaskQueue
	// 主集群会控制下发任务的数量，但是各子集群的配置可能不一样，所以子集群也需要控制并发度
	ScanEnginNum  chan int64
	ScanP         *prepare.ScanPrepare
	TrivyEngin    *scanTrivy.TrivyEngin
	AviraEngin    *aviraengin.AviraSrv
	HM            *hm.ScanHM
	ImageCacheURL string
}

// 增加超时控制
func (s *RegistryImageScan) ScanAndSend(ctx context.Context, subtask imagesecTypes.ScanSubTask) error {
	defer s.DeleteTaskQueue(ctx, subtask.SubTaskID)

	if subtask.ScanTimeout <= 0 {
		subtask.ScanTimeout = consts.DefaultScanTimeout
	}

	timeoutCtx, cancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(subtask.ScanTimeout))
	defer cancelFunc()

	pullImageConfig := types.Config{
		RepoName: subtask.RegImageMeta.Repo,
		Tag:      subtask.RegImageMeta.Tag,
		URL:      subtask.RegInfo.Url,
		Username: subtask.RegInfo.Username,
		Password: subtask.RegInfo.Password,
	}

	pullJob := NewPullImageJob(pullImageConfig)
	errs := make([]error, 0)
	malwareJob := NewNScanMalicious(s.MqWriter)
	sensitiveJob := NewScanSensitive(subtask.SensitiveRules, s.MqWriter)
	vulnJob := NewScanVuln()
	webshellJob := NewScanWebshell(s.MqWriter)
	licenseJob := NewScanLicense(s.MqWriter)
	deleteJob := NewDeleteLayer()

	logging.Get().Info().Str("module", "imagescan").Str("executor", "pull-image").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	artifact, err := pullJob.Run(timeoutCtx)
	if err != nil {
		errs = append(errs, err)
	}

	logging.Get().Info().Str("module", "imagescan").Str("executor", "pull-image").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "malware").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	malwareRes := malwareJob.DoTask(timeoutCtx, Param(artifact), subtask.DeepScan)

	if malwareRes.Err != nil {
		errs = append(errs, malwareRes.Err)
	}
	logging.Get().Info().Str("module", "imagescan").Str("executor", "malware").
		Int("cnt", len(malwareRes.Ma)).Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "sensitive").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	sens, err := sensitiveJob.Scan(timeoutCtx, Param(artifact))
	if err != nil {
		errs = append(errs, err)
	}
	logging.Get().Info().Str("module", "imagescan").Str("executor", "sensitive").Int("cnt", len(sens)).
		Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "vuln").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	vuln, err := vulnJob.Scan(timeoutCtx, Param(artifact))
	if err != nil {
		errs = append(errs, err)
	}
	logging.Get().Info().Str("module", "imagescan").Str("executor", "vuln").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "webshell").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	webs := webshellJob.DoTask(timeoutCtx, Param(artifact), subtask.DeepScan)
	if webs.Err != nil {
		errs = append(errs, webs.Err)
	}
	logging.Get().Info().Str("module", "imagescan").Str("executor", "webshell").Int("cnt", len(webs.WB)).
		Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "license").
		Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	lis, err := licenseJob.Scan(timeoutCtx, Param(artifact))
	if err != nil {
		errs = append(errs)
	}

	logging.Get().Info().Str("module", "imagescan").Str("executor", "license").Int("cnt", len(lis)).
		Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	for i := range errs {
		logging.Get().Err(errs[i]).Str("imageName", subtask.RegImageMeta.ImageName()).
			Int64("subtaskID", subtask.SubTaskID).Int64("taskID", subtask.TaskID).Msg("scan registry image")
	}

	scanResult := conversion(subtask, malwareRes.Ma, malwareRes.WF, sens, vuln, webs.WB, lis, errs)

	// send to kafka
	sendData, err := json.Marshal(scanResult)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("subTaskID", scanResult.SubTaskID).Msg("failed to marshal")
		return err
	}
	outCtx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()

	err = s.MqWriter.Write(outCtx, model.NodeImageScanResultTopic, kafka.Message{
		Key:   []byte(model.NodeImageScanResultKey),
		Value: sendData,
	})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Int64("subTaskID", scanResult.SubTaskID).Msg("send result to kafka failed")
		return err
	}

	logging.Get().Info().Str("module", "imagescan").Str("imageName", subtask.RegImageMeta.ImageName()).
		Int64("taskID", subtask.TaskID).
		Int64("subtaskID", subtask.SubTaskID).Int("vuln", len(scanResult.VulnResults)).
		Int("sensitive", len(scanResult.Sensitives.SensitiveFiles)).
		Int("webshell", len(scanResult.Webshells.HmWebshells)).
		Int("malware", len(scanResult.Malwares.ClamAvScanResults)).
		Int("license", len(scanResult.License)).
		Str("image", subtask.RegImageMeta.ImageName()).
		Msg("scanResult scan registry image end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "send kafka").Int64("subtaskID", subtask.SubTaskID).Msg("scan end")

	logging.Get().Info().Str("module", "imagescan").Str("executor", "delete layer").Int64("subtaskID", subtask.SubTaskID).Msg("scan start")
	_ = deleteJob.Run(timeoutCtx, Param(artifact))

	logging.Get().Info().Str("module", "imagescan").Str("executor", "delete layer").Int64("subtaskID", subtask.SubTaskID).Msg("scan end")
	return nil
}

func (s *RegistryImageScan) ReceiveScanSubtask(ctx context.Context, subtask imagesecTypes.ScanSubTask) error {
	exit := s.TaskQueue.Get(subtask.SubTaskID)
	if exit {
		logging.Get().Info().Str("module", "imagescan").Str("imageName", subtask.RegImageMeta.ImageName()).
			Int64("subtaskID", subtask.SubTaskID).
			Msg("scan task is running")
		return nil
	}
	go func() { s.ScanSubtaskChan <- subtask }()
	return nil
}

func (s *RegistryImageScan) DeleteTaskQueue(ctx context.Context, subtaskID int64) {
	// 延迟删除，主要是为了防止主集群持续发送
	time.Sleep(time.Minute * 2)
	s.TaskQueue.Delete(subtaskID)
}

func (s *RegistryImageScan) DoScanImageTask(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("DoScanImageTask recover panic")
			}
		}()

		for ta := range s.ScanSubtaskChan {
			cnt := <-s.ScanEnginNum
			logging.Get().Info().Str("module", "imagescan").Int64("enginNum", cnt).Msg("get task engin")

			go func(ta imagesecTypes.ScanSubTask, cnt int64) {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Msg("DoScanImageTask panic")
					}
				}()
				_ = s.ScanAndSend(ctx, ta)

				// res, err := s.PrepareScan(ctx, ta)
				// if err != nil {
				// 	logging.Get().Info().Str("module", "imagescan").Msg("PrepareScan")
				// 	return
				// }
				// _ = s.ScanVuln(ctx, ta)
				// _ = s.ScanAvira(ctx, res)
				// _ = s.ScanWebshell(ctx, res)

				s.ScanEnginNum <- cnt + 1
			}(ta, cnt)
		}
	}()
	return nil
}

func NewRegistryImageScan(mqWriter mq.Writer, cli redis.Client) (*RegistryImageScan, error) {
	if registryImageScan != nil {
		return registryImageScan, nil
	}

	// trivyEngin, err := scanTrivy.NewTrivyEngin(cli)
	// if err != nil {
	// 	logging.Get().Err(err).Str("module", "imagescan").Msg("NewTrivyEngin")
	// 	return nil, err
	// }
	// asvServer, err := aviraengin.NewSavServer()
	// if err != nil {
	// 	logging.Get().Err(err).Str("module", "imagescan").Msg("NewSavServer")
	// 	return nil, err
	// }
	// scanHM, err := hm.NewScanHM()
	// if err != nil {
	// 	logging.Get().Err(err).Str("module", "imagescan").Msg("NewScanHM")
	// 	return nil, err
	// }

	s := &RegistryImageScan{
		MqWriter:        mqWriter,
		ScanSubtaskChan: make(chan imagesecTypes.ScanSubTask, 1),
		TaskQueue:       NewTaskQueue(),
		ScanP:           prepare.NewPrepareImageScan(),
		// TrivyEngin:      trivyEngin,
		// AviraEngin:    asvServer,
		// HM:            scanHM,
		ImageCacheURL: "0.0.0.0:5566/",
	}
	_ = s.DoScanImageTask(context.Background())

	subtaskParallel := global.SubtaskParallel

	if subtaskParallel <= 0 {
		subtaskParallel = consts.MaxInprogressSubtaskPerNode
	}

	s.ScanEnginNum = make(chan int64)

	for i := 0; i < subtaskParallel; i++ {
		go func(i int64) { s.ScanEnginNum <- i }(int64(i))
	}

	registryImageScan = s

	return registryImageScan, nil
}

// 漏洞，病毒等扫描出错后，任务失败，但是依然需要上传数据
func conversion(
	subtask imagesecTypes.ScanSubTask,
	malware []model.PerLayerMaliciousResult,
	webInfo []model.WebFrameInfo,
	sens []model.PerLayerSensitiveResult,
	rep *report.Report,
	webs []scannermodel.WebshellFileInfo,
	lis []model.PerLayerLicenseResult,
	errs []error,
) imagesecTypes.ScanResult {
	res := imagesecTypes.ScanResult{
		TaskID:         subtask.TaskID,
		SubTaskID:      subtask.SubTaskID,
		OS:             ftypes.OS{},
		VulnResults:    make([]imagesecTypes.VulnResult, 0),
		Sensitives:     imagesecTypes.SensitiveFileResults{},
		Malwares:       imagesecTypes.MalwareResults{},
		Webshells:      imagesecTypes.WebshellResults{},
		OriginArtifact: ftypes.ArtifactDetail{},
		License:        make([]imagesecTypes.License, 0),
		StatusStr:      imagesecModel.TaskStatusScanFinishedStr,
	}

	if rep != nil && rep.Metadata.OS != nil {
		res.OS = *rep.Metadata.OS
	}
	if rep != nil {
		for _, r := range rep.Results {
			// base info
			vulnRes := imagesecTypes.VulnResult{}
			vulnRes.Type = r.Type
			vulnRes.Class = string(r.Class)
			vulnRes.Target = r.Target

			res.OriginArtifact = r.Artifact

			logging.Get().Debug().Str("module", "imagescan").Int("packageNum", len(r.Packages)).Msg("transform res")
			for _, v := range r.Packages {
				pkg := imagesecTypes.Package{
					Name:       v.Name,
					Version:    v.Version,
					SrcName:    v.SrcName,
					SrcVersion: v.SrcVersion,
					License:    v.License,
					FilePath:   v.FilePath,
					Layer:      v.Layer.Digest,
				}
				vulnRes.Packages = append(vulnRes.Packages, pkg)
			}

			// extract vulns
			for _, v := range r.Vulnerabilities {
				vulnBrief := imagesecTypes.VulnerabilityBrief{
					Severity:         v.Severity,
					Class:            string(r.Class),
					ID:               v.VulnerabilityID,
					PkgName:          v.PkgName,
					InstalledVersion: v.InstalledVersion,
					FixedVersion:     v.FixedVersion,
					Layer:            v.Layer.Digest,
				}
				vulnRes.Vulnerabilities.Vulnerabilities = append(vulnRes.Vulnerabilities.Vulnerabilities, vulnBrief)
			}
			res.VulnResults = append(res.VulnResults, vulnRes)
		}
	}
	// sensitive file
	for _, ses := range sens {
		for _, p := range ses.Sensitives {
			pk := imagesecTypes.SensitiveFile{Filename: p.Name, Layer: ses.LayerDigest, MD5: p.Md5}
			res.Sensitives.SensitiveFiles = append(res.Sensitives.SensitiveFiles, pk)
		}
	}

	// malware
	// 当前版本不区分是那个扫描器的扫描结果，后期重构扫描器时再区分
	ms := make([]imagesecTypes.ClamAvScanResult, 0)

	for i := range malware {
		for j := range malware[i].VirusInfos {
			vi := malware[i].VirusInfos[j]
			mm := imagesecTypes.ClamAvScanResult{
				// "filepath":"/tmpscan/a1ec08056ec40da7cc34c242726678f33044bc7f8cea77373f83563214fa569c1693598192",
				Filename:     vi.FileName, // vi.UnzipPath 是程序的临时解压目录，不可使用:
				Hash:         vi.Md5,
				MalwareNames: []string{vi.VirusName},
				Layer:        malware[i].LayerDigest,
			}
			ms = append(ms, mm)
		}
	}
	res.Malwares.ClamAvScanResults = ms

	// webshell
	wss := make([]imagesecTypes.HmWebshell, 0)
	for _, w := range webs {
		wss = append(wss, imagesecTypes.HmWebshell{
			Filename:    w.FileName,
			MD5:         w.Md5Hash,
			Mod:         w.Mode,
			Size:        w.Size,
			Code:        w.MaliciousData,
			RiskLevel:   getWebshellLevel(w.Level),
			Description: w.Description,
		})
	}
	res.Webshells.HmWebshells = wss

	// license
	for i := range lis {
		for j := range lis[i].LicenseInfos {
			ly := lis[i].LicenseInfos[j]
			lyy := imagesecTypes.License{Name: ly.Name, Layer: lis[i].LayerDigest, Filename: ly.Filename, MD5: ly.MD5}
			res.License = append(res.License, lyy)
		}
	}
	webinfos := imagesecTypes.WebFrameInfo{
		ImageUUID: subtask.RegImageMeta.ImageUUID,
		Data:      make([]imagesecTypes.WebFrame, 0),
	}
	for i := range webInfo {
		webinfos.Data = append(webinfos.Data, imagesecTypes.WebFrame{
			FrameName: webInfo[i].FrameName,
			Version:   webInfo[i].Version,
			FilePath:  webInfo[i].FilePath,
			FileName:  webInfo[i].FileName,
			Language:  webInfo[i].Language,
		})
	}
	res.WebFrameInfo = webinfos

	if len(errs) > 0 {
		msg := make([]string, 0)
		for i := range errs {
			msg = append(msg, errs[i].Error())
			logging.Get().Err(errs[i]).Str("imageName", subtask.RegImageMeta.ImageName()).
				Int64("taskID", subtask.TaskID).Int64("subTaskID", subtask.SubTaskID).Msg("scan image")
		}
		res.StatusStr = imagesecModel.TaskStatusFailedStr
		res.Msg = strings.Join(msg, ",")
		return res
	}

	return res
}

func getWebshellLevel(n int) string {

	levelToString := map[int]string{
		1: imagesecModel.WebshellRiskLevelMaybe,
		2: imagesecModel.WebshellRiskLevelCertain,
	}
	if l, ok := levelToString[n]; ok {
		return l
	}
	return imagesecModel.WebshellRiskLevelMaybe
}

type Param map[string]interface{}
