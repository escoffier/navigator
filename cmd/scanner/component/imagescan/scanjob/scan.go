package scanjob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/mq"

	global2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	aviraengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/avira"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/clean"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/hm"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/license"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/modify"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/prepare"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/sensitive"
	scanTrivy "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/trivy"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

var registryImageScan *RegImageScan

type RegImageScan struct {
	ScanCachePath string
	MqWriter      mq.Writer
	RedisCli      *redis.Client
	SubtaskChan   chan imagesecTypes.ScanSubTask
	TaskQueue     *TaskQueue
	ScanTicker    chan int64
	Config        ScanConfig
	Log           *scannerUtils.LogEvent
}

func (s *RegImageScan) Check() error {
	if s.MqWriter == nil {
		return fmt.Errorf("not init MqWriter")
	}
	if s.RedisCli == nil {
		return fmt.Errorf("not init RedisCli")
	}
	return nil
}

// 增加超时控制
func (s *RegImageScan) ScanAndSend(ctx context.Context, subtask imagesecTypes.ScanSubTask) error {

	defer s.DeleteTaskQueue(ctx, subtask.SubTaskID)

	if subtask.ScanTimeout <= 0 {
		subtask.ScanTimeout = consts.DefaultScanTimeout
	}

	result := &imagesecTypes.ReportScanResult{
		UUID:          subtask.GenUniqueID(),
		TaskID:        subtask.TaskID,
		SubTaskID:     subtask.SubTaskID,
		ImageUniqueID: subtask.RegImageMeta.UniqueID,
		Errors:        make([]error, 0),
	}

	// 准备工作
	s.Log.Debug().Str("ScanCachePath", s.ScanCachePath).Msg("RegImageScan")
	prep := prepare.NewRegImagePreparer(s.ScanCachePath).ImageScanJob(ctx, subtask)

	mo := modify.NewResultModify()

	cle := clean.NewScanClear()
	sendFile := report.NewSendFile(s.MqWriter, s.Config.MaxSingeFileSize)
	sendResult := report.NewSendResult(s.MqWriter)

	jobs := s.GetImageScanJob(ctx, prep)

	s.Log.Info().Int("jobCnt", len(jobs)).Msg("GetImageScanJob")

	if len(prep.Errors) > 0 {
		result.Errors = append(result.Errors, prep.Errors...)
	}

	out := make(chan []imagesecTypes.ScanJobResult)
	defer close(out)
	// 扫描任务
	for i := range jobs {
		go func(job types.ImageScanJob, prep *imagesecTypes.PrepareScan, out chan []imagesecTypes.ScanJobResult) {
			res := job.ImageScan(ctx, prep)
			out <- res
		}(jobs[i], prep, out)
	}
	// 等待接收结果
	for i := 0; i < len(jobs); i++ {
		res := <-out
		for j := range res {
			result = Merge(result, res[j])
		}
	}

	// 千万注意，这些job 是有顺序的
	_ = mo.ConvertScanStatus(ctx, result)
	_ = mo.ConvertToContainerPath(ctx, prep, result)
	_ = sendResult.Send(ctx, prep, result)

	// 发送文件
	_ = mo.ConvertToHostPath(ctx, prep, result)
	_ = sendFile.Send(ctx, prep, result)

	// 执行清理操作
	_ = cle.Clear(ctx, prep)

	s.Log.Debug().Str("subtask", subtask.LogStr()).Interface("result", result).
		Msg("scanResult scan registry image end")

	s.Log.Info().Str("subtask", subtask.LogStr()).Str("result", result.LogStr()).
		Msg("scanResult scan registry image end")

	return nil
}

func (s *RegImageScan) ReceiveScanSubtask(ctx context.Context, subtask imagesecTypes.ScanSubTask) error {
	s.Log.Info().Str("subtask", subtask.LogStr()).Msg("receive scan subtask")
	exit := s.TaskQueue.Get(subtask.SubTaskID)
	if exit {
		s.Log.Info().Str("subtask", subtask.LogStr()).Msg("scan task is running")
		return nil
	}
	go func() { s.SubtaskChan <- subtask }()
	return nil
}

func (s *RegImageScan) DeleteTaskQueue(ctx context.Context, subtaskID int64) {
	// 延迟删除，主要是为了防止主集群持续发送
	time.Sleep(time.Minute * 2)
	s.TaskQueue.Delete(subtaskID)
}

func (s *RegImageScan) DoScanImageTask(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("DoScanImageTask recover panic")
			}
		}()

		for ta := range s.SubtaskChan {
			cnt := <-s.ScanTicker

			s.Log.Info().Int64("enginNum", cnt).Msg("get task engin")

			go func(ta imagesecTypes.ScanSubTask, cnt int64) {
				defer func() {
					if r := recover(); r != nil {
						s.Log.Error().Str("Stack", string(debug.Stack())).Msg("DoScanImageTask panic")
					}
				}()
				_ = s.ScanAndSend(ctx, ta)
				s.ScanTicker <- cnt + 1
			}(ta, cnt)
		}
	}()
	return nil
}

func NewRegImageScan(mqWriter mq.Writer, redisClient *redis.Client, opt ...Option) (*RegImageScan, error) {
	if registryImageScan != nil {
		return registryImageScan, nil
	}
	if global2.ScannerOpts.PvcPath == "" {
		return nil, fmt.Errorf("not get pvc path")
	}
	registryImageScan = &RegImageScan{
		ScanCachePath: filepath.Join(global2.ScannerOpts.PvcPath, "scanImage"),
		MqWriter:      mqWriter,
		RedisCli:      redisClient,
		SubtaskChan:   make(chan imagesecTypes.ScanSubTask),
		TaskQueue:     NewTaskQueue(),
		ScanTicker:    make(chan int64),
		// default value
		Config: ScanConfig{
			CacheCleanPerInterval: 60 * 60,
			MaxSingeFileSize:      1024 * 1024,
			ScanEnginNum:          10,
			ImageCacheURL:         "0.0.0.0:5566/",
			SubtaskParallel:       consts.MaxInprogressSubtaskPerNode,
		},
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("scanRegImage"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	pa := global2.ScannerOpts.ParallelTaskNum * global2.ScannerOpts.ParallelSubTaskNum
	if pa > 0 {
		registryImageScan.Config.SubtaskParallel = int64(pa)
	}
	if global2.ScannerOpts.CacheCleanPerInterval > 0 {
		registryImageScan.Config.CacheCleanPerInterval = global2.ScannerOpts.CacheCleanPerInterval
	}

	for i := range opt {
		opt[i](registryImageScan)
	}
	if err := registryImageScan.Check(); err != nil {
		return nil, err
	}

	_ = registryImageScan.DoScanImageTask(context.Background())

	for i := 0; i < int(registryImageScan.Config.SubtaskParallel); i++ {
		go func(i int64) { registryImageScan.ScanTicker <- i }(int64(i))
	}
	registryImageScan.Monitor(context.Background())

	return registryImageScan, nil
}

func (s *RegImageScan) GetImageScanJob(ctx context.Context, pre *imagesecTypes.PrepareScan) []types.ImageScanJob {

	scanJobs := make([]types.ImageScanJob, 0)
	if sesJob, err := sensitive.NewScanSensitiveSrv(); err != nil {
		s.Log.Err(err).Msg("can not create sensitiveSrv")
		pre.Errors = append(pre.Errors, err)
	} else {
		scanJobs = append(scanJobs, sesJob)
	}

	scanJobs = append(scanJobs, license.NewScanLicense())

	if trivyJob, err := scanTrivy.NewTrivySrv(scanTrivy.WithRedisCli(s.RedisCli)); err != nil {
		s.Log.Err(err).Msg("can not create trivyJob")
		pre.Errors = append(pre.Errors, err)
	} else {
		scanJobs = append(scanJobs, trivyJob)
	}

	if pre.Subtask.DeepScan {
		srv, err := aviraengin.NewSavServer()
		if err != nil {
			s.Log.Err(err).Msg("can not create NewSavServer")
			pre.Errors = append(pre.Errors, err)
		} else {
			scanJobs = append(scanJobs, srv)
		}

		if hmJob, err := hm.NewScanHM(); err != nil {
			s.Log.Err(err).Msg("can not create NewScanHM")
			pre.Errors = append(pre.Errors, err)
		} else {
			scanJobs = append(scanJobs, hmJob)
		}
	}

	return scanJobs
}

func (s *RegImageScan) Monitor(ctx context.Context) {
	// 扫描过程可能因为各种各样的原因，导致异常退出而没有来的及清理临时文件
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("Monitor")
			}
		}()
		ticker := time.NewTicker(time.Minute * 10)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.cleanCacheFile(ctx)
		}
	}()

}

func Merge(result *imagesecTypes.ReportScanResult, res imagesecTypes.ScanJobResult) *imagesecTypes.ReportScanResult {
	if result == nil {
		result = &imagesecTypes.ReportScanResult{}
	}
	result.Malware.ClamAvScanResults = append(result.Malware.ClamAvScanResults, res.ClamAvScan...)
	result.Webshell.HmWebshells = append(result.Webshell.HmWebshells, res.Webshell...)
	result.OriginArtifact = append(result.OriginArtifact, res.OriginArtifact...)
	result.Sensitives.SensitiveFiles = append(result.Sensitives.SensitiveFiles, res.Sensitive...)

	result.SaveFileToKafka = append(result.SaveFileToKafka, res.SaveFileToKafka...)
	result.Errors = append(result.Errors, res.Errors...)

	for i := range res.AviraScan {
		avi := imagesecTypes.AviraScanResult{
			Filename: res.AviraScan[i].Filename,
			MD5:      res.AviraScan[i].MD5,
			Malware: []imagesecTypes.AviraMalware{{
				Type:        res.AviraScan[i].Type,
				Name:        res.AviraScan[i].Name,
				Description: res.AviraScan[i].Description,
			}},
			Layer: res.AviraScan[i].Layer,
		}
		result.Malware.AviraScanResults = append(result.Malware.AviraScanResults, avi)
	}

	for i := range res.License {
		lic := res.License[i]
		lic.Content = nil // 不保存文件内容
		result.License = append(result.License, lic)
	}

	if res.OS.Name != "" && result.OS.Name == "" {
		result.OS = res.OS
	}

	// 通知已缓存和可缓存的信息缓存
	// 加缓存
	ca := imagesecTypes.CacheScan{
		Issue:      res.Issue,
		CanInCache: len(res.Errors) == 0 && res.Scanned,
		InCache:    res.InCache,
		Layer:      res.Layer,
	}
	switch res.Issue {
	case imagesecModel.WebshellCacheData:
		result.WebshellCache = append(result.WebshellCache, ca)
	case imagesecModel.MalwareCacheData:
		result.MalwareCache = append(result.MalwareCache, ca)
	case imagesecModel.SensitiveCacheData:
		result.SensitiveCache = append(result.SensitiveCache, ca)
	case imagesecModel.LicenseCacheData:
		result.LicenseCache = append(result.LicenseCache, ca)
	}

	return result
}

func (s *RegImageScan) cleanCacheFile(ctx context.Context) error {
	dir, err := os.ReadDir(s.ScanCachePath)
	if err != nil {
		s.Log.Err(err).Str("ScanCachePath", s.ScanCachePath).Msg("cleanCacheFile")
		return err
	}
	for _, fi := range dir {
		info, err := fi.Info()
		if err != nil {
			continue
		}
		if time.Now().Unix()-info.ModTime().Unix() > s.Config.CacheCleanPerInterval {
			fn := filepath.Join(s.ScanCachePath, fi.Name())
			s.Log.Info().Str("file", fn).Msg("cache file in scanned has expired and cleaned")
			_ = os.RemoveAll(fn)
		}
	}
	s.Log.Info().Str("ScanCachePath", s.ScanCachePath).Msg("clean cache file")
	return nil
}

func (s *RegImageScan) DoScanJob(ctx context.Context, job types.ImageScanJob, prep *imagesecTypes.PrepareScan, wg *sync.WaitGroup, out chan []imagesecTypes.ScanJobResult) {
	res := job.ImageScan(ctx, prep)
	out <- res
}
