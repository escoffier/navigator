package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"golang.org/x/sync/semaphore"

	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	ireneBinaryName        = "irene"
	defaultIrenePolicyName = "policy-node-image"
	defaultCacheDir        = "cache"
	defaultTimeout         = 300
)

type RunningSubTask struct {
	imagesec.ScanSubTask
	ScannerPID int // irene process id
}

type Manager struct {
	runningSubTasks     []RunningSubTask // used slice to record running tasks for map would not shrink
	ireneWorkingDir     string           // irene binary working dir
	taskQueue           *util.Queue      // scan task
	lock                sync.RWMutex
	mqWriter            mq.Writer
	runConfig           config.Config             // 运行时配置
	nodeImageConfig     imagesec2.NodeImageConfig // 扫描时配置，从console同步
	nodeImageConfigLock sync.RWMutex
	scanTaskWg          *sync.WaitGroup
	dbUpdateWg          *sync.WaitGroup
	subscribeChan       <-chan interface{}
}

func init() {
	err := services.RegisterService(&Manager{
		taskQueue:       helper.TaskQueue,
		ireneWorkingDir: global.WorkingDir,
		runningSubTasks: make([]RunningSubTask, 0),
		scanTaskWg:      helper.ScanTaskWg,
		dbUpdateWg:      helper.DBFileUpdateWg,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register image task manager service")
	} else {
		logging.Get().Info().Msg("register image task manager service ok")
	}
}

func (m *Manager) addRunningTask(r RunningSubTask) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.runningSubTasks = append(m.runningSubTasks, r)
	return nil
}

func (m *Manager) removeRunningTask(r RunningSubTask) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	for k, v := range m.runningSubTasks {
		if v.SubTaskID == r.SubTaskID {
			// remove from slice
			m.runningSubTasks = append(m.runningSubTasks[:k], m.runningSubTasks[k+1:]...)
			return nil
		}
	}

	return fmt.Errorf("not found subtask %v", r.SubTaskID)
}

func (m *Manager) scanOutputFile(subTaskId int64) string {
	return fmt.Sprintf("result-%d.json", subTaskId)
}

func (m *Manager) GetSavServerAddr() string {
	return fmt.Sprintf("tcp:127.0.0.1:%d", m.runConfig.AviraConfig.ListenPort)
}

func (m *Manager) deepScanOption() string {
	opts := ""
	for _, v := range m.runConfig.DeepScanConfig.Types {
		if v == config.DeepScanTypesAvira {
			opts = opts + fmt.Sprintf(" --scan-malware %s --malware-server %s --malware-client-num %d",
				services.ScanMalwareTypeAvira, m.GetSavServerAddr(), m.runConfig.AviraConfig.ClientNum)
			continue
		}
		if v == config.DeepScanTypesWebshell {
			opts = opts + " --scan-webshell tws "
			if len(m.runConfig.WebshellConfig.IncludeTypes) > 0 {
				opts = opts + fmt.Sprintf(" --webshell-types %s", strings.Join(m.runConfig.WebshellConfig.IncludeTypes, ","))
			}
		}
	}
	return opts
}

func (m *Manager) ScanCommOpt() string {
	opts := ""
	if len(m.runConfig.IreneConfig.LogLevel) > 0 {
		opts = fmt.Sprintf(" %s --log-level %s ", opts, m.runConfig.IreneConfig.LogLevel)
	}
	if m.runConfig.IreneConfig.DeeperDebug {
		opts = fmt.Sprintf(" %s --deeper-debug true ", opts)
	}
	// scan os-pkgs,lang-pkgs,disabled iac
	opts = fmt.Sprintf(" --disable-types=iac %v", opts)
	return opts
}

func (m *Manager) getTimeOutOpt() int64 {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	if m.nodeImageConfig.ScanTimeout <= 0 {
		return defaultTimeout
	}
	return m.nodeImageConfig.ScanTimeout * 60
}

func (m *Manager) shouldDeepScan() bool {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	return m.nodeImageConfig.DeepScan
}

func (m *Manager) makeScanCmd(imageName string, taskId int64) string {
	binaryPath := filepath.Join(m.ireneWorkingDir, ireneBinaryName)
	policyPath := filepath.Join(m.ireneWorkingDir, "policy", defaultIrenePolicyName)
	cachePath := filepath.Join(m.ireneWorkingDir, defaultCacheDir)

	// default scan cmd without malware and webshell opt
	cmdStr := fmt.Sprintf("%s local-scan %s -i %s --parse-pkgs-only --cache-dir %s --policy-file-name %s "+
		"--output %s -t %d --mount-prefix %s ",
		binaryPath, m.ScanCommOpt(), imageName, cachePath, policyPath,
		m.scanOutputFile(taskId), m.getTimeOutOpt(), m.runConfig.ScanConfig.MountPrefix)

	if m.shouldDeepScan() {
		cmdStr = fmt.Sprintf("%s %s", cmdStr, m.deepScanOption())
	}

	return cmdStr
}

func (m *Manager) transformWebshellToUpload(res *scanner_ci.PolicyResult) []scannermodel.WebshellSaveInfo {
	uploadWebshell := make([]scannermodel.WebshellSaveInfo, 0)
	for _, v := range res.WebshellResults.HmWebshells {
		saveInfo := scannermodel.WebshellSaveInfo{}
		saveInfo.FileMd5 = v.MD5
		saveInfo.Filename = v.Filename
		uploadWebshell = append(uploadWebshell, saveInfo)
	}
	return uploadWebshell
}

func (m *Manager) uploadWebshellFile(res []scannermodel.WebshellSaveInfo) error {
	for _, v := range res {
		data, err := os.ReadFile(v.Filename)
		if err != nil {
			logging.Get().Err(err).Str("file", v.Filename).Msg("failed to read webshell file")
			continue
		}
		v.Data = data
		saveByte, err := json.Marshal(v)
		if err != nil {
			logging.Get().Err(err).Str("file", v.Filename).Msg("failed to marshal webshell file data")
			continue
		}
		if err = m.mqWriter.Write(
			context.Background(),
			scannermodel.WebshellKafkaTopic,
			kafka.Message{
				Topic: scannermodel.WebshellKafkaTopic,
				Key:   []byte("node-image-webshell"),
				Value: saveByte,
			}); err != nil {
			logging.Get().Err(err).Str("file", v.Filename).Int("msgLen", len(saveByte)).Msg("failed to send webshell file to kafka")
		} else {
			logging.Get().Info().Str("file", v.Filename).Msg("success to upload webshell file to kafka")
		}
	}
	return nil
}

func (m *Manager) syncResult(t imagesec.ScanSubTask) error {
	resultFile := m.scanOutputFile(t.SubTaskID)
	defer func() {
		// remove file when synced
		if err := os.Remove(resultFile); err != nil {
			logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Str("resultFile", resultFile).Msg("failed to remove file")
		}
	}()
	logging.Get().Debug().Int64("subTaskID", t.SubTaskID).Str("resultFile", resultFile).Msg("start sync result")

	// read result from local file
	data, err := os.ReadFile(resultFile)
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Str("resultFile", resultFile).Msg("failed to read file")
		return err
	}
	tmpRes := scanner_ci.PolicyResult{}
	err = json.Unmarshal(data, &tmpRes)
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Str("resultFile", resultFile).Msg("failed to unmarshal")
		return err
	}

	// upload webshell file
	// copy res to avoid tmpRes changed by m.transformResult
	uploadWebshell := m.transformWebshellToUpload(&tmpRes)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()
		_ = m.uploadWebshellFile(uploadWebshell)
	}()

	// transform scan result
	scanResult := m.transformResult(&tmpRes)
	scanResult.TaskID = t.TaskID
	scanResult.SubTaskID = t.SubTaskID
	if tmpRes.ExitCode == 0 {
		scanResult.StatusStr = imagesecModel.TaskStatusScanFinishedStr
		scanResult.Msg = "ok"
	} else {
		scanResult.StatusStr = imagesecModel.TaskStatusFailedStr
		scanResult.Msg = "err"
	}
	logging.Get().Debug().
		Int64("subTaskID", t.SubTaskID).
		Int("aviraMalwareCnt", len(scanResult.Malwares.AviraScanResults)).
		Int("webshellCnt", len(scanResult.Webshells.HmWebshells)).
		Msg("result info")

	// send to kafka
	sendData, err := json.Marshal(scanResult)
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Msg("failed to marshal")
		return err
	}
	err = m.mqWriter.Write(context.Background(), model.NodeImageScanResultTopic, kafka.Message{
		Key:   []byte("node-image-result"),
		Value: sendData,
	})
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Msg("failed to send result to kafka")
		return err
	}

	return nil
}

func (m *Manager) scanImage(t imagesec.ScanSubTask) error {
	infoLog := func() *zerolog.Event {
		return logging.Get().Info().Int64("subTaskID", t.SubTaskID)
	}
	errLog := func(err error) *zerolog.Event {
		return logging.Get().Err(err).Int64("subTaskID", t.SubTaskID)
	}
	debugLog := func() *zerolog.Event {
		return logging.Get().Debug().Int64("subTaskID", t.SubTaskID)
	}

	infoLog().Msg("start scanning")

	imageName := ""
	if len(t.ImageMeta.RepoTags) == 0 {
		// local build image without repo tags,use image id instead
		imageName = t.ImageMeta.ImageId
	} else {
		// only need a repo tag
		imageName = t.ImageMeta.RepoTags[0]
	}

	cmdStr := m.makeScanCmd(imageName, t.SubTaskID)
	debugLog().Str("cmd", cmdStr).Msg("make cmd")

	cmd := exec.Command("sh", "-c", cmdStr)
	if m.runConfig.ScanConfig.RealTimeLog {
		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer) // real time output
		cmd.Stdout = mw
		cmd.Stderr = mw
	}
	err := cmd.Start()
	if err != nil {
		errLog(err).Msg("failed to scan")
		return err
	}

	// record task and it's process ID
	r := RunningSubTask{
		ScannerPID: cmd.Process.Pid,
	}
	r.SubTaskID = t.SubTaskID

	// cmd run wrapper
	runCmdFunc := func() error {
		_ = m.addRunningTask(r)
		defer func() {
			if err = m.removeRunningTask(r); err != nil {
				errLog(err).Msg("failed to remove running task")
			}
		}()

		// wait cmd run end
		err = cmd.Wait()
		if err != nil {
			errLog(err).Msg("failed to execute scan cmd")
			return err
		}
		return nil
	}

	// run scan
	err = runCmdFunc()
	if err != nil {
		errLog(err).Msg("failed to scan image")
		return err
	}
	infoLog().Msg("success to scan image")

	// sync result
	err = m.syncResult(t)
	if err != nil {
		errLog(err).Msg("failed to send result")
		return err
	}
	infoLog().Msg("send result ok")

	return nil
}

func (m *Manager) Type() services.ServiceType {
	return services.TypeServiceTaskManager
}

func (m *Manager) PreRun(cfg config.Config, nc imagesec2.NodeImageConfig, bs *util.BroadcastServer) error {
	// create msg que cli
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq writer")
		return err
	}
	m.mqWriter = mqWriter

	// copy config
	m.runConfig = cfg
	m.nodeImageConfig = nc

	m.subscribeChan = bs.Subscribe(string(services.TypeServiceTaskManager))
	return nil
}

func (m *Manager) updateNodeImageConfig(cfg imagesec2.NodeImageConfig) {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	m.nodeImageConfig = cfg
}

func (m *Manager) handleConfigModifiedEvent() {
	for {
		logging.Get().Debug().Msg("wait config modified event")
		select {
		case item := <-m.subscribeChan:
			switch typed := item.(type) {
			case types.NotifyEvent:
				event := item.(types.NotifyEvent)
				if event.Type == types.NotifyEventTypeConfigModified {
					logging.Get().Debug().Interface("event", event).Msg("recv config modified event")
					m.updateNodeImageConfig(event.NodeImageConfig)
					continue
				}
				logging.Get().Debug().Interface("event", event).Msg("not config modified event,ignore")
			default:
				logging.Get().Error().Msgf("subscribe msg type err.%v", typed)
			}
		}
	}
}

func (m *Manager) Run() error {
	// handle config modify event
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("panic: %v. Stack: %s", r, debug.Stack())
		}
		m.handleConfigModifiedEvent()
	}()

	// do task
	limit := semaphore.NewWeighted(m.runConfig.TaskConfig.ParallelNum)
	m.taskQueue.Consume(func(item interface{}) {
		switch typed := item.(type) {
		case imagesec.ScanSubTask:
			subTask := item.(imagesec.ScanSubTask)
			logging.Get().Info().Int64("taskID", subTask.TaskID).Int64("subTaskID", subTask.SubTaskID).
				Strs("image", subTask.ImageMeta.RepoTags).Msg("start scanning task")
			if err := limit.Acquire(context.Background(), 1); err != nil {
				logging.Get().Err(err).Msg("failed to acquire semaphore")
				return
			}

			// wait db file finish update
			m.dbUpdateWg.Wait()

			m.scanTaskWg.Add(1)
			go func(sp *semaphore.Weighted, t imagesec.ScanSubTask) {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Msgf("scan task panic: %v. stack: %s", r, debug.Stack())
					}
				}()
				defer sp.Release(1)
				defer m.scanTaskWg.Done()

				_ = m.scanImage(t)
			}(limit, subTask)
		default:
			logging.Get().Error().Msgf("task queue element type err.%v", typed)
		}
	})

	// block
	stopChan := make(chan struct{})
	<-stopChan
	return fmt.Errorf("node image task service exit")
}

func (m *Manager) transformResult(result *scanner_ci.PolicyResult) imagesec.ScanResult {
	res := imagesec.ScanResult{}
	if result.Artifact.Artifact.OS != nil {
		res.OS = *result.Artifact.Artifact.OS
	}
	res.OriginArtifact = result.Artifact.Artifact

	for _, r := range result.Vulnerabilities.Results {

		// base info
		vulnRes := imagesec.VulnResult{}
		vulnRes.Type = r.Type
		vulnRes.Class = string(r.Class)
		vulnRes.Target = r.Target

		logging.Get().Debug().Int("packageNum", len(r.Packages)).Msg("transform res")
		for _, v := range r.Packages {
			pkg := imagesec.Package{
				Name:       v.Name,
				Version:    v.Version,
				SrcName:    v.SrcName,
				SrcVersion: v.SrcVersion,
				License:    strings.Split(v.License, " "),
				FilePath:   v.FilePath,
				DependsOn:  nil, // todo: need high version fanal
			}
			vulnRes.Packages = append(vulnRes.Packages, pkg)
		}

		// extract vulns
		for _, v := range r.Vulnerabilities {
			vulnBrief := imagesec.VulnerabilityBrief{
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

	// sensitive file
	for _, r := range result.MatchSensitiveFiles.DefaultFiles {
		s := imagesec.SensitiveFile{
			Filename: r,
		}
		res.Sensitives.SensitiveFiles = append(res.Sensitives.SensitiveFiles, s)
	}

	// malware
	res.Malwares = result.MalwareResults
	res.Malwares.AviraEngineVersion.Hash = helper.GetSavApiBinaryHash()

	// webshell
	res.Webshells = result.WebshellResults

	return res
}
