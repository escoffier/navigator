package tasks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"

	"github.com/rs/zerolog"

	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"golang.org/x/sync/semaphore"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
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
	Subtask    imagesec.ScanSubTask
	ScannerPID int // irene process id
}

type ScanTaskManager struct {
	runningSubTasks     []RunningSubTask // used slice to record running tasks for map would not shrink
	ireneWorkingDir     string           // irene binary working dir
	taskQueue           *util.Queue      // scan task
	taskLock            sync.RWMutex
	mqWriter            mq.Writer
	runtimeConfig       config.Config                 // 运行时配置
	nodeImageConfig     imagesecModel.ImageScanConfig // 扫描时配置，从console同步
	nodeImageConfigLock sync.RWMutex
	scanTaskWg          *sync.WaitGroup
	dbUpdateWg          *sync.WaitGroup
	subscribeChan       <-chan interface{}
}

func init() {
	err := services.RegisterService(&ScanTaskManager{
		taskQueue:       helper.TaskQueue,
		ireneWorkingDir: global.WorkingDir,
		runningSubTasks: make([]RunningSubTask, 0),
		scanTaskWg:      helper.ScanTaskWg,
		dbUpdateWg:      helper.DBFileUpdateWg,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register image task manager service")
		return
	}
	logging.Get().Info().Msg("register image task manager service ok")
}

func (m *ScanTaskManager) addRunningTask(r RunningSubTask) error {
	m.taskLock.Lock()
	defer m.taskLock.Unlock()
	m.runningSubTasks = append(m.runningSubTasks, r)
	return nil
}

func (m *ScanTaskManager) removeRunningTask(r RunningSubTask) error {
	m.taskLock.Lock()
	defer m.taskLock.Unlock()
	for k, v := range m.runningSubTasks {
		if v.Subtask.SubTaskID == r.Subtask.SubTaskID {
			// remove from slice
			m.runningSubTasks = append(m.runningSubTasks[:k], m.runningSubTasks[k+1:]...)
			return nil
		}
	}

	return fmt.Errorf("not found subtask %v", r.Subtask.SubTaskID)
}

func (m *ScanTaskManager) scanOutputFile(subTask imagesec.ScanSubTask) string {
	return fmt.Sprintf("result-%s.json", subTask.UniqueID)
}

func (m *ScanTaskManager) GetSavServerAddr() string {
	return fmt.Sprintf("tcp:127.0.0.1:%d", m.runtimeConfig.AviraConfig.ListenPort)
}

func (m *ScanTaskManager) deepScanOption() string {
	opts := ""
	for _, v := range m.runtimeConfig.DeepScanConfig.Types {
		if v == config.DeepScanTypesAvira {
			opts = opts + fmt.Sprintf(" --scan-malware %s --malware-server %s --malware-client-num %d",
				consts.ScanMalwareTypeAvira, m.GetSavServerAddr(), m.runtimeConfig.AviraConfig.ClientNum)
			continue
		}
	}
	return opts
}

func (m *ScanTaskManager) ScanCommOpt() string {
	opts := ""
	if len(m.runtimeConfig.IreneConfig.LogLevel) > 0 {
		opts = fmt.Sprintf(" %s --log-level %s ", opts, m.runtimeConfig.IreneConfig.LogLevel)
	}
	if m.runtimeConfig.IreneConfig.DeeperDebug {
		opts = fmt.Sprintf(" %s --deeper-debug true ", opts)
	}
	if m.runtimeConfig.IreneConfig.Slow {
		opts = fmt.Sprintf(" %s --slow true ", opts)
	}
	// scan os-pkgs,lang-pkgs,disabled iac
	opts = fmt.Sprintf(" --disable-types=iac %v", opts)
	return opts
}

func (m *ScanTaskManager) getTimeOutOpt() int64 {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	if m.nodeImageConfig.ScanTimeout <= 0 {
		return defaultTimeout
	}
	return m.nodeImageConfig.ScanTimeout * 60
}

func (m *ScanTaskManager) shouldDeepScan() bool {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	return m.nodeImageConfig.DeepScan
}

func (m *ScanTaskManager) makeScanCmd(imageName string, subtask imagesec.ScanSubTask) []string {
	policyPath := m.GetPolicyPath(context.Background(), subtask)
	cachePath := filepath.Join(m.ireneWorkingDir, defaultCacheDir)

	// default scan cmd without malware and webshell opt
	cmdStr := fmt.Sprintf(" local-scan %s -i %s --parse-pkgs-only --cache-dir %s --policy-file-name %s "+
		"--output %s -t %d --mount-prefix %s ",
		m.ScanCommOpt(), imageName, cachePath, policyPath,
		m.scanOutputFile(subtask), m.getTimeOutOpt(), m.runtimeConfig.ScanConfig.MountPrefix)

	if m.shouldDeepScan() {
		cmdStr = fmt.Sprintf("%s %s", cmdStr, m.deepScanOption())
	}

	arr := strings.Split(cmdStr, " ")

	return arr
}

func (m *ScanTaskManager) transformWebshellToUpload(res *scanner_ci.PolicyResult) []scannermodel.WebshellSaveInfo {
	uploadWebshell := make([]scannermodel.WebshellSaveInfo, 0)
	for _, v := range res.WebshellResults.HmWebshells {
		saveInfo := scannermodel.WebshellSaveInfo{
			FileMd5:  v.MD5,
			Filename: v.Filename,
		}
		uploadWebshell = append(uploadWebshell, saveInfo)
	}
	return uploadWebshell
}

func (m *ScanTaskManager) uploadWebshellFile(res []scannermodel.WebshellSaveInfo) error {
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

func (m *ScanTaskManager) syncResult(t imagesec.ScanSubTask) error {
	resultFile := m.scanOutputFile(t)
	defer func() {
		// remove file when synced
		if err := os.Remove(resultFile); err != nil {
			logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Str("resultFile", resultFile).
				Msg("failed to remove file")
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
	} else {
		scanResult.StatusStr = imagesecModel.TaskStatusFailedStr
		scanResult.Msg = tmpRes.ExistMsg
	}
	logging.Get().Debug().
		Int64("subTaskID", t.SubTaskID).
		Int("aviraMalwareCnt", len(scanResult.Malwares.AviraScanResults)).
		Int("pkgCnt", len(scanResult.VulnResults)).
		Int("sensitiveCnt", len(scanResult.Sensitives.SensitiveFiles)).
		Int("vulnCnt", len(scanResult.VulnResults)).
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

func (m *ScanTaskManager) checkResultFile(err error, t imagesec.ScanSubTask) error {
	resultFile := m.scanOutputFile(t)
	if util.FileExists(resultFile) {
		return nil
	}

	// run irene cmd failed,not output file,we make a fake result file here
	logging.Get().Debug().Int64("subTaskID", t.SubTaskID).Msg("make a fake result file because irene run err.")

	exitCode := scanner_ci.CiPolicyResultCodeException
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}
	tmpRes := scanner_ci.PolicyResult{
		ExistMsg: err.Error(),
		ExitCode: exitCode,
	}
	data, err := json.Marshal(&tmpRes)
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Msg("failed to make a fake result file")
		return err
	}
	err = os.WriteFile(resultFile, data, os.ModePerm)
	if err != nil {
		logging.Get().Err(err).Int64("subTaskID", t.SubTaskID).Msg("failed to write fake result file")
		return err
	}
	logging.Get().Debug().Int64("subTaskID", t.SubTaskID).Msg("make fake result file ok")
	return nil
}

func (m *ScanTaskManager) scanImage(ctx context.Context, subtask imagesec.ScanSubTask) error {
	infoLog := func() *zerolog.Event {
		return logging.Get().Info().Int64("subTaskID", subtask.SubTaskID)
	}
	errLog := func(err error) *zerolog.Event {
		return logging.Get().Err(err).Int64("subTaskID", subtask.SubTaskID)
	}
	debugLog := func() *zerolog.Event {
		return logging.Get().Debug().Int64("subTaskID", subtask.SubTaskID)
	}

	infoLog().Msg("start scanning")

	imageName := ""
	if len(subtask.NodeImageMeta.RepoTags) == 0 {
		// local build image without repo tags,use image id instead
		imageName = subtask.NodeImageMeta.ImageId
	} else {
		// only need first repo tag
		imageName = subtask.NodeImageMeta.RepoTags[0]
	}

	cmdArgs := m.makeScanCmd(imageName, subtask)

	defer func() { _ = m.DeletePolicyPath(ctx, subtask) }()

	debugLog().Str("cmd", strings.Join(cmdArgs, " ")).Msg("make cmd")

	binaryPath := filepath.Join(m.ireneWorkingDir, ireneBinaryName)
	// cmd := exec.Command("/bin/sh", "-c", cmdStr)
	cmd := exec.Command(binaryPath, cmdArgs...)
	if m.runtimeConfig.ScanConfig.RealTimeLog {
		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer) // real time output
		cmd.Stdout = mw
		cmd.Stderr = mw
	}
	err := cmd.Start()
	if err != nil {
		errLog(err).Msg("failed to start cmd")
		return err
	}

	// record task and it's process ID
	r := RunningSubTask{
		Subtask:    subtask,
		ScannerPID: cmd.Process.Pid,
	}

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
		// not return, need send result
		errLog(err).Msg("failed to scan image")
		// check result file
		_ = m.checkResultFile(err, subtask)
	} else {
		infoLog().Msg("success to scan image")
	}

	// sync result
	err = m.syncResult(subtask)
	if err != nil {
		errLog(err).Msg("failed to send result")
		return err
	}
	infoLog().Msg("send result ok")

	return nil
}

func (m *ScanTaskManager) GetPolicyPath(ctx context.Context, subtask imagesec.ScanSubTask) string {
	defaultFilename := filepath.Join(m.ireneWorkingDir, "policy", defaultIrenePolicyName)
	if len(subtask.SensitiveRules) == 0 {
		return defaultFilename
	}

	content, err := os.ReadFile(defaultFilename)
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtask.SubTaskID).Str("UniqueID", subtask.UniqueID).Msg("read default policy")
		return defaultFilename
	}
	policy := scanner_ci.Policy{}

	if err := json.Unmarshal(content, &policy); err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtask.SubTaskID).Str("UniqueID", subtask.UniqueID).Msg("unmarshal default policy")
		return defaultFilename
	}
	ses := policy.SensitiveFile.DefaultFilePattern
	for i := range subtask.SensitiveRules {
		ses = append(ses, scanner_ci.Pattern{Value: subtask.SensitiveRules[i]})
	}
	policy.SensitiveFile.DefaultFilePattern = ses

	marshal, err := json.Marshal(policy)
	if err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtask.SubTaskID).Str("UniqueID", subtask.UniqueID).
			Msg("marshal policy")
		return defaultFilename
	}

	filename := filepath.Join(m.ireneWorkingDir, "policy", defaultIrenePolicyName+"-"+subtask.UniqueID)

	if err := os.WriteFile(filename, marshal, os.ModePerm); err != nil {
		logging.Get().Err(err).Int64("subtaskID", subtask.SubTaskID).Str("subtaskUUID", subtask.UniqueID).
			Msg("write policy")
		return defaultFilename
	}
	logging.Get().Info().Int64("subtaskID", subtask.SubTaskID).Str("subtaskUUID", subtask.UniqueID).
		Str("policyFilename", filename).Msg("write policy succeed")
	return filename
}

func (m *ScanTaskManager) DeletePolicyPath(ctx context.Context, subtask imagesec.ScanSubTask) error {
	defaultFilename := filepath.Join(m.ireneWorkingDir, "policy", defaultIrenePolicyName)
	file := m.GetPolicyPath(ctx, subtask)
	if file == defaultFilename {
		return nil
	}
	if err := os.Remove(file); err != nil {
		logging.Get().Err(err).Str("filename", file).Msg("delete policy path")
		return err
	}
	return nil
}

func (m *ScanTaskManager) Type() consts.ServiceType {
	return consts.TypeServiceTaskManager
}

func (m *ScanTaskManager) PreRun(cfg config.Config, nc imagesecModel.ImageScanConfig, bs *util.BroadcastServer) error {
	// create msg que cli
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq writer")
		return err
	}
	m.mqWriter = mqWriter

	// copy config
	m.runtimeConfig = cfg
	m.nodeImageConfig = nc

	m.subscribeChan = bs.Subscribe(string(consts.TypeServiceTaskManager))
	return nil
}

func (m *ScanTaskManager) updateNodeImageConfig(cfg imagesecModel.ImageScanConfig) {
	m.nodeImageConfigLock.Lock()
	defer m.nodeImageConfigLock.Unlock()
	m.nodeImageConfig = cfg
}

func (m *ScanTaskManager) handleConfigModifiedEvent() {
	for {
		logging.Get().Debug().Msg("wait config modified event")
		select {
		case item := <-m.subscribeChan:
			switch typed := item.(type) {
			case types.NotifyEvent:
				event := item.(types.NotifyEvent)
				if event.Type == consts.NotifyEventTypeConfigModified {
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

func (m *ScanTaskManager) Run() error {
	// handle config modify event
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("panic: %v. Stack: %s", r, debug.Stack())
		}
		m.handleConfigModifiedEvent()
	}()

	// do task
	limit := semaphore.NewWeighted(m.runtimeConfig.TaskConfig.ParallelNum)
	m.taskQueue.Consume(func(item interface{}) {
		switch typed := item.(type) {
		case imagesec.ScanSubTask:
			subTask := item.(imagesec.ScanSubTask)
			logging.Get().Info().Int64("taskID", subTask.TaskID).Int64("subTaskID", subTask.SubTaskID).
				Strs("image", subTask.NodeImageMeta.RepoTags).Msg("start scanning task")
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

				_ = m.scanImage(context.Background(), t)
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

func (m *ScanTaskManager) transformResult(result *scanner_ci.PolicyResult) imagesec.ScanResult {
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
				License:    v.License,
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
	in := helper.GetAviraDBVersion()
	res.Malwares.AviraEngineVersion = imagesec.AviraEngineVersion{
		Hash:    in.WorkVersion.Hash,
		Version: in.WorkVersion.Version,
		Comment: in.WorkVersion.Comment,
	}

	// webshell
	res.Webshells = result.WebshellResults

	return res
}
