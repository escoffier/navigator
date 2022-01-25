package scan

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	JobName = "scan-image"
)

type scanImageConfig struct {
	scanType map[task.ScanType]task.ScanPolicy
}

type ImageScan struct {
	imageCacheURL string
	// layersFilePath map[string]string
	config scanImageConfig
}

func (i *ImageScan) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	logging.GetLogger().Info().Msg("scan image start")

	// get image info from parameter
	u, ok := param["imageCacheUrl"].(string)
	if !ok {
		return nil, errors.New("not find 'imageCacheUrl' in parameter")
	}
	// l, ok := param["layersFilePath"].([map[string]string])
	if !ok {
		return nil, errors.New("not find 'layersFilePath' in parameter")
	}
	i.imageCacheURL = u
	// i.layersFilePath = l

	// save all scan result
	scanResult := make(map[task.ScanType]interface{})
	artifacts := make(jobs.Artifact)
	component.MergeArtifact(jobs.Artifact(param), artifacts)

	// parallel do different scan type
	wg := sync.WaitGroup{}
	for k, v := range i.config.scanType {
		logging.GetLogger().Info().Interface("scanType", k).Msg("start specify scan")
		wg.Add(1)
		go func(scanType task.ScanType, policy task.ScanPolicy) {
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("exec %s scan error : %v. stack: %s", string(scanType), r, debug.Stack())
				}
			}()

			defer wg.Done()

			scanExecutor, err := Open(ExecutorConfig{Type: string(scanType), Policy: policy})
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("create scan executor failed")
				return
			}

			curArtifact, err := scanExecutor.Scan(context.Background(), Param(artifacts))
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("scan executor failed")
				return
			}
			logging.GetLogger().Info().Interface("executorName", scanType).Msg("executor scan end")
			scanResult[scanType] = curArtifact
		}(k, v)
	}
	wg.Wait()
	artifacts["scanResult"] = scanResult

	return artifacts, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("jobName", JobName).Msg("init job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &ImageScan{}
	i.config.scanType = config.Info.Task.ScanType
	return i, nil
}
