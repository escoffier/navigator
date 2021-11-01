package mock_scan

import (
	"context"
	"errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs/scan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"sync"
)

const (
	JobName = "mock-scan-image"
)

type MockScanImageConfig struct {
	scanType map[task.ScanType]task.ScanPolicy
}

type MockImageScan struct {
	imageCacheUrl  string
	layersFilePath map[string]string
	config         MockScanImageConfig
}

func (i *MockImageScan) Run(ctx context.Context, param jobs.Param) (jobs.Artifact, error) {
	logging.GetLogger().Info().Interface("param", param).Msg("mock-image-scan start")

	// get image info from parameter
	u, ok := param["imageCacheUrl"].(string)
	if !ok {
		return nil, errors.New("not find 'imageCacheUrl' in parameter")
	}
	l, ok := param["layersFilePath"].(map[string]string)
	if !ok {
		return nil, errors.New("not find 'layersFilePath' in parameter")
	}
	i.imageCacheUrl = u
	i.layersFilePath = l

	// save all scan result
	scanResult := make(map[task.ScanType]interface{})
	artifacts := make(jobs.Artifact)
	component.MergeArtifact(jobs.Artifact(param), artifacts)

	// parallel do different scan type
	wg := sync.WaitGroup{}
	for k, v := range i.config.scanType {
		logging.GetLogger().Info().Interface("scanType", k).Interface("policy", v).Msg("start specify scan")
		wg.Add(1)
		go func(scanType task.ScanType, policy task.ScanPolicy) {
			defer wg.Done()
			// create scan job by type
			scanExecutor, err := scan.Open(scan.ExecutorConfig{Type: string(scanType)})
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("create scan executor failed")
				return
			}
			logging.GetLogger().Info().Interface("executorName", scanType).Msg("open executor ok")

			curArtifact, err := scanExecutor.Scan(context.Background(), scan.Param(artifacts))
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("scan job scan failed")
				return
			}
			logging.GetLogger().Info().Interface("executorName", scanType).Msg("executor scan end")
			scanResult[scanType] = curArtifact
		}(k, v)
	}
	wg.Wait()

	artifacts["scanResult"] = scanResult

	logging.GetLogger().Info().Msg("mock-image-scan end")
	return artifacts, nil
}

func init() {
	err := jobs.Register(JobName, newJob)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("jobName", JobName).Msg("int job err")
	}
}

func newJob(config jobs.JobConfig) (jobs.Job, error) {
	i := &MockImageScan{}
	i.config.scanType = config.Info.Task.ScanType
	return i, nil
}
