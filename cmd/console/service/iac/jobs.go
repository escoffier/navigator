package iac

import (
	"context"
	"encoding/json"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/security-rd/go-pkg/iac"
	"gitlab.com/security-rd/go-pkg/iac/consts"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	YamlScanConcurrency = "YAML_SCAN_CONCURRENCY"
)

var (
	yamlJobChan    = make(chan YamlJob)
	jobsInProgress = JobsInProgress{
		jobs: make(map[int]JobDetail),
		lock: sync.Mutex{},
	}
)

type YamlJob struct {
	YamlData   []byte
	Resource   iacModel.Resource
	TemplateID int
	TaskID     int
	RecordID   int
	ResultID   int
	Total      int
	Todo       int
}

type JobDetail struct {
	Total     int
	Todo      int
	Count     int
	Success   int
	StartedAt int64
}

type JobsInProgress struct {
	jobs map[int]JobDetail
	lock sync.Mutex
}

func (jip *JobsInProgress) Add(job YamlJob) {
	jobsInProgress.lock.Lock()
	defer jobsInProgress.lock.Unlock()
	detail, ok := jobsInProgress.jobs[job.TaskID]
	if ok {
		detail.Count += 1
		jobsInProgress.jobs[job.TaskID] = detail
	} else {
		jobsInProgress.jobs[job.TaskID] = JobDetail{
			Total:     job.Total,
			Todo:      job.Todo,
			Count:     1,
			StartedAt: time.Now().Unix(),
		}
	}
}

func (jip *JobsInProgress) Success(job YamlJob) {
	jobsInProgress.lock.Lock()
	defer jobsInProgress.lock.Unlock()
	detail, ok := jobsInProgress.jobs[job.TaskID]
	if ok {
		detail.Success += 1
		jobsInProgress.jobs[job.TaskID] = detail
	}
}

func (jip *JobsInProgress) CheckOver(job YamlJob) (bool, int, int64) {
	jobsInProgress.lock.Lock()
	defer jobsInProgress.lock.Unlock()
	detail, ok := jobsInProgress.jobs[job.TaskID]
	if ok {
		if detail.Todo == detail.Count {
			delete(jobsInProgress.jobs, job.TaskID)
			return true, detail.Success, detail.StartedAt
		}
		return false, detail.Success, detail.StartedAt
	} else {
		logging.Get().Error().Int("task id", job.TaskID).Msgf("check job not exist")
		return false, 0, 0
	}
}

// fixme: 此处有bug，可能后续的job还没加进来
func (jip *JobsInProgress) Sub(taskID int) JobDetail {
	jobsInProgress.lock.Lock()
	defer jobsInProgress.lock.Unlock()
	detail, ok := jobsInProgress.jobs[taskID]
	if ok {
		detail.Count--
		if detail.Count == 0 {
			delete(jobsInProgress.jobs, taskID)
		}
	}
	return detail
}

func initYamlJobWorkers() {
	sConcurrency := os.Getenv(YamlScanConcurrency)
	concurrency, err := strconv.Atoi(sConcurrency)
	if err != nil || concurrency < 1 {
		concurrency = 1
	}

	for i := 0; i < concurrency; i++ {
		go scanYaml()
	}
}

func AddYamlScanJob(job YamlJob) {
	yamlJobChan <- job
	jobsInProgress.Add(job)
}

func scanYaml() {
	for {
		job := <-yamlJobChan
		err := runJob(job)
		if err != nil {
			logging.Get().Error().Err(err).Interface("job", job).Msg("runJob fails")
			continue
		}
	}
}

func runJob(job YamlJob) error {
	ctx := context.Background()

	defer func() {
		timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		err := iacModel.UpdateYamlRecordAlreadyComplete(timeOutCtx, db, job.TaskID, job.RecordID)
		if err != nil {
			logging.Get().Error().Err(err).Msg("UpdateYamlRecordAlreadyComplete fails")
			return
		}

		timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
		defer cancel()
		if over, success, startedAt := jobsInProgress.CheckOver(job); over {
			// 结果更新数据库
			// ivan_iac_yaml_tasks
			err := iacModel.UpdateYamlTask(timeOutCtx, db, map[string]interface{}{"id": job.TaskID}, map[string]interface{}{"duration": time.Now().Unix() - startedAt, "status": iacModel.YamlTaskStatusComplete, "success": job.Total - (job.Todo - success), "updated_at": time.Now()})
			if err != nil {
				logging.Get().Error().Err(err).Msg("UpdateYamlTask fails")
				return
			}
		}
	}()

	// 更新 ivan_iac_yaml_records scanning
	timeOutCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := iacModel.UpdateYamlRecord(timeOutCtx, db, map[string]interface{}{"id": job.RecordID}, map[string]interface{}{"status": iacModel.YamlRecordStatusScanning, "updated_at": time.Now()})
	if err != nil {
		logging.Get().Error().Err(err).Msg("UpdateYamlRecord fails")
		return err
	}

	// 扫描yaml数据
	logging.Get().Info().Str("yaml", string(job.YamlData)).Msg("yamlData")
	startTime := time.Now()
	_, results, err := iac.RunWithData(job.YamlData, consts.ScanTypeKubernetes, time.Second*30)
	duration := time.Now().Sub(startTime)
	if err != nil {
		logging.Get().Error().Err(err).Msg("iac.RunWithData fails")
		// 更新 ivan_iac_yaml_records complete
		timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
		defer cancel()
		err2 := iacModel.UpdateYamlResult(timeOutCtx, db, map[string]interface{}{"id": job.ResultID}, map[string]interface{}{"status": iacModel.YamlResultStatusFailed, "updated_at": time.Now()})
		if err2 != nil {
			logging.Get().Error().Err(err2).Msg("UpdateYamlResult fails")
			return err2
		}

		// 更新 ivan_iac_yaml_records complete
		timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
		defer cancel()
		err2 = iacModel.UpdateYamlRecord(timeOutCtx, db, map[string]interface{}{"id": job.RecordID}, map[string]interface{}{"status": iacModel.YamlRecordStatusFailed, "fail_reason": err.Error(), "updated_at": time.Now()})
		if err2 != nil {
			logging.Get().Error().Err(err2).Msg("UpdateYamlRecord fails")
			return err2
		}
		return err
	}
	// 解析results
	// ivan_iac_yaml_results
	bResults, err := json.Marshal(results.GetFailed().Flatten())
	if err != nil {
		logging.Get().Error().Err(err).Msg("Marshal scan results fails")
		return err
	}
	// 更新 ivan_iac_yaml_records complete
	timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = iacModel.UpdateYamlResult(timeOutCtx, db, map[string]interface{}{"id": job.ResultID}, map[string]interface{}{"duration": duration.Seconds(), "status": iacModel.YamlResultStatusComplete, "result": string(bResults), "updated_at": time.Now()})
	if err != nil {
		logging.Get().Error().Err(err).Msg("UpdateYamlResult fails")
		return err
	}

	timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, successRate, err := iacModel.FilterYamlResultByTemplate(timeOutCtx, db, string(bResults), job.TemplateID)
	if err != nil {
		logging.Get().Error().Err(err).Msg("FilterYamlResultByTemplate fails")
		return err
	}

	// 更新 ivan_iac_yaml_records complete
	timeOutCtx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = iacModel.UpdateYamlRecord(timeOutCtx, db, map[string]interface{}{"id": job.RecordID}, map[string]interface{}{"status": iacModel.YamlRecordStatusComplete, "success_rate": successRate, "updated_at": time.Now()})
	if err != nil {
		logging.Get().Error().Err(err).Msg("UpdateYamlRecord fails")
		return err
	}
	jobsInProgress.Success(job)
	return nil
}
