package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	flowconf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/jobs"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"golang.org/x/sync/semaphore"
)

const (
	DefaultMaxTaskNum    = 2
	DefaultMaxSubTaskNum = 2
	DefaultInterval      = 30
)

type FlowLoopFunc func(st *task.SubTask, t *task.Task) error

type SeqEngineConfig struct {
	DeqType       string
	Interval      int   // interval of dequeue tasks,unit:second
	MaxTaskNum    int64 // max parallel task num
	MaxSubTaskNum int64 // max parallel subtask num per task
}

type SequenceEngine struct {
	taskSrv  *task.TaskSrv
	config   SeqEngineConfig
	LoopFunc LoopEngineFunc
}

func NewSequenceEngine(config SeqEngineConfig, loopFunc LoopEngineFunc) Engine {
	s := &SequenceEngine{
		config: config,
	}
	if s.config.MaxTaskNum <= 0 {
		s.config.MaxTaskNum = DefaultMaxTaskNum
	}
	if s.config.MaxSubTaskNum <= 0 {
		s.config.MaxSubTaskNum = DefaultMaxSubTaskNum
	}
	if s.config.Interval <= 0 {
		s.config.Interval = DefaultInterval
	}
	if loopFunc == nil {
		logging.GetLogger().Debug().Msg("set default loop func")
		s.LoopFunc = s.defaultLoopFunc()
	} else {
		s.LoopFunc = loopFunc
	}

	ts := task.NewTaskSrv()
	s.taskSrv = ts

	return s
}

func (s *SequenceEngine) defaultLoopFunc() LoopEngineFunc {
	return func(_ interface{}) error {
		return nil
	}
}

func (s *SequenceEngine) SubTaskHeartBeatFunc() FlowLoopFunc {
	return func(st *task.SubTask, t *task.Task) error {
		err := s.taskSrv.UpdateSubTasksHeartBeat([]int64{st.ID})
		if err != nil {
			logging.GetLogger().Warn().
				Str("msg", err.Error()).
				Int64("taskId", t.ID).
				Int64("subtaskId", st.ID).
				Msg("update subtask heart beat failed")
		}

		// also update task heart beat
		err2 := s.taskSrv.UpdateTasksHeartBeat([]int64{t.ID})
		if err2 != nil {
			logging.GetLogger().Warn().
				Str("msg", err2.Error()).
				Int64("taskId", t.ID).
				Int64("subtaskId", st.ID).
				Msg("update task heart beat failed")
		}

		if err != nil {
			return fmt.Errorf("update subtask heatbeat %v", err)
		}
		if err2 != nil {
			return fmt.Errorf("update task heatbeat %v", err2)
		}
		return nil
	}
}

func (s *SequenceEngine) Run(ctx context.Context) error {
	// new dequeuer
	dequeue, err := dequeue.Open(dequeue.Config{Type: s.config.DeqType})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("new dequeue err")
		return err
	}

	// task concurrency limit
	limit := semaphore.NewWeighted(s.config.MaxTaskNum)

	flowLoopFn := s.SubTaskHeartBeatFunc()

	// loop get task
	for {
		time.Sleep(time.Duration(s.config.Interval) * time.Second)

		// dequeue tasks
		tasks, err := dequeue.DequeueTasks(context.Background())
		if err != nil {
			logging.GetLogger().Err(err).Msg("dequeue tasks err")
			continue
		}
		logging.GetLogger().Info().Int("taskCount", len(tasks)).Msg("dequeue tasks")

		// do task
		_ = task.WalkTasks(ctx, tasks, limit, func(t *task.Task, limit *semaphore.Weighted, flow flowconf.FlowConf) error {
			go func(t *task.Task) {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("task panic: %v. stack: %s", r, debug.Stack())
					}
				}()
				defer limit.Release(1)
				defer global.TaskWg.Done()

				taskWg := sync.WaitGroup{}

				subLimit := semaphore.NewWeighted(s.config.MaxSubTaskNum)

				// do subtask
				_ = task.WalkSubTasks(ctx, t, t.Scope.SubTasks, subLimit, flow, &taskWg,
					func(ct *task.Task, subtask *task.SubTask, subLimit *semaphore.Weighted, flow flowconf.FlowConf, wg *sync.WaitGroup) error {
						go func(tmpTask *task.Task, tmpSubTask *task.SubTask) {
							defer func() {
								if r := recover(); r != nil {
									logging.GetLogger().Error().Msgf("subtask panic : %v. stack: %s", r, debug.Stack())
								}
							}()
							defer subLimit.Release(1)
							defer wg.Done()
							_ = s.handleFlow(ctx, flow, tmpSubTask, tmpTask, flowLoopFn)
						}(ct, subtask)
						return nil
					})
			}(t)

			return nil
		})

		loopErr := s.LoopFunc(tasks)
		if loopErr != nil {
			logging.GetLogger().Error().Msgf("loop func return err,break engine loop:%v", loopErr)
			break
		}

	}

	logging.GetLogger().Error().Msg("sequence engine exit.")
	return nil
}

func (s *SequenceEngine) handleFlow(ctx context.Context, flowConf []string, st *task.SubTask, t *task.Task, flowFn FlowLoopFunc) error {
	// sequence do job in flow conf
	errMsg := ""
	success := true
	defer func() {
		if success {
			logging.GetLogger().Info().Int64("taskId", t.ID).Int64("subtaskId", st.ID).Msg("subtask scan success")
		} else {
			logging.GetLogger().Error().Str("errMsg", errMsg).Int64("taskId", t.ID).Int64("subtaskId", st.ID).Msg("subtask scan err")
		}
	}()

	artifacts := make(jobs.Artifact)
	taskSrv := task.NewTaskSrv()

	// update subtask status
	if err := taskSrv.SetSubTaskInProgress(st.ID); err != nil {
		success = false
		errMsg = fmt.Sprintf("update subtask status err.%v", err)
		return err
	}

	for _, j := range flowConf {
		// generate job by name
		logging.GetLogger().Info().
			Str("jobName", j).
			Int64("subtaskId", st.ID).
			Int64("taskId", t.ID).Msg("start job")
		config := jobs.JobConfig{
			Type: j,
			Info: jobs.JobInfo{
				SubTask:        *st,
				CacheServerURL: "",
				Task:           *t,
			},
		}
		job, err := jobs.Open(config)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("create job")
			success = false
			errMsg = "create job err:" + err.Error()
			break
		}
		curArtifact, err := job.Run(ctx, jobs.Param(artifacts))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("job run failed")
			success = false
			errMsg = "job run err:" + err.Error()
			break
		}

		// merge artifact which will be next job's input parameter
		component.MergeArtifact(curArtifact, artifacts)

		// update subtask and task heart beat after every job
		_ = flowFn(st, t)

		logging.GetLogger().Info().
			Str("jobName", j).
			Int64("subtaskId", st.ID).
			Int64("taskId", t.ID).
			Msg("job success")
	}

	if !success {
		_ = taskSrv.SetSubTaskFailed(st.ID, errMsg)
		return fmt.Errorf("subtask scan error: %v", errMsg)
	}

	if err := taskSrv.SetSubTaskSuccess(st.ID); err != nil {
		success = false
		errMsg = fmt.Sprintf("scan success,but update db err:%v", err)
		return err
	}
	return nil
}
