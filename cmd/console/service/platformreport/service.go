package platformreport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/badoux/checkmail"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/taskmanager"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	ErrInvalidTemplate = fmt.Errorf("invalid template")
	ErrInvalidOp       = fmt.Errorf("invalid op")
)

type Service struct {
	manager   def.TaskManager
	emailConf *def.EmailConf
}

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(db *rdbtools.GormWrapper, emailConf *def.EmailConf) error {
	if db == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		instance, err = newService(db, emailConf)
	})
	return err
}

const (
	MaxTaskTime = time.Hour * 5
)

func newService(db *rdbtools.GormWrapper, emailConf *def.EmailConf) (*Service, error) {
	service := &Service{
		manager:   taskmanager.NewManager(db, MaxTaskTime, def.ReportPath),
		emailConf: emailConf,
	}

	go service.expireTaskLoop()
	go service.schedule()
	return service, nil
}

func (s *Service) AddReportTaskTemplate(ctx context.Context, template *model.ReportTaskTemplate) error {
	if err := checkTemplate(template); err != nil {
		logging.GetLogger().Err(err).Msg("invalid template")
		return ErrInvalidTemplate
	}

	nowTime := time.Now()
	taskMeta := template.Convert()
	taskMeta.CreatedAt = nowTime
	taskMeta.UpdatedAt = nowTime
	id, err := s.manager.CreateTaskTemplate(ctx, taskMeta)
	if err != nil {
		return err
	}

	if template.Type == model.ReportTaskTypeOneTime {
		go func() {
			if _err := s.handleTaskAsync(taskMeta, nowTime); _err != nil {
				logging.GetLogger().Err(_err).Msgf("handle task fail, taskID:%d", template.ID)
			}
		}()
	}

	template.CreatedTimestamp = util.GetMillisecondTimestampByTime(nowTime)
	template.ID = id
	return nil
}

func (s *Service) GetTemplateTask(ctx context.Context, id int32) (*model.ReportTaskTemplate, error) {
	meta, err := s.manager.GetTaskTemplate(ctx, id)
	if err != nil {
		return nil, err
	}

	return meta.Convert(), nil
}

func (s *Service) TriggerTask(ctx context.Context, id int32) error {
	template, err := s.manager.GetTaskTemplate(ctx, id)
	if err != nil {
		return err
	}

	if template.Type == model.ReportTaskTypeOneTime {
		return ErrInvalidOp
	}

	nowTime := time.Now()
	_, startTimestamp := getTimeRange(template, nowTime)
	return s.handleTask(ctx, template, startTimestamp, util.GetMillisecondTimestampByTime(nowTime))
}

func (s *Service) UpdateReportTaskTemplate(ctx context.Context, template *model.ReportTaskTemplate) error {
	if err := checkTemplate(template); err != nil {
		logging.GetLogger().Err(err).Msg("invalid template")
		return ErrInvalidTemplate
	}

	templateMeta := template.Convert()
	templateMeta.UpdatedAt = time.Now()
	return s.manager.UpdateTaskTemplate(ctx, templateMeta)
}

func (s *Service) DeleteReportTaskTemplate(ctx context.Context, taskID int32) error {
	return s.manager.DeleteTaskTemplate(ctx, taskID)
}

func (s *Service) GetReportTaskTemplates(ctx context.Context, types []string, query string, offset, limit uint) ([]*model.ReportTaskTemplate, int64, error) {
	templates, count, err := s.manager.GetReportTaskTemplates(ctx, types, query, int(offset), int(limit))
	if err != nil {
		return nil, 0, err
	}

	var result = make([]*model.ReportTaskTemplate, len(templates))
	for i := range templates {
		result[i] = templates[i].Convert()
	}

	return result, count, nil
}

func (s *Service) GetTemplateReports(ctx context.Context, templateID int32, offset, limit uint) ([]*model.ReportRecord, int64, error) {
	return s.manager.GetTemplateReports(ctx, templateID, int(offset), int(limit))
}

func (s *Service) GetReport(ctx context.Context, uuid string) (*model.ReportDetail, error) {
	return s.manager.GetReport(ctx, uuid)
}

func (s *Service) handleTaskAsync(template *model.ReportTaskTemplateMeta, checkTime time.Time) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	startTimestamp, endTimestamp := getTimeRange(template, checkTime)
	return s.handleTask(ctx, template, startTimestamp, endTimestamp)
}

func (s *Service) handleTask(ctx context.Context, template *model.ReportTaskTemplateMeta, startTimestamp, endTimestamp int64) error {
	if template.Type != model.ReportTaskTypeOneTime {
		createdTimestamp := util.GetMillisecondTimestampByTime(template.CreatedAt)
		if createdTimestamp > endTimestamp {
			logging.GetLogger().Info().Msg("not need to generate task")
			return nil
		}
	} else {
		nowTimestamp := util.GetMillisecondTimestampByTime(time.Now())
		if nowTimestamp < endTimestamp {
			logging.GetLogger().Info().Msg("not reach oneTime task endTime")
			return nil
		}
	}

	uuid, err := s.manager.CreateTask(ctx, template.ID, startTimestamp, endTimestamp)
	if err != nil {
		if err == def.ErrTaskConflict {
			logging.GetLogger().Info().Msgf("create report task conflict, taskID:%d, startTime:%s, endTime:%s",
				template.ID,
				util.GetTimeByMillisecondTimestamp(startTimestamp),
				util.GetTimeByMillisecondTimestamp(endTimestamp))
			return nil
		}

		logging.GetLogger().Err(err).Msg("create report task fail")
		return err
	}

	defer func() {
		if err != nil {
			oneCtx, oneCancel := context.WithTimeout(context.Background(), time.Second)
			defer oneCancel()
			if _err := s.manager.UpdateTaskFailed(oneCtx, uuid); _err != nil {
				logging.GetLogger().Err(_err).Msg("UpdateTaskFailed fail")
			}
		}
	}()

	return s.launchK8sJob(ctx, &jobArg{
		templateID:     template.ID,
		uuid:           uuid,
		startTimestamp: startTimestamp,
		endTimestamp:   endTimestamp,
	})
}

var (
	defaultTimeLocation = util.GetCSTLocation()
)

func getTimeRange(template *model.ReportTaskTemplateMeta, checkTime time.Time) (startTimestamp, endTimestamp int64) {
	checkTime = checkTime.In(defaultTimeLocation)
	if template.Type == model.ReportTaskTypeWeekly {
		var dayTime = checkTime.Sub(util.GetDayZeroTime(checkTime))
		var millisecondDiff = dayTime.Milliseconds() - template.EndTimestamp
		var weekDay = util.GetWeekDay(checkTime)
		var dayDiff = weekDay - template.CycleDay + 7

		if weekDay > template.CycleDay ||
			(weekDay == template.CycleDay && dayTime.Milliseconds() >= template.EndTimestamp) {
			dayDiff -= 7
		}
		endTime := checkTime.Add(-time.Hour * 24 * time.Duration(dayDiff)).Add(-time.Duration(millisecondDiff) * time.Millisecond)
		endTimestamp = util.GetMillisecondTimestampByTime(endTime)
		startTimestamp = util.GetMillisecondTimestampByTime(endTime.Add(-time.Hour * 24 * 7))
	} else if template.Type == model.ReportTaskTypeMonthly {
		var dayTime = checkTime.Sub(util.GetDayZeroTime(checkTime))
		var targetMonthTime time.Time
		if uint8(checkTime.Day()) > template.CycleDay ||
			(uint8(checkTime.Day()) == min(template.CycleDay, util.GetMonthDays(checkTime)) && dayTime.Milliseconds() >= template.EndTimestamp) {
			targetMonthTime = checkTime
		} else {
			targetMonthTime = util.LastLogicMonth(checkTime)
		}

		var endTime = time.Date(
			targetMonthTime.Year(),
			targetMonthTime.Month(),
			int(min(template.CycleDay, util.GetMonthDays(targetMonthTime))),
			0, 0, 0, 0, targetMonthTime.Location()).
			Add(time.Millisecond * time.Duration(template.EndTimestamp))

		endTimestamp = util.GetMillisecondTimestampByTime(endTime)
		startTimestamp = util.GetMillisecondTimestampByTime(util.LastLogicMonth(endTime))
	} else {
		startTimestamp, endTimestamp = template.StartTimestamp, template.EndTimestamp
	}
	return startTimestamp, endTimestamp
}

func min(a, b uint8) uint8 {
	if a < b {
		return a
	}

	return b
}

func checkTemplate(t *model.ReportTaskTemplate) error {
	if len(t.Name) > 100 {
		return fmt.Errorf("invalid name:%s", t.Name)
	}

	if !model.CheckType(t.Type) {
		return fmt.Errorf("invalid type:%s", t.Type)
	}

	if len(t.Categories) == 0 {
		return fmt.Errorf("not specify categories")
	}

	t.Categories = util.FilterDuplicateStringArray(t.Categories)
	for _, category := range t.Categories {
		if !model.CheckCategory(category) {
			return fmt.Errorf("invalid category:%s", category)
		}
	}

	t.Emails = util.FilterDuplicateStringArray(t.Emails)
	if len(t.Emails) == 0 {
		return fmt.Errorf("not specify emails")
	}
	for _, email := range t.Emails {
		if checkErr := checkmail.ValidateFormat(email); checkErr != nil {
			return fmt.Errorf("invalid email:%s", email)
		}
	}

	if len(t.Clusters) == 0 {
		return fmt.Errorf("not specify clusters")
	}
	t.Clusters = util.FilterDuplicateStringArray(t.Clusters)

	if len(t.Description) > 255 {
		return fmt.Errorf("invalid descripion:%s", t.Description)
	}

	if (t.Type == model.ReportTaskTypeMonthly && (t.CycleDay <= 0 || t.CycleDay > 31)) ||
		(t.Type == model.ReportTaskTypeWeekly && (t.CycleDay <= 0 || t.CycleDay > 7)) {
		return fmt.Errorf("invalid cycleDay:%d, type:%s", t.CycleDay, t.Type)
	}

	if t.Type == model.ReportTaskTypeOneTime {
		if t.StartTimestamp <= 0 || t.EndTimestamp < t.StartTimestamp {
			return fmt.Errorf("invalid timestamp, startTimestamp:%d, endTimestamp:%d", t.StartTimestamp, t.EndTimestamp)
		}
	} else if t.EndTimestamp <= 0 || t.EndTimestamp > 24*(time.Hour.Milliseconds()) {
		return fmt.Errorf("invalid timestamp, startTimestamp:%d, endTimestamp:%d", t.StartTimestamp, t.EndTimestamp)
	}

	return nil
}
