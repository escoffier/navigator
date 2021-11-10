package taskmanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	manager *Manager
)

func initManager(t *testing.T) {
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")
	db, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	manager = NewManager(db, time.Hour*2, "./")
}

func TestManager_CreateTaskTemplate(t *testing.T) {
	initManager(t)
	template := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeOneTime,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       0,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
	}

	id, err := manager.CreateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(id)

	template.ID = 0
	_, err = manager.CreateTaskTemplate(context.TODO(), template)
	assert.Equal(t, def.ErrTaskTemplateNameDuplicate, err)
}

func TestManager_UpdateTaskTemplate(t *testing.T) {
	initManager(t)
	template := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeOneTime,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       0,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
		UpdatedAt:      time.Now(),
	}

	_, err := manager.CreateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}

	template.Name += "update"
	err = manager.UpdateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}

	template2 := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeOneTime,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       0,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
	}

	_, err = manager.CreateTaskTemplate(context.TODO(), template2)
	if err != nil {
		t.Fatal(err)
	}

	template2.Name = template.Name
	err = manager.UpdateTaskTemplate(context.TODO(), template2)
	assert.Equal(t, def.ErrTaskTemplateNameDuplicate, err)
}

func TestManager_GetTaskTemplate(t *testing.T) {
	initManager(t)
	template := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeOneTime,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       0,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
	}

	id, err := manager.CreateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.GetTaskTemplate(context.TODO(), id)
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.GetTaskTemplate(context.TODO(), 0)
	assert.Equal(t, def.ErrTaskTemplateNotExist, err)
}

func TestManager_DeleteTaskTemplate(t *testing.T) {
	initManager(t)
	template := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeOneTime,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       0,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
	}

	id, err := manager.CreateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}

	uuid, err := manager.CreateTask(context.TODO(), id,
		util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		util.GetMillisecondTimestampByTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}

	err = manager.FinishTask(context.TODO(), id, uuid, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}

	err = manager.DeleteTaskTemplate(context.TODO(), id)
	if err != nil {
		t.Fatal(err)
	}

	err = manager.DeleteTaskTemplate(context.TODO(), 0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_CreateTask(t *testing.T) {
	initManager(t)
	nowTime := time.Now()
	uuid, err := manager.CreateTask(context.TODO(), 0, util.GetMillisecondTimestampByTime(nowTime.Add(-time.Hour)), util.GetMillisecondTimestampByTime(nowTime))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(uuid)

	_, err = manager.CreateTask(context.TODO(), 0, util.GetMillisecondTimestampByTime(nowTime.Add(-time.Hour)), util.GetMillisecondTimestampByTime(nowTime))
	assert.Equal(t, def.ErrTaskConflict, err)
}

func TestManager_UpdateTaskStatus(t *testing.T) {
	initManager(t)
	nowTime := time.Now()
	uuid, err := manager.CreateTask(context.TODO(), 0, util.GetMillisecondTimestampByTime(nowTime.Add(-time.Hour)), util.GetMillisecondTimestampByTime(nowTime))
	if err != nil {
		t.Fatal(err)
	}

	err = manager.UpdateTaskFailed(context.TODO(), uuid)
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_FinishTask(t *testing.T) {
	initManager(t)
	nowTime := time.Now()
	uuid, err := manager.CreateTask(context.TODO(), 0, util.GetMillisecondTimestampByTime(nowTime.Add(-time.Hour)), util.GetMillisecondTimestampByTime(nowTime))
	if err != nil {
		t.Fatal(err)
	}

	err = manager.FinishTask(context.TODO(), 0, uuid, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_DealExpireRecords(t *testing.T) {
	initManager(t)
	err := manager.DealExpireRecords(context.TODO(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_LoadCronTaskTemplates(t *testing.T) {
	initManager(t)

	template := &model.ReportTaskTemplateMeta{
		Name:           fmt.Sprintf("testName-%d", time.Now().UnixNano()),
		Type:           model.ReportTaskTypeMonthly,
		Clusters:       `["test_cluster"]`,
		Categories:     `["images"]`,
		Emails:         `["xxx@xx.com"]`,
		Description:    "testDescription",
		CycleDay:       15,
		StartTimestamp: util.GetMillisecondTimestampByTime(time.Now().Add(-time.Hour)),
		EndTimestamp:   util.GetMillisecondTimestampByTime(time.Now()),
	}

	_, err := manager.CreateTaskTemplate(context.TODO(), template)
	if err != nil {
		t.Fatal(err)
	}

	tasks, err := manager.LoadAllTaskTemplates(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	t.Log(tasks)
}

func TestManager_GetReportTaskTemplates(t *testing.T) {
	initManager(t)
	templates, count, err := manager.GetReportTaskTemplates(context.TODO(), nil, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(count)
	assert.Equal(t, true, len(templates) <= 10)

	templates, count, err = manager.GetReportTaskTemplates(context.TODO(), nil, "test", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(count)
	assert.Equal(t, true, len(templates) <= 10)

	templates, count, err = manager.GetReportTaskTemplates(context.TODO(), []string{model.ReportTaskTypeWeekly}, "test", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(count)
	assert.Equal(t, true, len(templates) <= 10)
}

func TestManager_GetTemplateReports(t *testing.T) {
	initManager(t)
	records, count, err := manager.GetTemplateReports(context.TODO(), 1, 0, 10)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(count)
	for _, record := range records {
		t.Log(*record)
	}
}

func TestManager_GetReport(t *testing.T) {
	initManager(t)
	_, err := manager.GetReport(context.TODO(), "nonsense")
	if err != nil && err != def.ErrReportNotFound {
		t.Fatal(err)
	}
}

func TestRemove(t *testing.T) {
	err := os.Remove("nonsense")
	t.Log(errors.Is(err, os.ErrNotExist))
}
