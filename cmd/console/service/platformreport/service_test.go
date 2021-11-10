package platformreport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	timeFormat = "2006-01-02 15:04:05"
)

func TestGetTimeRange_1(t *testing.T) {
	task := &model.ReportTaskTemplateMeta{
		Type:         model.ReportTaskTypeWeekly,
		CycleDay:     3,
		EndTimestamp: 7200000,
	}

	nowTime := time.Now()
	for i := 0; i < 14; i++ {
		checkTime := nowTime.Add(time.Hour * 24 * time.Duration(i))
		startTimestamp, endTimestamp := getTimeRange(task, checkTime)
		startTime, endTime := util.GetTimeByMillisecondTimestamp(startTimestamp), util.GetTimeByMillisecondTimestamp(endTimestamp)
		t.Log(checkTime.Format(timeFormat), "checkDay:", util.GetWeekDay(checkTime),
			"start:", startTime.Format(timeFormat),
			"end:", endTime.Format(timeFormat))
		assert.Equal(t, uint8(3), util.GetWeekDay(startTime))
		assert.Equal(t, uint8(3), util.GetWeekDay(endTime))
	}
}

func TestGetTimeRange_2(t *testing.T) {
	task := &model.ReportTaskTemplateMeta{
		Type:         model.ReportTaskTypeMonthly,
		CycleDay:     3,
		EndTimestamp: 7200000,
	}
	nowTime := time.Now()
	for i := 0; i < 31; i++ {
		checkTime := nowTime.Add(time.Hour * 24 * time.Duration(i))
		startTimestamp, endTimestamp := getTimeRange(task, checkTime)
		startTime, endTime := util.GetTimeByMillisecondTimestamp(startTimestamp), util.GetTimeByMillisecondTimestamp(endTimestamp)
		t.Log(checkTime.Format(timeFormat), "checkMonthDay:", checkTime.Day(),
			"start:", startTime.Format(timeFormat),
			"end:", endTime.Format(timeFormat))
		assert.Equal(t, 3, startTime.Day())
		assert.Equal(t, 3, endTime.Day())
	}
}

func TestGetTimeRange_3(t *testing.T) {
	task := &model.ReportTaskTemplateMeta{
		Type:         model.ReportTaskTypeMonthly,
		CycleDay:     31,
		EndTimestamp: 4500000,
	}

	nowTime := time.Now()
	for i := 0; i < 62; i++ {
		checkTime := nowTime.Add(time.Hour * 24 * time.Duration(i))
		startTimestamp, endTimestamp := getTimeRange(task, checkTime)
		startTime, endTime := util.GetTimeByMillisecondTimestamp(startTimestamp), util.GetTimeByMillisecondTimestamp(endTimestamp)
		t.Log(checkTime.Format(timeFormat), "checkMonthDay:", checkTime.Day(),
			"start:", startTime.Format(timeFormat),
			"end:", endTime.Format(timeFormat))
		assert.Equal(t, true, endTime.Day() == 31 || endTime.Day() == int(util.GetMonthDays(endTime)))
		assert.Equal(t, true, startTime.Day() == endTime.Day() || startTime.Day() == int(util.GetMonthDays(startTime)))
	}
}

func TestAddDate(t *testing.T) {
	t1 := time.Date(2021, 10, 31, 0, 0, 0, 0, time.Local)
	t.Log(t1.AddDate(0, 1, 0).Format(timeFormat))
	t.Log(t1.AddDate(0, -1, 0).Format(timeFormat))

	t.Log(time.Date(2021, 11, 31, 0, 0, 0, 0, time.Local).Format(timeFormat))
}

func TestGenerateNotifyBaseURL(t *testing.T) {
	t.Log(generateNotifyBaseURL("https://console2-test-cn.tensorsecurity.cn"))
	t.Log(generateNotifyBaseURL("https://console2-test-cn.tensorsecurity.cn/"))
}
