package util

import (
	"testing"
	"time"
)

func TestGetDayZeroTime(t *testing.T) {
	nowTime := time.Now()
	t.Log(GetDayZeroTime(nowTime))
}

func TestGetMonthDays(t *testing.T) {
	nowTime := time.Now()
	for i := 0; i < 12; i++ {
		curTime := nowTime.AddDate(0, i, 0)
		t.Log(curTime, GetMonthDays(curTime))
	}
}

func TestLastLogicMonth(t *testing.T) {
	nowTime := time.Now()
	t.Log(nowTime, LastLogicMonth(nowTime))
}

func TestGetCSTLocation(t *testing.T) {
	t.Log(time.Now().In(GetCSTLocation()))
}
