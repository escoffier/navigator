package cleaner

import (
	"strings"
	"testing"
	"time"
)

func TestESCleanerTimeFormat(t *testing.T) {
	t.Log(generateDateFilter(1))

	dateStr := strings.TrimPrefix("access_2021-05-18", "access_")
	t.Log(dateStr)
	tt, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(tt)
}
