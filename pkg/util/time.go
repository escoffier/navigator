package util

import "time"

func GetMillisecondTime(t time.Time) time.Time {
	return time.Unix(0, t.UnixNano()/1e6*1e6).In(t.Location())
}

func GetMillisecondTimestampByTime(t time.Time) int64 {
	return t.UnixNano() / 1e6
}

func GetTimeByMillisecondTimestamp(timestamp int64) time.Time {
	return time.Unix(0, timestamp*1e6)
}

func GetMonthDays(t time.Time) uint8 {
	return getMonthDays(t.Month(), IsLeapYear(t.Year()))
}

func getMonthDays(month time.Month, leap bool) uint8 {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	default:
		if leap {
			return 29
		}
		return 28
	}
}

func IsLeapYear(year int) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

func GetDayZeroTime(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func GetWeekDay(t time.Time) uint8 {
	switch t.Weekday() {
	case time.Monday:
		return 1
	case time.Tuesday:
		return 2
	case time.Wednesday:
		return 3
	case time.Thursday:
		return 4
	case time.Friday:
		return 5
	case time.Saturday:
		return 6
	default:
		return 7
	}
}

func LastLogicMonth(t time.Time) time.Time {
	year := t.Year()
	var month time.Month
	if t.Month() == 1 {
		year--
		month = time.December
	} else {
		month = t.Month() - 1
	}
	leap := IsLeapYear(year)
	days := t.Day()
	if days > int(getMonthDays(month, leap)) {
		days = int(getMonthDays(month, leap))
	}
	return time.Date(year, month, days, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

func GetCSTLocation() *time.Location {
	return time.FixedZone("CST", 8*3600)
}
