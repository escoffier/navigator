package util

import "time"

func GetMillisecondTime(t time.Time) time.Time {
	return time.Unix(0, t.UnixNano()/1e6*1e6).In(t.Location())
}
