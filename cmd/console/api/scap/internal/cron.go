package internal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
)

var (
	regexp1 = regexp.MustCompile(`^([01][0-9]|2[0-3]|[0-9]):([0-5][0-9]|[0-9]):([0-5][0-9]|[0-9])$`)
	regexp2 = regexp.MustCompile(`^([0-6]|0[0-6])/([01][0-9]|2[0-3]|[0-9]):([0-5][0-9]|[0-9]):([0-5][0-9]|[0-9])$`)
	regexp3 = regexp.MustCompile(`^([0-2][0-9]|[3][01]|[1-9])/([01][0-9]|2[0-3]|[0-9]):([0-5][0-9]|[0-9]):([0-5][0-9]|[0-9])$`)
	regexp4 = regexp.MustCompile(`^(0[1-9]|1[012]|[1-9])/([0-2][0-9]|[3][01]|[1-9])/([01][0-9]|2[0-3]|[0-9]):([0-5][0-9]|[0-9]):([0-5][0-9]|[0-9])$`)
)

// 类型，1:-, 2:每天，3:每周，4:每月，5.每年
// 时间间隔
// 当type为1时，忽略
// 当type为2时，格式为 时:分:秒
// 当type为3时，格式为 week/时:分:秒
// 当type为4时，格式为 day/时:分:秒
// 当type为5时，格式为 month/day/时:分:秒

// Cron 获取cron表达式的字符串
func Cron(cron *scap.Cron) (string, error) {
	if cron == nil || cron.Type < 1 || cron.Type > 5 {
		return "", errors.New("invalid cron type")
	}

	var s = []string{"*", "*", "*", "*", "*", "*"}
	split := strings.Split(cron.Time, "/")
	var time string

	switch cron.Type {
	// case 1:
	// 	return "", nil
	case 2:
		if !regexp1.MatchString(cron.Time) {
			return "", fmt.Errorf("invalid cron, invalid time: %s", cron.Time)
		}
		time = split[0]
	case 3:
		if !regexp2.MatchString(cron.Time) {
			return "", fmt.Errorf("invalid cron, invalid time: %s", cron.Time)
		}

		time = split[1]
		s[5] = split[0]
	case 4:
		if !regexp3.MatchString(cron.Time) {
			return "", fmt.Errorf("invalid cron, invalid time: %s", cron.Time)
		}

		time = split[1]
		s[3] = split[0]
	case 5:
		if !regexp4.MatchString(cron.Time) {
			return "", fmt.Errorf("invalid cron, invalid time: %s", cron.Time)
		}
		time = split[2]
		s[3] = split[1]
		s[4] = split[0]
	default:
		return "", fmt.Errorf("unknown cron type")
	}

	times := strings.Split(time, ":")
	if len(times) != 3 {
		return "", fmt.Errorf("invalid cron, invalid time format: %s", time)
	}
	s[0] = times[2]
	s[1] = times[1]
	s[2] = times[0]

	return strings.Join(s, " "), nil
}

// ParseCron 解析cron表达式
func ParseCron(cronString string) *scap.Cron {
	if len(cronString) == 0 {
		return &scap.Cron{Type: 1}
	}
	var cron = new(scap.Cron)
	var s = strings.Builder{}
	split := strings.Split(cronString, " ")
	if split[5] != "*" {
		cron.Type = 3
		s.WriteString(split[5])
		s.WriteByte('/')
	} else if split[4] != "*" {
		cron.Type = 5
		s.WriteString(split[4])
		s.WriteByte('/')
		s.WriteString(split[3])
		s.WriteByte('/')
	} else if split[3] != "*" {
		cron.Type = 4
		s.WriteString(split[3])
		s.WriteByte('/')
	} else {
		cron.Type = 2
	}

	s.WriteString(split[2])
	s.WriteByte(':')
	s.WriteString(split[1])
	s.WriteByte(':')
	s.WriteString(split[0])

	cron.Time = s.String()

	return cron
}
