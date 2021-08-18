package syslog

import (
	"errors"
	"fmt"
	"log/syslog"
)

type Conf struct {
	Network  string
	Addr     string
	Facility uint8
	Severity uint8
	Tag      string
}

var (
	ErrInvalidFacility = errors.New("invalid syslog facility")
	ErrInvalidSeverity = errors.New("invalid syslog severity")
)

func NewWriter(conf *Conf) (*syslog.Writer, error) {
	var facility, severity syslog.Priority
	if conf.Facility >= uint8(len(facilityOptions)) {
		return nil, ErrInvalidFacility
	}
	facility = severityOptions[conf.Facility]
	if facility == notSupportFacility {
		return nil, ErrInvalidFacility
	}

	if conf.Severity >= uint8(len(severityOptions)) {
		return nil, ErrInvalidSeverity
	}
	severity = severityOptions[conf.Severity]
	writer, err := syslog.Dial(conf.Network, conf.Addr, facility|severity, conf.Tag)
	if err != nil {
		return nil, fmt.Errorf("dial syslog server fail, err:%w", err)
	}

	return writer, nil
}

const (
	notSupportFacility = -1
)

var (
	severityOptions = []syslog.Priority{
		syslog.LOG_EMERG,
		syslog.LOG_ALERT,
		syslog.LOG_CRIT,
		syslog.LOG_ERR,
		syslog.LOG_WARNING,
		syslog.LOG_NOTICE,
		syslog.LOG_INFO,
		syslog.LOG_DEBUG,
	}

	facilityOptions = []syslog.Priority{
		syslog.LOG_KERN,
		syslog.LOG_USER,
		syslog.LOG_MAIL,
		syslog.LOG_DAEMON,
		syslog.LOG_AUTH,
		syslog.LOG_SYSLOG,
		syslog.LOG_LPR,
		syslog.LOG_NEWS,
		syslog.LOG_UUCP,
		syslog.LOG_CRON,
		syslog.LOG_AUTHPRIV,
		syslog.LOG_FTP,
		notSupportFacility, // unused
		notSupportFacility, // unused
		notSupportFacility, // unused
		notSupportFacility, // unused
		syslog.LOG_LOCAL0,
		syslog.LOG_LOCAL1,
		syslog.LOG_LOCAL2,
		syslog.LOG_LOCAL3,
		syslog.LOG_LOCAL4,
		syslog.LOG_LOCAL5,
		syslog.LOG_LOCAL6,
		syslog.LOG_LOCAL7,
	}
)
