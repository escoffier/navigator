package k8saudit

import (
	"context"
	"encoding/json"
	"errors"

	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/storeerror"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type store struct {
	db *rdbtools.GormWrapper
}

const (
	auditSyslogConfigKey = "audit-syslog-conf"
)

func (s *store) LoadSyslogSettings(ctx context.Context) (*pb.SyslogSetting, error) {
	config, err := dal.GetConfig(ctx, s.db, auditSyslogConfigKey)
	if err != nil {
		return nil, storeerror.WrapError(storeerror.ErrCodeUnknown, err)
	}

	if config == nil {
		return nil, storeerror.WrapError(storeerror.ErrCodeNotFound, errors.New("config not found"))
	}

	var setting *pb.SyslogSetting
	err = json.Unmarshal(config.Config, &setting)
	if err != nil {
		return nil, storeerror.WrapError(storeerror.ErrCodeUnknown, err)
	}

	return setting, nil
}

func (s *store) UpdateSyslogSettings(ctx context.Context, setting *pb.SyslogSetting) error {
	jsonContent, err := json.Marshal(setting)
	if err != nil {
		return storeerror.WrapError(storeerror.ErrCodeUnknown, err)
	}

	err = dal.SetConfig(ctx, s.db, auditSyslogConfigKey, jsonContent)
	if err != nil {
		return storeerror.WrapError(storeerror.ErrCodeUnknown, err)
	}

	return nil
}
