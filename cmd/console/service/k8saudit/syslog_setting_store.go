package k8saudit

import (
	"context"
	"errors"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/storeerror"
	"gorm.io/gorm"
)

type store struct {
	db *databases.RDBInstance
}

const (
	auditSyslogConfigKey = "audit-syslog-conf"
)

func (s *store) LoadSyslogSettings(ctx context.Context) (*pb.SyslogSetting, error) {
	config, err := dal.GetConfig(ctx, s.db.GetReadDB(), auditSyslogConfigKey)
	if err != nil && err != gorm.ErrRecordNotFound {
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

	err = dal.SetConfig(ctx, s.db.Get(), auditSyslogConfigKey, jsonContent)
	if err != nil {
		return storeerror.WrapError(storeerror.ErrCodeUnknown, err)
	}

	return nil
}
