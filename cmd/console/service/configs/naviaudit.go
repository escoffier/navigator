package configs

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/security-rd/go-pkg/pb"
	"net/http"
	"time"
)

const (
	naviAuditDefaultTimeout = time.Second * 5
)

type NaviauditConfigOperator struct {
	naviService *naviaudit.Service
	Aperator    string
}

type syslogSetting struct {
	Enable   bool   `json:"enable"`
	Network  string `json:"network"`
	Addr     string `json:"addr"`
	Severity string `json:"severity"`
	Facility string `json:"facility"`
	Tag      string `json:"tag"`
}

func (c *NaviauditConfigOperator) GetAperator() string {
	return c.Aperator
}

func (c *NaviauditConfigOperator) SetAperator(username string) {
	c.Aperator = username
}

func (nco *NaviauditConfigOperator) Export(ctx context.Context) ([]byte, error) {
	type Conf struct {
		Config []byte
		Status bool
	}

	ctx, cancel := context.WithTimeout(ctx, naviAuditDefaultTimeout)
	defer cancel()

	conf, err := nco.naviService.GetSyslogSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetSyslogSettings fail, err:%s", err.Error())
	}

	jsonconf, err := json.Marshal(conf)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	config := Conf{
		Config: jsonconf,
	}
	if conf != nil {
		config.Status = true
	} else {
		config.Status = false
	}

	jsondata, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}

	return jsondata, nil
}

func (nco *NaviauditConfigOperator) Import(ctx context.Context, config []byte) error {
	ctx, cancel := context.WithTimeout(ctx, naviAuditDefaultTimeout)
	defer cancel()

	type Conf struct {
		Config []byte
		Status bool
	}
	var data Conf
	if err := json.Unmarshal(config, &data); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}
	if !data.Status {

	}

	var setting syslogSetting
	err := json.Unmarshal(data.Config, &setting)
	if err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	err = nco.naviService.UpdateSyslogSettings(ctx, convertSyslogSettingToPb(&setting))
	if err != nil {
		if err == naviaudit.ErrInvalidSyslogSetting {
			return apperror.NewInvalidArgError(http.StatusBadRequest, err)
		}
		return err
	}

	return nil
}

func convertSyslogSettingToPb(setting *syslogSetting) *pb.SyslogSetting {
	return &pb.SyslogSetting{
		Enable:   setting.Enable,
		Network:  setting.Network,
		Addr:     setting.Addr,
		Severity: setting.Severity,
		Facility: setting.Facility,
		Tag:      setting.Tag,
	}
}
