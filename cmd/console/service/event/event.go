package event

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const ConfEventNotice = "conf-event-notice"

type EventService struct {
	rdb *databases.RDBInstance
}

type EventNotifyConfig struct {
	Sound              string   `json:"sound"`
	Mail               string   `json:"mail"`
	Message            string   `json:"message"`
	Severity           int      `json:"severity"`
	NotifyObject       string   `json:"notify_object"`
	Emails             []string `json:"emails"`
	Mobiles            []string `json:"mobiles"`
	Categories         []string `json:"categories"`
	MicrosegEventDeny  bool     `json:"microseg_event_deny"`
	MicrosegEventAlert bool     `json:"microseg_event_alert"`
}

var instance *EventService
var rlOnce sync.Once

func InitService(rdb *databases.RDBInstance) error {
	rlOnce.Do(func() {
		instance = &EventService{
			rdb: rdb,
		}
	})
	return nil
}

func GetService(_ context.Context) (*EventService, bool) {
	return instance, instance != nil
}

func (s *EventService) GetConfig(ctx context.Context) (EventNotifyConfig, error) {
	conf := model.TensorConfig{}
	result := EventNotifyConfig{}

	err := s.rdb.GetReadDB().WithContext(ctx).
		First(&conf, "k = ?", ConfEventNotice).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			logging.Get().Error().Err(err).Msg("get db data err")
			return result, err
		}

		// default
		result.Sound = "disabled"
		result.Mail = "disabled"
		result.Severity = 3
	} else {
		if err = json.Unmarshal(conf.Config, &result); err != nil {
			logging.Get().Error().Err(err).Msg("json.Unmarshal err")
			return result, err
		}
	}
	return result, nil
}

func (s *EventService) Config(ctx context.Context, req EventNotifyConfig) error {
	// if req.Mail == "enabled" && len(req.Emails) == 0 {
	// 	encoding.HandleError(c, errutil.ErrIllegalParameter)
	// 	return
	// }
	buf := bytes.Buffer{}
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(req)
	if err != nil {
		logging.Get().Error().Err(err).Msg("json.Encode err")
		return err
	}

	raw := string(buf.String())
	logging.Get().Info().Msg(raw)

	now := time.Now()
	if err = s.rdb.Get().WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "k"}},
		DoUpdates: clause.AssignmentColumns([]string{"config", "updater", "updated_at"}),
	}).Create(&model.TensorConfig{
		Key:    ConfEventNotice,
		Config: []byte(raw),
		// Creator:   "",
		// Updater:   "",
		CreatedAt: now,
		UpdatedAt: now,
	}).Error; err != nil {
		logging.Get().Err(err).Msg("upsert err")
		return err
	}
	return nil
}
