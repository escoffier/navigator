package notifyhandler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/badoux/checkmail"
	"gopkg.in/gomail.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type EmailConf struct {
	Username string
	Password string
	Host     string
	Port     int
}

type Handler struct {
	db        *rdbtools.GormWrapper
	emailConf *EmailConf
}

func NewHandler(db *rdbtools.GormWrapper, emailConf *EmailConf) *Handler {
	return &Handler{
		db:        db,
		emailConf: emailConf,
	}
}

func (h *Handler) Notify(ctx context.Context, dataType string, storageView *model.StorageView) error {
	emails, err := h.loadAdminEmails(ctx)
	if err != nil {
		return err
	}

	if len(emails) == 0 {
		return nil
	}

	return h.sendEmail(emails, makeEmailBody(dataType, storageView))
}

const (
	ModulePlatform = "Platform"
)

func (h *Handler) loadAdminEmails(ctx context.Context) ([]string, error) {
	var module model.ModuleGroup
	var err = h.db.Get().WithContext(ctx).Where("module_name_en = ?", ModulePlatform).Select("id").Find(&module).Error
	if err != nil {
		return nil, fmt.Errorf("loadAdminEmails fail, err:%w", err)
	}
	platformModuleID := strconv.Itoa(module.Id)

	var users []*model.User
	err = h.db.Get().WithContext(ctx).Where("rule = ?", model.RoleAdmin).Select("username, module_id").Find(&users).Error
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, nil
	}

	var emails = make([]string, 0, len(users))
	for _, user := range users {
		if checkErr := checkmail.ValidateFormat(user.UserName); checkErr != nil {
			logging.GetLogger().Info().Msgf("username:%s is not email, checkErr:%s", user.UserName, checkErr.Error())
			continue
		}

		var moduleIDList []string
		err = json.Unmarshal([]byte(user.ModuleID), &moduleIDList)
		if err != nil {
			logging.GetLogger().Error().Msgf("decode moduleID fail, err:%s", err.Error())
			continue
		}

		for _, moduleID := range moduleIDList {
			if moduleID == platformModuleID {
				emails = append(emails, user.UserName)
				break
			}
		}
	}

	return emails, nil
}

const (
	subject = "磁盘空间不足提醒"
)

func translateDataType(dataType string) string {
	switch dataType {
	case model.DataTypeHotLogic:
		return "业务逻辑数据"
	case model.DataTypeHotOffline:
		return "离线数据"
	case model.DataTypeCold:
		return "冷数据"
	default:
		return "其它数据"
	}
}

func makeEmailBody(dataType string, storageView *model.StorageView) string {
	return fmt.Sprintf("数据类型:%s. 磁盘状态:(预计总空间:%dMB, 实际已使用:%dMB). 请即时扩展磁盘或者清理数据!",
		translateDataType(dataType), storageView.Total/1024/1024, storageView.Used/1024/1024)
}

func (h *Handler) sendEmail(emails []string, body string) error {
	logging.GetLogger().Info().Msgf("emails:%+v, body:%s", emails, body)
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(h.emailConf.Username,
		util.GetEnvWithDefault(env.EmailOfficialName, env.DefaultEmailOfficialName)))
	m.SetHeader("To", emails...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(h.emailConf.Host, h.emailConf.Port, h.emailConf.Username, h.emailConf.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return d.DialAndSend(m)
}
