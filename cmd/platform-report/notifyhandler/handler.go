package notifyhandler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"

	"gopkg.in/gomail.v2"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Handler struct {
	emailConf *def.EmailConf
}

func NewHandler(emailConf *def.EmailConf) *Handler {
	return &Handler{
		emailConf: emailConf,
	}
}

func (h *Handler) Notify(_ context.Context, template *model.ReportTaskTemplateMeta, startTimestamp, endTimestamp int64) error {
	var emails []string
	var err = json.Unmarshal(util.String2BytesNoCopy(template.Emails), &emails)
	if err != nil {
		return fmt.Errorf("parse emails fail, err:%s", err)
	}

	emails = util.FilterDuplicateStringArray(emails)
	return h.sendEmail(emails, h.makeEmailBody(template, startTimestamp, endTimestamp))
}

const (
	subject      = "平台报告提醒"
	officialName = "探真官方"
)

func translateDataType(dataType string) string {
	switch dataType {
	case model.ReportTaskTypeWeekly:
		return "周报"
	case model.ReportTaskTypeMonthly:
		return "月报"
	default:
		return "自定义"
	}
}

const (
	timeFormat = "2006-01-02 15:04:05 MST"
)

func (h *Handler) makeEmailBody(template *model.ReportTaskTemplateMeta, startTimestamp, endTimestamp int64) string {
	return fmt.Sprintf("<div> 已为您成功生成一份报告：</div> "+
		"<div>报告类型：%s</div> "+
		"<div>报告名称：%s</div> "+
		"<div>报告周期：%s - %s</div>"+
		"<div>平台链接：%s</div>",
		translateDataType(template.Type), template.Name,
		util.GetTimeByMillisecondTimestamp(startTimestamp).In(util.GetCSTLocation()).Format(timeFormat),
		util.GetTimeByMillisecondTimestamp(endTimestamp).In(util.GetCSTLocation()).Format(timeFormat),
		fmt.Sprintf("%s#/?reportId=%d", h.emailConf.BaseURL, template.ID))
}

func (h *Handler) sendEmail(emails []string, body string) error {
	logging.GetLogger().Info().Msgf("emails:%+v, body:%s", emails, body)
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(h.emailConf.Username, officialName))
	m.SetHeader("To", emails...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(h.emailConf.Host, h.emailConf.Port, h.emailConf.Username, h.emailConf.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return d.DialAndSend(m)
}
