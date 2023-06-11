package scanner_ci

import (
	"context"
	"strings"
	"time"
)

var ConstWebhookInt = map[int64]string{
	1 << CiPolicyResultCodeAlert: "ci-alert",
	1 << CiPolicyResultCodeBlock: "ci-block",
}

var ConstWebhookString = map[string]int64{
	"ci-alert": 1 << CiPolicyResultCodeAlert,
	"ci-block": 1 << CiPolicyResultCodeBlock,
}

type Webhook struct {
	ID        int64 `gorm:"primaryKey" json:"id"`
	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	DeletedAt int
	Enable    bool   `json:"enable"`
	URL       string `gorm:"type:varchar(255);column:url" json:"url"`
	Secret    string `gorm:"type:varchar(255);columb:secret" json:"secret"`
	Flag      int64  `json:"flag"`
}

func (Webhook) TableName() string {
	return "ivan_ci_webhook"
}

type WebhookRecord struct {
	ID        int64     `gorm:"primaryKey" json:"id"`
	CreatedAt int64     `gorm:"autoCreateTime:milli;column:created_at" json:"created_at"`
	UpdatedAt int64     `gorm:"autoUpdateTime:milli;column:updated_at" json:"updated_at"`
	RequestID string    `gorm:"type:varchar(255);column:request_id" json:"request_id"`
	Status    int       `json:"status"`
	SendTime  time.Time `json:"send_time"`
	ErrMsg    string    `gorm:"type:varchar(255);column:err_msg" json:"err_msg"`
}

func (vi *WebhookRecord) ChangErrMsg(ctx context.Context) {
	lang, ok := ctx.Value(AcceptLanguage).(string)
	if ok && lang == "en" {
		switch strings.TrimSpace(vi.ErrMsg) {
		case "请求失败":
			vi.ErrMsg = "request failed"
		case "请求返回代码错误 405":
			vi.ErrMsg = "request return error code: 405"
		case "结果集解析错误":
			vi.ErrMsg = "parse param failed"
		case "请求生成错误":
			vi.ErrMsg = "generate request failed"
		}
	}
}

func (WebhookRecord) TableName() string {
	return "ivan_ci_webhook_record"
}

type WebHookBody struct {
	Action    string
	Image     string
	Vuln      []WebhookVulnList
	Sensitive SensitiveFileResult
	Os        string
	Pkg       []PkgList
}

const (
	AcceptLanguage = "Accept-Language"
)
