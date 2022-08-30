package scanner_ci

import (
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
