package env

import (
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	webhookUrl        = "WEBHOOK_URL"
	defaultWebhookUrl = "https://webhook-svc:443"
)

func GetWebHookUrl() string {
	return util.GetEnvWithDefault(webhookUrl, defaultWebhookUrl)
}
