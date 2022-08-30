package ci

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type CiComponent struct {
	PM   PolicyManager
	IM   ImageManager
	WM   WhitelistManager
	WH   WebhookManager
	Ctrl Controller
}

func NewCiComponent(dal store.ScanCiInterface) CiComponent {
	ctrl, err := NewCiController(dal)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init Ci Controller error")
	}
	return CiComponent{PM: NewPolicyManager(dal), IM: NewImageManager(dal), WM: NewWhiteList(dal), WH: NewWebhookManager(dal), Ctrl: *ctrl}
}
