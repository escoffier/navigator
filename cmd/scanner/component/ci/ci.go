package ci

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type CiComponent struct {
	PM   PolicyManager
	IM   ImageManager
	WM   WhitelistManager
	WH   WebhookManager
	Ctrl Controller
}

func NewCiComponent(dal adaptStore.ScanCiInterface, userDal imagesecStore.UserDal) CiComponent {
	ctrl, err := NewCiController(dal)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init Ci Controller error")
	}
	return CiComponent{PM: NewPolicyManager(dal, userDal), IM: NewImageManager(dal), WM: NewWhiteList(dal), WH: NewWebhookManager(dal), Ctrl: *ctrl}
}
