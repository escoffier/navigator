package types

import (
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NotifyEvent struct {
	Type            consts.NotifyEventType
	NodeImageConfig imagesecModel.NodeImageConfig
}
