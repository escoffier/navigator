package consumer

import (
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
)

type Consumer interface {
	Init(chan constant.Data) error
	Consume(*utils.NsMap)
	Stop()
}
