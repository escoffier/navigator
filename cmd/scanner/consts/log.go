package consts

import (
	"github.com/rs/zerolog"
	"gitlab.com/security-rd/go-pkg/logging"
)

func ImageScanInfo() *zerolog.Event {
	imageScan := logging.Get().Info().Str("module", ModelImageScan)
	return imageScan
}

func ImageScanDebug() *zerolog.Event {
	imageScan := logging.Get().Debug().Str("module", ModelImageScan)
	return imageScan
}
