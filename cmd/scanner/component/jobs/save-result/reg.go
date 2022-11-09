package saveresult

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/imroc/req/v3"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (srv *ScanResultHandle) SetRedisData(ctx context.Context, data model.ImageRiskOverRedis) error {
	if !data.Valid() {
		logging.GetLogger().Info().Interface("data", data).Msg("SetRedisData")
		return fmt.Errorf("data not valid")
	}

	logging.GetLogger().Debug().Interface("data", data).Msg("SetRedisData")

	consoleURL := os.Getenv("CONSOLE_EXTERNAL_URL")
	if consoleURL == "" {
		logging.GetLogger().Err(fmt.Errorf("not get CONSOLE_EXTERNAL_URL")).Msg("SetRedisData")
		return fmt.Errorf("not find CONSOLE_EXTERNAL_URL")
	}

	url := fmt.Sprintf("%s%s", consoleURL, "/api/openapi/scanner/vulns/setVulnRisk")
	logging.GetLogger().Debug().Str("url", url).Msg("SetRedisData")

	client := req.C().SetTimeout(10 * time.Minute)

	resp, err := client.R().SetHeader(consts.ScannerUser, consts.InternalApiKey).SetBody(data).Post(url)

	if err != nil {
		logging.GetLogger().Err(err).Str("url", url).Msg("SetRedisData")
		return err
	}
	if !resp.IsSuccess() {
		logging.GetLogger().Err(err).Str("url", url).Int("httpcode", resp.GetStatusCode()).Msg("SetRedisData")
		return fmt.Errorf("SetRedisData not success")
	}
	logging.GetLogger().Info().Str("url", url).Msg("SetRedisData  success ")
	return nil
}
