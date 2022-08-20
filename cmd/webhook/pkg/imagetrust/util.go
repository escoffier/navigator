package imagetrust

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func checkRegistryUrl(ctx context.Context, image string) bool {
	ctx1, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	repoUrl, err := utils.GetImageUrl(image)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("image: %s is invalid ", repoUrl)
		return false
	}

	logging.GetLogger().Info().Msgf("imageRegistryCheckUrl: %s", checkImageRegistryUrl)
	req, err := http.NewRequestWithContext(ctx1, http.MethodGet, checkImageRegistryUrl, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create request failed")
		return false
	}
	var ImageRegs []ImageRegistry
	err = util.HTTPRequest(ctx1, http.DefaultClient, req, func(resp *http.Response, err error) error {
		if err != nil {
			return err
		}

		if resp.Body == nil {
			return fmt.Errorf("resp body is empty")
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode >= http.StatusBadRequest {
			err = fmt.Errorf("request scanner err. resp data: %s", string(body))
			return err
		}

		var rawResp response.HTTPEnvelope
		err = json.Unmarshal(body, &rawResp)
		if err != nil {
			return err
		}
		if rawResp.Data == nil {
			return fmt.Errorf("resp data is empty")
		}

		if len(rawResp.Data.Items) > 0 {
			err = json.Unmarshal(rawResp.Data.Items, &ImageRegs)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("get check resp err")
		return false
	}

	for i := range ImageRegs {
		r, err := url.Parse(ImageRegs[i].Url)
		if err != nil {
			continue
		}
		if r.Host == repoUrl {
			return true
		}
	}

	return false
}
