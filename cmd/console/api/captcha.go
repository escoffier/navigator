package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dchest/captcha"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	width      = 240
	height     = 80
	captchaLen = 4
)

func (api *api) createCaptcha() http.HandlerFunc {
	type CreateCaptchaResponse struct {
		CaptchaID string `json:"captchaID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := captcha.NewLen(captchaLen)
		response.Ok(w, response.WithItem(CreateCaptchaResponse{
			CaptchaID: id,
		}))
	}
}

func (api *api) getCaptchaImage() http.HandlerFunc {
	type reqCaptcha struct {
		CaptchaID string `json:"captchaID"`
		Reload    bool   `json:"reloadCaptcha"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rc := reqCaptcha{}
		err := json.NewDecoder(r.Body).Decode(&rc)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rc.CaptchaID == "" {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("captchaID error")))
			return
		}

		if rc.Reload {
			if !captcha.Reload(rc.CaptchaID) {
				RespAndLog(w, r.Context(),
					NewMalformedRequestError(http.StatusBadRequest,
						fmt.Errorf("captchaID error")))
				return
			}
		}

		err = captcha.WriteImage(w, rc.CaptchaID, width, height)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to get captcha, err:%s", err)))
			return
		}

		response.Ok(w)
	}
}
