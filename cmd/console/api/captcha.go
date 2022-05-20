package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"golang.org/x/time/rate"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) createCaptcha() http.HandlerFunc {
	// 1 token is generated per second, maximum 5
	lmt := util.NewLimiter(rate.Every(time.Second), 5)

	type CreateCaptchaResponse struct {
		CaptchaID string `json:"captchaID"`
		Skip      bool   `json:"skip"`
		Image     string `json:"image"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !lmt.AllowKey(util.MD5Hex(r.UserAgent())) {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewCaptchaLimitError(http.StatusBadRequest,
					fmt.Errorf("the captcha request is too fast")))
			return
		}

		service, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		result := CreateCaptchaResponse{}

		result.CaptchaID = service.CreateCaptcha()
		if service.IsBreakerClosed() {
			if result.CaptchaID == "" {
				apperror.RespAndLog(w, r.Context(), errors.New("internal server error"))
				return
			}

			var image bytes.Buffer
			err := service.WriteImage(&image, result.CaptchaID)
			if service.IsBreakerClosed() {
				if err != nil {
					apperror.RespAndLog(w, r.Context(),
						apperror.NewMalformedRequestError(http.StatusBadRequest,
							fmt.Errorf("failed to get captcha, err:%s", err)))
					return
				}

				result.Image = base64.StdEncoding.EncodeToString(image.Bytes())
			}
		}

		result.Skip = !service.IsBreakerClosed()
		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(result))
	}
}

// Deprecated, this will be removed in a later release
// createCaptcha API has returned the image together
func (api *api) getCaptchaImage() http.HandlerFunc {
	type reqCaptcha struct {
		CaptchaID string `json:"captchaID"`
		Reload    bool   `json:"reloadCaptcha"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rc := reqCaptcha{}
		err := json.NewDecoder(r.Body).Decode(&rc)
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}

		if rc.CaptchaID == "" {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("captchaID error")))
			return
		}

		service, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		if rc.Reload {
			if !service.Reload(rc.CaptchaID) {
				apperror.RespAndLog(w, r.Context(),
					apperror.NewMalformedRequestError(http.StatusBadRequest,
						fmt.Errorf("captchaID error")))
				return
			}
		}

		err = service.WriteImage(w, rc.CaptchaID)
		if err != nil {
			apperror.RespAndLog(w, r.Context(),
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to get captcha, err:%s", err)))
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion))
	}
}

const (
	secret = "12kisIs@&L"
)

func (api *api) getCaptchaValue() http.HandlerFunc {
	type rsp struct {
		Skip  bool
		Value string `json:"value"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAccountTimeout)
		defer cancel()
		captchaID := r.URL.Query().Get("captchaID")
		if r.Header.Get("Secret") != secret {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest,
					fmt.Errorf("invalid secret"), "密钥非法", "invalid secret"))
			return
		}

		service, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		result := rsp{Skip: !service.IsBreakerClosed()}
		if !result.Skip {
			result.Value = service.GetCaptchaString(captchaID)
			if result.Value == "" {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest,
						fmt.Errorf("invalid captcha id"), "验证码id非法", "invalid captcha id"))
				return
			}
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(result))
	}
}
