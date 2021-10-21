package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/captcha"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (api *api) createCaptcha() http.HandlerFunc {
	type CreateCaptchaResponse struct {
		CaptchaID string `json:"captchaID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		service, ok := captcha.GetService()
		if !ok {
			apperror.RespAndLog(w, r.Context(), ErrServiceNotReady)
			return
		}

		id := service.CreateCaptcha()
		if id == "" {
			apperror.RespAndLog(w, r.Context(), errors.New("internal server error"))
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(CreateCaptchaResponse{
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

		captchaValue := service.GetCaptchaString(captchaID)
		if captchaValue == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewCommonError(http.StatusBadRequest,
					fmt.Errorf("invalid captcha id"), "验证码id非法", "invalid captcha id"))
			return
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(rsp{Value: captchaValue}))
	}
}
