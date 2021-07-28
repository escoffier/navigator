package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dchest/captcha"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	captchaWidth  = 240
	captchaHeight = 80
	captchaLen    = 4
)

var globalStore = captcha.NewMemoryStore(captcha.CollectNum, captcha.Expiration)

func init() {
	captcha.SetCustomStore(globalStore)
}

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

		err = captcha.WriteImage(w, rc.CaptchaID, captchaWidth, captchaHeight)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to get captcha, err:%s", err)))
			return
		}

		response.Ok(w)
	}
}

const (
	defaultAuthTimeout = time.Second * 5
	secret             = "12kisIs@&L"
)

func (api *api) getCaptchaValue() http.HandlerFunc {
	type rsp struct {
		Value string `json:"value"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultAuthTimeout)
		defer cancel()
		captchaID := r.URL.Query().Get("captchaID")
		if r.Header.Get("Secret") != secret {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest, fmt.Errorf("invalid secret"), "密钥非法", "invalid secret"))
			return
		}

		captchaValue := GetCaptchaString(captchaID)
		if len(captchaValue) == 0 {
			RespAndLog(w, ctx, NewCommonError(http.StatusBadRequest, fmt.Errorf("invalid captcha id"), "验证码id非法", "invalid captcha id"))
			return
		}

		response.Ok(w, response.WithItem(rsp{Value: captchaValue}))
	}
}

func CaptchaVerifyString(id string, digits string) bool {
	return captcha.VerifyString(id, digits)
}

func GetCaptchaString(id string) string {
	digits := globalStore.Get(id, false)
	ns := make([]byte, len(digits))
	for i := range ns {
		ns[i] = digits[i] + '0'
	}

	return string(ns)
}
