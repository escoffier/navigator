package apperror

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type AppError struct {
	error
	suggestedUserFriendlyLocale locale.LocaleErrCode
	suggestedHTTPCode           int
}

func New(suggestedLocale locale.LocaleErrCode, suggestedHTTPcode int, internalErr error) AppError {
	return AppError{
		error:                       internalErr,
		suggestedUserFriendlyLocale: suggestedLocale,
		suggestedHTTPCode:           suggestedHTTPcode,
	}
}

func RespondWithSuggested(w http.ResponseWriter, r *http.Request, err error) {
	if ae, ok := err.(AppError); ok {
		response.RespError(w, ae.suggestedHTTPCode, response.WithMessage(locale.Error(ae.suggestedUserFriendlyLocale, r)))
	} else {
		// Fallback to internal error & AnError.
		logging.GetLogger().Warn().Msg("Expected AppError, responding with AnError.")
		response.InternalError(w, response.WithMessage(locale.Error(locale.AnError, r)))
	}
}
