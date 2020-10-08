package apperror

import (
	"errors"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type appSubError struct {
	location string
	message  string
}

type appError struct {
	error
	suggestedUserFriendlyLocale locale.LocaleErrCode
	suggestedHTTPCode           int
	suberrors                   []appSubError
}

func New(suggestedLocale locale.LocaleErrCode, suggestedHTTPcode int, internalErr error, subErrors ...appSubError) appError {
	ae := appError{
		error:                       internalErr,
		suggestedUserFriendlyLocale: suggestedLocale,
		suggestedHTTPCode:           suggestedHTTPcode,
	}
	ae.suberrors = append(ae.suberrors, subErrors...)
	return ae
}

// TODO: I'm not sure I like this NewSuberror thing. It's useful for validation helper functions, however in those functions
// it's not clear what the "location" should be anymore, since they should have access to request json struct tags.
// However, some functions, like KubeClientFromB64KubeConfig, blur the line between validation and actual work...
// It seems to be a tough conceptual problem.
func NewSuberror(location, message string) appSubError {
	return appSubError{location: location, message: message}
}

func RespondWithSuggested(w http.ResponseWriter, r *http.Request, err error) {

	var det detailedError
	if errors.As(err, &det) {
		subfuncs := []response.ResponseErrorOptionFunc{}

		subfuncs = append(subfuncs, response.WithMessage(det.LocalizedError(r)))
		for _, v := range det.Suberrors {
			subfuncs = append(subfuncs, response.WithSuberror(v.Location, v.Message))
		}

		response.RespError(w, det.HTTPCode, subfuncs...)
		return
	}

	if ae, ok := err.(appError); ok {
		subfuncs := []response.ResponseErrorOptionFunc{}
		subfuncs = append(subfuncs, response.WithMessage(locale.Error(ae.suggestedUserFriendlyLocale, r)))
		for _, v := range ae.suberrors {
			subfuncs = append(subfuncs, response.WithSuberror(v.location, v.message))
		}

		response.RespError(w, ae.suggestedHTTPCode, subfuncs...)
	} else {
		// Fallback to internal error & AnError.
		logging.GetLogger().Warn().Msg("Expected appError, responding with AnError.")
		response.InternalError(w, response.WithMessage(locale.Error(locale.AnError, r)))
	}
}
