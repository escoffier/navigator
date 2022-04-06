package apperror

import (
	"context"
	"errors"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func RespAndLog(w http.ResponseWriter, ctx context.Context, err error) {

	var det detailedError
	if errors.As(err, &det) {
		// Log
		if det.HTTPCode >= 400 && det.HTTPCode < 500 {
			logging.GetLogger().Warn().Err(err).Msg("Request handled with error")
		} else if det.HTTPCode >= 500 {
			logging.GetLogger().Error().Err(err).Msg("Request handled with error")
		} else {
			logging.GetLogger().Info().Err(err).Msg("Request handled with error")
		}

		// Respond
		subfuncs := make([]response.ResponseErrorOptionFunc, 0, len(det.Suberrors)+1)
		subfuncs = append(subfuncs, response.WithMessage(det.LocalizedError(ctx)))
		for _, v := range det.Suberrors {
			subfuncs = append(subfuncs, response.WithSuberror(v.Location, v.Message))
		}
		response.RespError(w, det.HTTPCode, subfuncs...)
		return
	}

	// Fallback to internal error
	logging.GetLogger().Err(err).Msg("Error")
	response.RespError(w, http.StatusInternalServerError, response.WithMessage(http.StatusText(http.StatusInternalServerError)))
}
