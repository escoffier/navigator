package response

import (
	"encoding/json"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ResponseErrorOptionFunc func(ev *HTTPEnvelope)
type ResponseDataOptionFunc func(ev *HTTPEnvelope)

func WithMessage(message string) ResponseErrorOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Error.Message = message
	}
}

func WithSuberror(location, message string) ResponseErrorOptionFunc {
	return func(ev *HTTPEnvelope) {
		if message == "" {
			message = ev.Error.Message
		}
		subErr := HTTPSubError{
			Location: location,
			Message:  message,
		}
		ev.Error.Errors = append(ev.Error.Errors, subErr)
	}
}

func WithItems(items interface{}) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		// We don't actually check whether it's an array.
		// It's a costly reflection operation. Trust the caller.
		ev.Data.Items = items
	}
}

func WithItem(item interface{}) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		// We don't actually check whether it's a single item. See WithItems.
		ev.Data.Item = item
	}
}

func WithTotalItems(n int64) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Data.TotalItems = n
	}
}

func WithItemsPerPage(n int64) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Data.ItemsPerPage = n
	}
}

func WithStartIndex(n int64) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Data.StartIndex = n
	}
}

func Bad(w http.ResponseWriter, opts ...ResponseErrorOptionFunc) {
	respError(w, http.StatusBadRequest, opts...)
}

func InternalError(w http.ResponseWriter, opts ...ResponseErrorOptionFunc) {
	respError(w, http.StatusInternalServerError, opts...)
}

func Unauthorized(w http.ResponseWriter, opts ...ResponseErrorOptionFunc) {
	respError(w, http.StatusUnauthorized, opts...)
}

func Conflict(w http.ResponseWriter, opts ...ResponseErrorOptionFunc) {
	respError(w, http.StatusConflict, opts...)
}

func Ok(w http.ResponseWriter, opts ...ResponseDataOptionFunc) {
	respData(w, http.StatusOK, opts...)
}

func respError(w http.ResponseWriter, code int, opts ...ResponseErrorOptionFunc) {
	resp := HTTPEnvelope{
		ApiVersion: "1.0",
		Error: &HTTPError{
			Code: code,
		},
	}
	resp.Error.Errors = make([]HTTPSubError, 0)

	for _, opt := range opts {
		opt(&resp)
	}

	respond(w, code, resp)
}

func respData(w http.ResponseWriter, code int, opts ...ResponseDataOptionFunc) {
	resp := HTTPEnvelope{
		ApiVersion: "1.0",
		Data:       &HTTPData{},
	}

	for _, opt := range opts {
		opt(&resp)
	}

	respond(w, code, resp)
}

func respond(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to marshall response")
		http.Error(w, locale.Error(locale.HTTPResponseError, nil), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to write response")
		http.Error(w, locale.Error(locale.HTTPResponseError, nil), http.StatusInternalServerError)
	}
}
