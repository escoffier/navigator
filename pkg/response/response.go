package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

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
	val := reflect.ValueOf(items)
	if val.Kind() != reflect.Array && val.Kind() != reflect.Slice {
		return func(ev *HTTPEnvelope) {
			ev.EnvelopeError = fmt.Sprintf("WithItem expected reflect.Array or reflect.Slice, got %s", val.Kind().String())
		}
	} else {
		return func(ev *HTTPEnvelope) {
			if val.Len() == 0 {
				// force return of empty array if `items` is empty.
				// because if it's a slice, it's returned as `null`
				ev.Data.Items = []int{}
			} else {
				ev.Data.Items = items
			}
		}
	}
}

func WithItem(item interface{}) ResponseDataOptionFunc {
	val := reflect.ValueOf(item)
	if val.Kind() != reflect.Struct {
		return func(ev *HTTPEnvelope) {
			ev.EnvelopeError = fmt.Sprintf("WithItem expected reflect.Struct, got %s", val.Kind().String())
		}
	} else {
		return func(ev *HTTPEnvelope) {
			ev.Data.Item = item
		}
	}
}

func WithCustomField(key string, value interface{}) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		if ev.Data.CustomFields == nil {
			ev.Data.CustomFields = make(map[string]interface{})
		}
		ev.Data.CustomFields[key] = value
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

func Ok(w http.ResponseWriter, opts ...ResponseDataOptionFunc) {
	RespData(w, http.StatusOK, opts...)
}

func RespError(w http.ResponseWriter, code int, opts ...ResponseErrorOptionFunc) {
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

	if resp.EnvelopeError != "" {
		logging.GetLogger().Error().Str("enveloperror", resp.EnvelopeError).Msg("When constructing response, error in With* helper")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
		return
	}

	respond(w, code, resp)
}

func RespData(w http.ResponseWriter, code int, opts ...ResponseDataOptionFunc) {
	resp := HTTPEnvelope{
		ApiVersion: "1.0",
		Data:       &HTTPData{},
	}

	for _, opt := range opts {
		opt(&resp)
	}

	if resp.EnvelopeError != "" {
		logging.GetLogger().Error().Str("enveloperror", resp.EnvelopeError).Msg("When constructing response, error in With* helper")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
		return
	}

	respond(w, code, resp)
}

func respond(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to marshall response")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to write response")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
	}
}
