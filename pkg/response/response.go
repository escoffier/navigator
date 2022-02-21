package response

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"

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
				// because if it's a slice, it's returned as `null`.
				// Need to marshal since HTTPData.Items is of type json.RawMessage
				marshalled, err := json.Marshal([]int{})
				if err != nil {
					ev.EnvelopeError = fmt.Sprintf("Failed to marshal empty items[] to json: %v", err)
				} else {
					ev.Data.Items = marshalled
				}
			} else {
				// need to marshal since HTTPData.Items is of type json.RawMessage
				marshalled, err := json.Marshal(items)
				if err != nil {
					ev.EnvelopeError = fmt.Sprintf("Failed to marshal items[] to json: %v", err)
				} else {
					ev.Data.Items = marshalled
				}
			}
		}
	}
}

func WithItem(item interface{}) ResponseDataOptionFunc {
	val := reflect.ValueOf(item)
	// 如果传入的item是一个指针，则判断指针关联的类型是否为结构体
	if val.Kind() == reflect.Struct || (val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct) {
		return func(ev *HTTPEnvelope) {
			// need to marshal since HTTPData.Item is of type json.RawMessage
			marshalled, err := json.Marshal(item)
			if err != nil {
				ev.EnvelopeError = fmt.Sprintf("Failed to marshal item to json: %v", err)
			} else {
				ev.Data.Item = marshalled
			}
		}
	} else {
		return func(ev *HTTPEnvelope) {
			ev.EnvelopeError = fmt.Sprintf("WithItem expected reflect.Struct, got %s", val.Kind().String())
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

func WithCheckId(checkId string) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Data.CheckId = checkId
	}
}

func WithExportFileStatus(status uint8) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.Data.Status = status
	}
}

func WithApiVersion(version string) ResponseDataOptionFunc {
	return func(ev *HTTPEnvelope) {
		ev.ApiVersion = version
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

	Respond(w, code, "application/json", resp)
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

	Respond(w, code, "application/json", resp)
}

func Respond(w http.ResponseWriter, code int, contentType string, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to marshall response")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to write response")
		http.Error(w, "Error when constructing HTTP response", http.StatusInternalServerError)
	}

	// logging.GetLogger().Info().Str("resp", fmt.Sprintf("%+v", string(response))).Msg("Resp sent")
}

// JSONOK custom gin json serialize data
func JSONOK(ctx *gin.Context, opts ...ResponseDataOptionFunc) {
	data := &HTTPEnvelope{
		ApiVersion: "1.0",
		Data:       &HTTPData{},
	}
	for _, op := range opts {
		op(data)
	}
	ctx.JSON(http.StatusOK, data)
}

func JSONError(ctx *gin.Context, err error, opts ...ResponseErrorOptionFunc) {
	data := &HTTPEnvelope{
		ApiVersion: "1.0",
		Error:      &HTTPError{},
	}
	for _, op := range opts {
		op(data)
	}

	data.Error.Message = err.Error()
	httpCode := http.StatusBadRequest
	if err2, ok := err.(*HTTPError); ok {
		httpCode = err2.Code
		data.Error.Code = httpCode
		data.Error.Errors = err2.Errors
	}

	ctx.JSON(httpCode, data)
}
