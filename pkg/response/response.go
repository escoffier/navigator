package response

import (
	"encoding/json"
	"net/http"
)

func respError(w http.ResponseWriter, code int, msg string) {
	resp := HTTPEnvelope{
		ApiVersion: "1.0",
		Error: &HTTPError{
			Code:    code,
			Message: msg,
		},
	}
	resp.Error.Errors = make([]HTTPSubError, 0)
	// We don't handle any suberrors for now.
	// subErr := HTTPSubError{
	// 	Message: msg,
	// }
	// resp.Error.Errors = append(resp.Error.Errors, subErr)
	Respond(w, code, resp)
}

func Bad(w http.ResponseWriter, msg string) {
	respError(w, http.StatusBadRequest, msg)
}

func InternalError(w http.ResponseWriter, msg string) {
	respError(w, http.StatusInternalServerError, msg)
}

func Unauthorized(w http.ResponseWriter, msg string) {
	respError(w, http.StatusUnauthorized, msg)
}

type ResponseOptionFunc func(c *HTTPEnvelope)

func WithItems(items interface{}) ResponseOptionFunc {
	return func(c *HTTPEnvelope) {
		// We don't actually check whether it's an array.
		c.Data.Items = items
	}
}

func WithItem(item interface{}) ResponseOptionFunc {
	return func(c *HTTPEnvelope) {
		// We don't actually check whether it's a single item.
		c.Data.Item = item
	}
}

func WithTotalItems(n int64) ResponseOptionFunc {
	return func(c *HTTPEnvelope) {
		c.Data.TotalItems = n
	}
}

func WithItemsPerPage(n int64) ResponseOptionFunc {
	return func(c *HTTPEnvelope) {
		c.Data.ItemsPerPage = n
	}
}

func WithStartIndex(n int64) ResponseOptionFunc {
	return func(c *HTTPEnvelope) {
		c.Data.StartIndex = n
	}
}

// Ok write 200 response with payload in JSON format
func Ok(w http.ResponseWriter, opts ...ResponseOptionFunc) {
	resp := HTTPEnvelope{
		ApiVersion: "1.0",
		Data:       &HTTPData{},
	}

	for _, opt := range opts {
		opt(&resp)
	}

	// resp.Errors = make([]HTTPSubError, 0)
	// subErr := HTTPSubError{
	// 	Message: msg,
	// }
	// resp.Errors = append(resp.Errors, subErr)

	Respond(w, http.StatusOK, resp)
}

// Respond setups the response correctly for HTTP requests
func Respond(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		InternalError(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
